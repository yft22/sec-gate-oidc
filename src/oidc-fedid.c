/*
 * Copyright (C) 2015-2021 IoT.bzh Company
 * Author "Fulup Ar Foll"
 *
 * $RP_BEGIN_LICENSE$
 * Commercial License Usage
 *  Licensees holding valid commercial IoT.bzh licenses may use this file in
 *  accordance with the commercial license agreement provided with the
 *  Software or, alternatively, in accordance with the terms contained in
 *  a written agreement between you and The IoT.bzh Company. For licensing terms
 *  and conditions see https://www.iot.bzh/terms-conditions. For further
 *  information use the contact form at https://www.iot.bzh/contact.
 *
 * GNU General Public License Usage
 *  Alternatively, this file may be used under the terms of the GNU General
 *  Public license version 3. This license is as published by the Free Software
 *  Foundation and appearing in the file LICENSE.GPLv3 included in the packaging
 *  of this file. Please review the following information to ensure the GNU
 *  General Public License requirements will be met
 *  https://www.gnu.org/licenses/gpl-3.0.html.
 * $RP_END_LICENSE$
*/

#include <libafb/afb-v4.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

#include "oidc-core.h"
#include "oidc-alias.h"
#include <http-client.h>
#include "oidc-fedid.h"

#include <assert.h>
#include <string.h>
#include <locale.h>

MAGIC_OIDC_SESSION(oidcFedUserCookie);
MAGIC_OIDC_SESSION(oidcFedSocialCookie);

typedef struct {
	afb_hreq *hreq;
    struct afb_req_v4 *wreq;
	oidcIdpT *idp;
	fedUserRawT *fedUser;
	fedSocialRawT *fedSocial;
} oidcFedidHdlT;

// if fedkey exists callback receive local store user profil otherwise we should create it
static void fedidCheckCB(void *ctx, int status, unsigned argc, afb_data_x4_t const argv[], struct afb_api_v4 *api) {
    char *errorMsg = "[invalid-profil] Fail to process user profile (fedidCheckCB)";
	oidcFedidHdlT *userRqt= (oidcFedidHdlT*)ctx;
   	char url[EXT_URL_MAX_LEN];
    const char *target;
    afb_data_x4_t reply[1], argd[argc];
	fedUserRawT *fedUser;
	oidcProfilsT *idpProfil;
	oidcAliasT *alias;
    afb_session *session;
	const char *redirect, *action=NULL;
	afb_hreq *hreq=NULL;
	struct afb_req_v4 *wreq=NULL;
	int err;

    // internal API error
    if (status < 0) goto OnErrorExit;

    // session is in hreq for REST and in comreq for wbesocket
    if (userRqt->hreq) {
		hreq= userRqt->hreq;
		session= userRqt->hreq->comreq.session;
	}

    if (userRqt->wreq) {
		wreq= userRqt->wreq;
        session= afb_req_v4_get_common(wreq)->session;
	}

    if (!session) {
		EXT_DEBUG ("[fedid-register-fail] session missing");
		goto OnErrorExit;
	}

    if (argc != 1) { // feduser was not created

		// fedkey not fount let's store social authority profil into session and redirect user on userprofil creation
		afb_session_cookie_set (session, oidcFedUserCookie, userRqt->fedUser, free, userRqt->fedUser);
		afb_session_cookie_set (session, oidcFedSocialCookie, userRqt->fedSocial, free, userRqt->fedSocial);
		afb_session_set_loa (session, oidcSessionCookie, 0); // user not register reset session loa

        httpKeyValT query[]= {
            {.tag="action"    , .value="register"},
            {.tag="language"  , .value=setlocale(LC_CTYPE, "")},
            {NULL} // terminator
        };

		if (hreq) {
        	err= httpBuildQuery (userRqt->idp->uid, url, sizeof(url), NULL /* prefix */, userRqt->idp->oidc->globals->registerUrl, query);
        	if (err) {
            	EXT_ERROR ("[fedid-register-unknown] fail to build redirect url");
            	goto OnErrorExit;
        	}
		} else {
            target= userRqt->idp->oidc->globals->registerUrl;
        	action= "register";
		}
    } else { // feduser is avaliable

		err= afb_data_convert (argv[0], fedUserObjType, &argd[0]);
		if (err < 0) goto OnErrorExit;
		fedUser= (fedUserRawT*)afb_data_ro_pointer(argd[0]);

		// let's store user profil into session cookie (/oidc/profil/get serves it)
   		afb_session_cookie_set (session, oidcFedUserCookie, fedUser, (void*)afb_data_unref, argd[0]);

		// free idp social federated profil, and set current session loa+profil to fedid service values
		fedUserFreeCB(userRqt->fedUser);
		fedSocialFreeCB(userRqt->fedSocial);
		afb_session_cookie_get (session, oidcIdpProfilCookie, (void**) &idpProfil);
		afb_session_set_loa (session, oidcSessionCookie, idpProfil->loa);

		// everyting looks good let's return user to original page
		afb_session_cookie_get (session, oidcAliasCookie, (void**)&alias);

		// Fulup TBD link account is a previous waiting tolink fed account exist linkit now
		// get fedlinkcookie
		// subcall for linking account  (social-link fedsocial, pseudo, email);
		// le call doit fonctionner à tous les coups

        err= httpBuildQuery (userRqt->idp->uid, url, sizeof(url), NULL /* prefix */, alias->url, NULL);
        if (err) {
            EXT_ERROR ("[fedid-register-exist] fail to build redirect url");
            goto OnErrorExit;
        }

		if (hreq) {
			// add afb-binder endpoint to login redirect alias
	    	err= afb_hreq_make_here_url(hreq, alias->url, url,sizeof(url));
    	    if (err<0) {
        	    EXT_ERROR ("[fedid-register-exist] fail to build redirect url");
            	goto OnErrorExit;
        	}
		} else {
            target= alias->url;
			action= "redirect";
		}
    }

	// free user info handle and redirect to initial targeted url
    if (hreq) {
        EXT_DEBUG ("[fedid-check-redirect] redirect to %s", url);
	    afb_hreq_redirect_to(hreq, url, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    } else {
		struct afb_data *reply;
        json_object *responseJ;

        wrap_json_pack (&responseJ, "{ss ss}"
            ,"action", action
            ,"url", target
        );

        EXT_DEBUG ("[fedid-check-reply] {'action':%s, 'target':'%s'}", action, target);
		afb_data_create_raw(&reply, &afb_type_predefined_json_c, responseJ, 0, (void*)json_object_put, responseJ);
	    afb_req_v4_reply_hookable(wreq, status, 1, &reply);
	}
	free (userRqt);
	return;

OnErrorExit:
	EXT_NOTICE ("[fedid-authent-redirect] (hoops!!!) internal error");
    if (hreq) afb_hreq_redirect_to(hreq, userRqt->idp->oidc->globals->errorUrl, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
	if (wreq) afb_req_v4_reply_hookable(wreq, -1, 0, NULL);
}

// try to wreq user profile from its federation key
int fedidCheck (oidcIdpT *idp, fedSocialRawT *fedSocial, fedUserRawT *fedUser, struct afb_req_v4 *wreq, afb_hreq *hreq) {
    int err;
    afb_data_x4_t params[1];

	oidcFedidHdlT *userRqt= calloc(1,sizeof(oidcFedidHdlT));
	userRqt->hreq=hreq;
    userRqt->wreq=wreq;
	userRqt->idp=idp;
	userRqt->fedUser=fedUser;
	userRqt->fedSocial=fedSocial;

	// increase fedSocial usagecount and checl social fedkey
    err= afb_data_create_raw(&params[0], fedSocialObjType, fedSocial, 0, fedSocialFreeCB, fedSocial);
	if (err) goto OnErrorExit;

	afb_data_addref(params[0]);  // prevent params to be deleted
	afb_api_v4_call_hookable(idp->oidc->apiv4, "fedid", "social-check", 1, params, fedidCheckCB, userRqt);
	return 0;

OnErrorExit:
	return -1;
}