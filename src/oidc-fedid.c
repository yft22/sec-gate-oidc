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

#include "oidc-core.h"
#include "oidc-alias.h"
#include <http-client.h>

#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

// #undef AFB_BINDING_VERSION
// #define AFB_BINDING_VERSION 4
// #include "libafb/core/afb-v4.h"
// #include <libafb/core/afb-session.h>
// #include <libafb/http/afb-hreq.h>
// #include <libafb/core/afb-data.h>
// #include <libafb/core/afb-api-v4.h>

#include "oidc-fedid.h"

#include <assert.h>
#include <string.h>
#include <locale.h>


MAGIC_OIDC_SESSION(oidcFedUserCookie);
MAGIC_OIDC_SESSION(oidcFedSocialCookie);

typedef struct {
	afb_hreq *hreq;
    struct afb_req_v4 *request;
	oidcIdpT *idp;
	fedUserRawT *fedUser;
	fedSocialRawT *fedSocial;

} oidcFedidHdlT;

// if fedkey exists callback receive local store user profil otherwise we should create it
static void fedidCheckCB(void *ctx, int status, unsigned args, afb_data_x4_t const argv[], struct afb_api_v4 *api) {
    char *errorMsg = "[invalid-profil] Fail to process user profile (fedidCheckCB)";
	oidcFedidHdlT *userInfoHdl= (oidcFedidHdlT*)ctx;
   	char url[EXT_URL_MAX_LEN];
    afb_data_x4_t reply[1], argd[args];
	fedUserRawT *fedUser;
	oidcProfilsT *idpProfil;
	oidcAliasT *alias;
    afb_session *session;
	const char* response=NULL;
	afb_hreq *hreq=NULL;
	struct afb_req_v4 *request=NULL;
	int err;

    // internal API error
    if (status < 0) goto OnErrorExit;

    // session is in hreq for REST and in comreq for wbesocket
    if (userInfoHdl->hreq) {
		hreq= userInfoHdl->hreq;
		session= userInfoHdl->hreq->comreq.session;
	}

    if (userInfoHdl->request) {
		request= userInfoHdl->request;
		session= (*(struct afb_req_common **)request)->session;
	}

    if (!session) {
		EXT_DEBUG ("[fedid-register-fail] session missing");
		goto OnErrorExit;
	}

    if (args != 1) { // feduser was not created

		// fedkey not fount let's store social authority profil into session and redirect user on userprofil creation
		afb_session_set_cookie (session, oidcFedUserCookie, userInfoHdl->fedUser, fedUserFreeCB);
		afb_session_set_cookie (session, oidcFedSocialCookie, userInfoHdl->fedSocial, fedSocialFreeCB);

        if (hreq) {
            httpKeyValT query[]= {
                {.tag="action"    , .value="register"},
                {.tag="state"     , .value=afb_session_uuid(session)},
                {.tag="language"  , .value=setlocale(LC_CTYPE, "")},
                {NULL} // terminator
            };
            err= httpBuildQuery (userInfoHdl->idp->uid, url, sizeof(url), NULL /* prefix */, userInfoHdl->idp->oidc->globals->registerUrl, query);
            if (err) {
                EXT_ERROR ("[fedid-register-unknown] fail to build redirect url");
                goto OnErrorExit;
            }
            response= url;
        } else {
			response= "FEDID_USER_REFUSED";
		}
    } else { // feduser is avaliable

		err= afb_data_convert (argv[0], fedUserObjType, &argd[0]);
		if (err < 0) goto OnErrorExit;
		fedUser= (fedUserRawT*)afb_data_ro_pointer(argd[0]);

		// free idp social federated profil, and set current session loa+profil to fedid service values
		fedUserFreeCB(userInfoHdl->fedUser);
		fedSocialFreeCB(userInfoHdl->fedSocial);
		afb_session_get_cookie (session, oidcIdpProfilCookie, (void**) &idpProfil);
		afb_session_set_loa (session, oidcSessionCookie, idpProfil->loa);

		// let's store user profil into session cookie (/oidc/profil/get serves it)
        fedUser->ucount++;
   		afb_session_set_cookie (session, oidcFedUserCookie, fedUser, fedUserFreeCB);

		// everyting looks good let's return user to original page
		afb_session_get_cookie (session, oidcAliasCookie, (void**)&alias);
	    if (hreq) {
            httpKeyValT query[]= {
                {.tag="language"  , .value=setlocale(LC_CTYPE, "")},
                {NULL} // terminator
            };
            err= httpBuildQuery (userInfoHdl->idp->uid, url, sizeof(url), NULL /* prefix */, alias->url, query);
            if (err) {
                EXT_ERROR ("[fedid-register-exist] fail to build redirect url");
                goto OnErrorExit;
            }
			response= url;
		}
		else response= "FEDID_USER_CREATED";
    }

	// free user info handle and redirect to initial targeted url
    if (hreq) {
        EXT_DEBUG ("[fedid-check-redirect] redirect to %s", response);
	    afb_hreq_redirect_to(hreq, response, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    }
	if (request) {
		struct afb_data *reply;
        EXT_DEBUG ("[fedid-check-reply] status=%d", status);
		afb_data_create_raw(&reply, &afb_type_predefined_stringz, response, strlen(response)+1, NULL, NULL);
	    afb_req_v4_reply_hookable(request, status, 1, NULL);
	}
	free (userInfoHdl);
	return;

OnErrorExit:
	EXT_NOTICE ("[fedid-authent-redirect] (hoops!!!) internal error");
    if (hreq) afb_hreq_redirect_to(hreq, userInfoHdl->idp->oidc->globals->errorUrl, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
	if (request) afb_req_v4_reply_hookable(request, -1, 0, NULL);
}

// try to request user profile from its federation key
int fedidCheck (oidcIdpT *idp, fedSocialRawT *fedSocial, fedUserRawT *fedUser, struct afb_req_v4 *request, afb_hreq *hreq) {
    int err;
    afb_data_x4_t params[1];

	oidcFedidHdlT *userInfoHdl= calloc(1,sizeof(oidcFedidHdlT));
	userInfoHdl->hreq=hreq;
    userInfoHdl->request=request;
	userInfoHdl->idp=idp;
	userInfoHdl->fedUser=fedUser;
	userInfoHdl->fedSocial=fedSocial;
	fedSocial->ucount++;
    fedUser->ucount++;

	// increase fedSocial usagecount and checl social fedkey
    err= afb_data_create_raw(&params[0], fedSocialObjType, fedSocial, 0, fedSocialFreeCB, fedSocial);
	if (err) goto OnErrorExit;

	afb_api_v4_call_hookable(idp->oidc->apiv4, "fedid", "social-check", 1, params, fedidCheckCB, userInfoHdl);
	return 0;

OnErrorExit:
	return -1;
}