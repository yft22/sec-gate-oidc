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

#undef AFB_BINDING_VERSION
#include "libafb/core/afb-v4.h"
#include <libafb/core/afb-session.h>
#include <libafb/http/afb-hreq.h>
#include <libafb/core/afb-data.h>
#include <libafb/core/afb-api-v4.h>

#include "oidc-fedid.h"

#include <assert.h>
#include <string.h>
#include <locale.h>


MAGIC_OIDC_SESSION(oidcFedUserCookie);
MAGIC_OIDC_SESSION(oidcFedSocialCookie);

typedef struct {
	afb_hreq *hreq;
	oidcIdpT *idp;
	fedUserRawT *fedUser;
	fedSocialRawT *fedSocial;
} oidcFedidHdlT;

// if fedkey exists callback receive local store user profil otherwise we should create it
static void fedidCheckCB(void *ctx, int status, unsigned nreplies, afb_data_x4_t const replies[], struct afb_api_v4 *api) {
    char *errorMsg = "[invalid-profil] Fail to process user profile (fedidCheckCB)";
	oidcFedidHdlT *userInfoHdl= (oidcFedidHdlT*)ctx;
   	char url[EXT_URL_MAX_LEN];
    afb_data_x4_t reply, data;
	fedUserRawT *fedUser;
	oidcProfilsT *idpProfil;
	oidcCookieT *cookie;
	afb_hreq *hreq= userInfoHdl->hreq;
	const char* redirect;

	int err;

    // internal API error
    if (status < 0) goto OnErrorExit;

    switch (status) {

	case FEDID_USER_UNKNOWN:
		// fedkey not fount let's store social authority profil into session and redirect user on userprofil creation
        userInfoHdl->fedUser->ucount++;
        userInfoHdl->fedSocial->ucount++;
		afb_session_set_cookie (hreq->comreq.session, oidcFedUserCookie, userInfoHdl->fedUser, fedUserFreeCB);
		afb_session_set_cookie (hreq->comreq.session, oidcFedSocialCookie, userInfoHdl->fedSocial, fedSocialFreeCB);
	    httpKeyValT query[]= {
			{.tag="action"    , .value="register"},
			{.tag="language"  , .value=setlocale(LC_CTYPE, "")},
			{NULL} // terminator
	    };
        err= httpBuildQuery (userInfoHdl->idp->uid, url, sizeof(url), NULL /* prefix */, userInfoHdl->idp->oidc->globals->registerUrl, query);
    	if (err) {
            EXT_ERROR ("[fail-register-redirect] fail to build redirect url (fedidCheckCB)");
            goto OnErrorExit;
        }
		redirect= url;
        break;

	case FEDID_USER_EXIST:
        if (nreplies != 1) goto OnErrorExit;
        
		// fed key found let's push data with user-profil into session cookie
		err= afb_data_convert (replies[0], fedUserObjType, &data);
		if (err < 0) goto OnErrorExit;
		fedUser= (fedUserRawT*)afb_data_ro_pointer(replies[0]);

		// free idp social federated profil, and set current session loa+profil to fedid service values
		fedUserFreeCB(userInfoHdl->fedUser);
		fedSocialFreeCB(userInfoHdl->fedSocial);
		afb_session_get_cookie (hreq->comreq.session, oidcIdpProfilCookie, (void**) &idpProfil);
		afb_session_set_loa (hreq->comreq.session, oidcIdpLoa, idpProfil->loa);

		// let's store user profil into session cookie (/oidc/profil/get serves it)
   		afb_session_set_cookie (hreq->comreq.session, oidcFedUserCookie, fedUser, fedUserFreeCB);


		// everyting looks good let's return user to original page
		afb_session_get_cookie (hreq->comreq.session, oidcAliasCookie, (void**)&cookie);
	    redirect= cookie->alias->url;
        break;

        default:
            goto OnErrorExit;
    }
	// free user info handle and redirect to initial targeted url
    EXT_DEBUG ("[fedid-authent-redirect] %s (fedidCheckCB)", url);
	afb_hreq_redirect_to(hreq, redirect, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
	free (userInfoHdl);
	return;

OnErrorExit:
    afb_hreq_redirect_to(hreq, userInfoHdl->idp->oidc->globals->errorUrl, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
}

// try to request user profile from its federation key
int fedidCheck (afb_hreq *hreq, oidcIdpT *idp, fedSocialRawT *fedSocial, fedUserRawT *fedUser) {
    int err;
    afb_data_x4_t argv[1];

	oidcFedidHdlT *userInfoHdl= malloc(sizeof(oidcFedidHdlT));
	userInfoHdl->hreq=hreq;
	userInfoHdl->idp=idp;
	userInfoHdl->fedUser=fedUser;
	userInfoHdl->fedSocial=fedSocial;

	// increase fedSocial usagecount and checl social fedkey
	fedSocial->ucount++;
    err= afb_data_create_raw(&argv[0], fedSocialObjType, fedSocial, 0, fedSocialFreeCB, fedSocial);
	if (err) goto OnErrorExit;
  
	afb_api_v4_call_hookable(idp->oidc->apiv4, "fedid", "social-check", 1, argv, fedidCheckCB, userInfoHdl);
	return 0;

OnErrorExit:
	return -1;
}