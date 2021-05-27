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
#include "oidc-utils.h"
#include "oidc-idsvc.h"

#include <assert.h>
#include <string.h>
#include <locale.h>

MAGIC_OIDC_SESSION (oidcFedUserCookie);
MAGIC_OIDC_SESSION (oidcFedSocialCookie);


const nsKeyEnumT oidcFedidSchema[] = {
    {"pseudo"  , OIDC_SCHEMA_PSEUDO},
    {"name"    , OIDC_SCHEMA_NAME},
    {"email"   , OIDC_SCHEMA_EMAIL},
    {"avatar"  , OIDC_SCHEMA_AVATAR},
    {"company" , OIDC_SCHEMA_COMPANY},
    {NULL} // terminator
};

typedef struct {
    afb_hreq *hreq;
    struct afb_req_v4 *wreq;
    oidcIdpT *idp;
    fedUserRawT *fedUser;
    fedSocialRawT *fedSocial;
} oidcFedidHdlT;

// session timeout, reset LOA
void fedidsessionReset (int signal, void *ctx)
{
    afb_session *session = (afb_session *) ctx;
    afb_event_t evtCookie = NULL;
    oidcIdpT *idpProfil;

    // signal should be null
    if (signal) return;

    // reset session LOA (this will force authentication)
    afb_session_set_loa (session, oidcSessionCookie, 0);
    EXT_NOTICE ("[fedidsessionReset] timeout ?");

    afb_data_t reply;
    afb_session_cookie_get (session, idsvcEvtCookie, (void **) &evtCookie);
    afb_session_cookie_get (session, oidcIdpProfilCookie, (void **) &idpProfil);

    if (evtCookie) {
        json_object *eventJ;
        wrap_json_pack (&eventJ, "{ss ss ss* ss*}"
        , "status", "loa-reset"
        , "home" , idpProfil->oidc->globals->homeUrl ? : "/"
        , "login", idpProfil->oidc->globals->loginUrl
        , "error", idpProfil->oidc->globals->errorUrl
    );
        // create an API-V4 json param
        afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, eventJ, 0, (void *) json_object_put, eventJ);
        afb_event_push (evtCookie, 1, &reply);
    }
}

// if fedkey exists callback receive local store user profile otherwise we should create it
static void fedidCheckCB (void *ctx, int status, unsigned argc, afb_data_x4_t const argv[], struct afb_api_v4 *api)
{
    char *errorMsg = "[invalid-profile] Fail to process user profile (fedidCheckCB)";
    idpRqtCtxT *idpRqtCtx = (idpRqtCtxT *) ctx;
    char url[EXT_URL_MAX_LEN];
    const char *target;
    afb_data_x4_t reply[1], argd[argc];
    fedUserRawT *fedUser;
    oidcProfileT *idpProfil;
    oidcAliasT *alias;
    afb_session *session;
    const char *redirect;
    afb_hreq *hreq = NULL;
    struct afb_req_v4 *wreq = NULL;
    int err;

    // internal API error
    if (status < 0) goto OnErrorExit;

    // session is in hreq for REST and in comreq for wbesocket
    if (idpRqtCtx->hreq) {
        hreq = idpRqtCtx->hreq;
        session = idpRqtCtx->hreq->comreq.session;
    }

    if (idpRqtCtx->wreq) {
        wreq = idpRqtCtx->wreq;
        session = afb_req_v4_get_common (wreq)->session;
    }

    if (!session) {
        EXT_DEBUG ("[fedid-register-fail] session missing");
        goto OnErrorExit;
    }

    afb_session_cookie_get (session, oidcIdpProfilCookie, (void **) &idpProfil);
    if (argc != 1) {  // fedid is not registered and we are not facing a secondary authentication
        const char *targetUrl;

        // fedkey not fount let's store social authority profile into session and redirect user on userprofil creation
        afb_session_cookie_set (session, oidcFedUserCookie, idpRqtCtx->fedUser, fedUserFreeCB, idpRqtCtx->fedUser);
        afb_session_cookie_set (session, oidcFedSocialCookie, idpRqtCtx->fedSocial, fedSocialFreeCB, idpRqtCtx->fedSocial);
        afb_session_set_loa (session, oidcSessionCookie, 0);    // user not register reset session loa

        httpKeyValT query[] = {
            {.tag = "language",.value = setlocale (LC_CTYPE, "")},
            {NULL}              // terminator
        };

        if (idpProfil->slave) {
            targetUrl= idpRqtCtx->idp->oidc->globals->fedlinkUrl; 
        } else {
            targetUrl= idpRqtCtx->idp->oidc->globals->registerUrl;
        }    
        if (hreq) {
            err = httpBuildQuery (idpRqtCtx->idp->uid, url, sizeof (url), NULL /* prefix */ , targetUrl, query);
            if (err) {
                EXT_ERROR ("[fedid-register-unknown] fail to build redirect url");
                goto OnErrorExit;
            }
        } else {
            target = idpRqtCtx->idp->oidc->globals->registerUrl;
        }

    } else { // fedid is already registered

        err = afb_data_convert (argv[0], fedUserObjType, &argd[0]);
        if (err < 0) goto OnErrorExit;
        fedUser = (fedUserRawT *) afb_data_ro_pointer (argd[0]);

        // check if federation linking is pending
        fedSocialRawT *fedLinkSocial=NULL;
        afb_session_cookie_get (session, oidcFedSocialCookie, (void **) &fedLinkSocial);
        int fedLoa= afb_session_get_loa (session, oidcFedSocialCookie);

        // if we have to link two accounts do it before cleaning oidcFedSocialCookie
        if (fedLoa == FEDID_LINK_REQUESTED) {
            assert(fedLinkSocial);
            afb_data_x4_t params[2];
            int status;
            unsigned int count;
            afb_data_t data;

            // make sure we do not link account twice
            afb_session_set_loa (session, oidcFedSocialCookie, FEDID_LINK_RESET);

            // delegate account federation linking to fedid binding
            params[0]= afb_data_addref(argd[0]);
            err = afb_create_data_raw (&params[1], fedSocialObjType, fedLinkSocial, 0, NULL, NULL);
            if (err < 0) goto OnErrorExit;
            err= afb_api_v4_call_sync_hookable (api, API_OIDC_USR_SVC, "user-federate", 2, params, &status, &count, &data);
            if (err < 0 || status != 0) {
                EXT_ERROR ("[fedid-link-account] fail to link account pseudo=%s email=%s", fedUser->pseudo, fedUser->email);
                goto OnErrorExit;
            }
        }

        // let's store user profile into session cookie (/oidc/profile/get serves it)
        afb_session_cookie_set (session, oidcFedUserCookie, fedUser, (void *) afb_data_unref, argd[0]);
        afb_session_cookie_set (session, oidcFedSocialCookie, idpRqtCtx->fedSocial, fedSocialFreeCB, idpRqtCtx->fedSocial);

        // everyting looks good let's return user to original page
        afb_session_cookie_get (session, oidcIdpProfilCookie, (void **) &idpProfil);
        afb_session_cookie_get (session, oidcAliasCookie, (void **) &alias);

        err = httpBuildQuery (idpRqtCtx->idp->uid, url, sizeof (url), NULL /* prefix */ , alias->url, NULL);
        if (err) {
            EXT_ERROR ("[fedid-register-exist] fail to build redirect url");
            goto OnErrorExit;
        }

        if (hreq) {
            // add afb-binder endpoint to login redirect alias
            err = afb_hreq_make_here_url (hreq, alias->url, url, sizeof (url));
            if (err < 0) {
                EXT_ERROR ("[fedid-register-exist] fail to build redirect url");
                goto OnErrorExit;
            }
        } else {
            target = alias->url;
        }

        // if idp session as a timeout start a rtimer
        if (idpProfil->sTimeout) {
            fedidSessionT *fedSession = NULL;
            afb_session_cookie_get (session, oidcSessionCookie, (void **) &fedSession);
            if (fedSession && fedSession->timerId) {
                afb_jobs_abort (fedSession->timerId);
                fedSession->timerId = 0;
            } else {
                fedSession = calloc (1, sizeof (fedSession));
                afb_session_cookie_set (session, oidcSessionCookie, (void *) fedSession, NULL, NULL);
            }

            fedSession->timerId = afb_sched_post_job (NULL /*group */ , idpProfil->sTimeout * 1000, 0 /*max-exec-time */ , fedidsessionReset, session);
            if (fedSession->timerId < 0) {
                EXT_ERROR ("[fedid-register-timeout] fail to set idp profile session loa");
                goto OnErrorExit;
            }
        }
        afb_session_set_loa (session, oidcSessionCookie, idpProfil->loa);
    }

    // free user info handle and redirect to initial targeted url
    if (hreq) {
        EXT_DEBUG ("[fedid-check-redirect] redirect to %s", url);
        afb_hreq_redirect_to (hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    } else {
        struct afb_data *reply;
        json_object *responseJ;

        wrap_json_pack (&responseJ, "{ss}", "target", target);

        EXT_DEBUG ("[fedid-check-reply] {'target':'%s'}", target);
        afb_data_create_raw (&reply, &afb_type_predefined_json_c, responseJ, 0, (void *) json_object_put, responseJ);
        afb_req_v4_reply_hookable (wreq, status, 1, &reply);
    }

    idpRqtCtxFree (idpRqtCtx);
    return;

  OnErrorExit:
    EXT_NOTICE ("[fedid-authent-redirect] (hoops!!!) internal error");
    if (hreq) afb_hreq_redirect_to (hreq, idpRqtCtx->idp->oidc->globals->errorUrl, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
    if (wreq) afb_req_v4_reply_hookable (wreq, -1, 0, NULL);
}

// try to wreq user profile from its federation key
int fedidCheck (idpRqtCtxT *idpRqtCtx)
{
    int err;
    afb_data_x4_t params[1];

    // fedSocial should remain valid after subcall for fedsocial cookie
    err = afb_data_create_raw (&params[0], fedSocialObjType, idpRqtCtx->fedSocial, 0, NULL, NULL);
    if (err) goto OnErrorExit;

    afb_data_addref (params[0]);        // prevent params to be deleted
    afb_api_v4_call_hookable (idpRqtCtx->idp->oidc->apiv4, API_OIDC_USR_SVC, "social-check", 1, params, fedidCheckCB, idpRqtCtx);
    return 0;

  OnErrorExit:
    return -1;
}
