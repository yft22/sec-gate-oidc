/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 * WARNING: pcsc plugin requires read access to /etc/shadow
 * Reference: 
 *  https://buzz.smartcardfocus.com/category/get-the-code/
 *  http://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09_sup.pdf
 */

#define _GNU_SOURCE

#include <libafb/afb-v4.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "oidc-fedid.h"

#include <assert.h>
#include <string.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// import pcsc-little API
#include <winscard.h>

// keep track of oidc-idp.c generic utils callbacks
static idpGenericCbT *idpCallbacks = NULL;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = { };
static const httpKeyValT noHeaders = { };

typedef struct {
    const char *avatarAlias;
    int readerMax;
    int readerId;
    int readerTimeout; //ms
    LPSCARDHANDLE readerHandle;
    const char *readerName;
} pcscOptsT;

// dflt_xxxx config.json default options
static pcscOptsT dfltOpts = {
    .readerMax = 16,
    .avatarAlias = "/sgate/pcsc/avatar-dflt.png",
};

static const oidcProfileT dfltProfiles[] = {
    {.loa = 1,.scope = "login"},
    {NULL}                      // terminator
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/pcsc/login",
    .aliasLogo = "/sgate/pcsc/logo-64px.png",
    .sTimeout = 600
};

static const oidcWellknownT dfltWellknown = {
    .tokenid = "/sgate/pcsc/login.html",
    .userinfo = NULL,
    .authorize = NULL,
};

// check user email/pseudo attribute
static void checkLoginVerb (struct afb_req_v4 *wreq, unsigned nparams, struct afb_data *const params[])
{
    const char *errmsg = "[pcsc-login] invalid credentials";
    oidcIdpT *idp = (oidcIdpT *) afb_req_v4_vcbdata (wreq);
    struct afb_data *args[nparams];
    const char *login, *passwd = NULL, *scope = NULL;
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    afb_data_t reply;
    const char *state;
    int aliasLoa;
    int err;

    err = afb_data_convert (params[0], &afb_type_predefined_json_c, &args[0]);
    json_object *queryJ = afb_data_ro_pointer (args[0]);
    err = wrap_json_unpack (queryJ, "{ss ss s?s s?s s?s}", "login", &login, "state", &state, "passwd", &passwd, "password", &passwd, "scope", &scope);
    if (err) goto OnErrorExit;

    // search for a scope fiting wreqing loa
    afb_session *session = afb_req_v4_get_common (wreq)->session;
    if (!state || strcmp (state, afb_session_uuid (session))) goto OnErrorExit;

    afb_session_cookie_get (session, oidcAliasCookie, (void **) &alias);
    if (alias) aliasLoa = alias->loa;
    else aliasLoa = 0;

    // search for a matching profile if scope is selected then scope&loa should match
    for (int idx = 0; idp->profiles[idx].uid; idx++) {
        profile = &idp->profiles[idx];
        if (idp->profiles[idx].loa >= aliasLoa) {
            if (scope && strcasecmp (scope, idp->profiles[idx].scope)) continue;
            profile = &idp->profiles[idx];
            break;
        }
    }
    if (!profile) {
        EXT_NOTICE ("[pcsc-check-scope] scope=%s does not match wreqed loa=%d", scope, aliasLoa);
        goto OnErrorExit;
    }
    // check password
    fedUserRawT *fedUser = NULL;
    fedSocialRawT *fedSocial = NULL;

    /// FULUP TDB
    //err = pcscAccessToken (idp, profile, login, passwd, &fedSocial, &fedUser);
    if (err) goto OnErrorExit;

    // do no check federation when only login
    if (fedUser) {
        afb_req_addref (wreq);
        idpRqtCtxT *idpRqtCtx= calloc (1,sizeof(idpRqtCtxT));
        idpRqtCtx->idp = idp;
        idpRqtCtx->fedSocial= fedSocial;
        idpRqtCtx->fedUser= fedUser;
        idpRqtCtx->wreq= wreq;
        err = idpCallbacks->fedidCheck (idpRqtCtx);
        if (err) {
            afb_req_unref (wreq);
            idpRqtCtxFree(idpRqtCtx);
            goto OnErrorExit;
        }
    } else {
        afb_req_v4_reply_hookable (wreq, 0, 0, NULL);        // login exist
    }
    return;

  OnErrorExit:

    afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg, strlen (errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable (wreq, -1, 1, &reply);
}

// when call with no login/passwd display form otherwise try to log user
int pcscLoginCB (afb_hreq * hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *) ctx;
    assert (idp->magic == MAGIC_OIDC_IDP);
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfileT *profile = NULL;
    const oidcAliasT *alias = NULL;
    int err, status, aliasLoa;

    // check if wreq as a code
    const char *login = afb_hreq_get_argument (hreq, "login");
    const char *passwd = afb_hreq_get_argument (hreq, "passwd");
    const char *scope = afb_hreq_get_argument (hreq, "scope");

    afb_session_cookie_get (hreq->comreq.session, oidcAliasCookie, (void **) &alias);
    if (alias) aliasLoa = alias->loa;
    else aliasLoa = 0;

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url (hreq, idp->statics->aliasLogin, redirectUrl, sizeof (redirectUrl));
    if (status < 0) goto OnErrorExit;

    // if no code then set state and redirect to IDP
    if (!login || !passwd) {
        char url[EXT_URL_MAX_LEN];

        // search for a scope fiting wreqing loa
        for (int idx = 0; idp->profiles[idx].uid; idx++) {
            profile = &idp->profiles[idx];
            if (idp->profiles[idx].loa >= aliasLoa) {
                // if no scope take the 1st profile with valid LOA
                if (scope && (strcmp (scope, idp->profiles[idx].scope))) continue;
                profile = &idp->profiles[idx];
                break;
            }
        }

        // if loa wreqed and no profile fit exit without trying authentication
        if (!profile) goto OnErrorExit;

        httpKeyValT query[] = {
            {.tag = "state",.value = afb_session_uuid (hreq->comreq.session)},
            {.tag = "scope",.value = profile->scope},
            {.tag = "redirect_uri",.value = redirectUrl},
            {.tag = "language",.value = setlocale (LC_CTYPE, "")},
            {NULL}              // terminator
        };

        // store wreqed profile to retreive attached loa and role filter if login succeded
        afb_session_cookie_set (hreq->comreq.session, oidcIdpProfilCookie, (void *) profile, NULL, NULL);

        // build wreq and send it
        err = httpBuildQuery (idp->uid, url, sizeof (url), NULL /* prefix */ , idp->wellknown->tokenid, query);
        if (err) goto OnErrorExit;

        EXT_DEBUG ("[pcsc-redirect-url] %s (pcscLoginCB)", url);
        afb_hreq_redirect_to (hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);

    } else {

        // we have a code check state to assert that the response was generated by us then wreq authentication token
        const char *state = afb_hreq_get_argument (hreq, "state");
        if (!state || strcmp (state, afb_session_uuid (hreq->comreq.session))) goto OnErrorExit;

        EXT_DEBUG ("[pcsc-auth-code] login=%s (pcscLoginCB)", login);
        afb_session_cookie_get (hreq->comreq.session, oidcIdpProfilCookie, (void **) &profile);
        if (!profile) goto OnErrorExit;

        // Check received login/passwd
        fedUserRawT *fedUser=NULL;
        fedSocialRawT *fedSocial=NULL;

        // Fulup TDB 
        // err = pcscAccessToken (idp, profile, login, passwd, &fedSocial, &fedUser);
        // if (err) goto OnErrorExit;

        // check if federated id is already present or not
        idpRqtCtxT *idpRqtCtx= calloc (1,sizeof(idpRqtCtxT));
        idpRqtCtx->idp = idp;
        idpRqtCtx->fedSocial= fedSocial;
        idpRqtCtx->fedUser= fedUser;
        idpRqtCtx->hreq= hreq;
        err = idpCallbacks->fedidCheck (idpRqtCtx);
        if (err) {
            idpRqtCtxFree(idpRqtCtx);
            goto OnErrorExit;
        }
    }

    return 1;   // we're done

  OnErrorExit:
    afb_hreq_redirect_to (hreq, idp->wellknown->tokenid, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    return 1;
}

int pcscRegisterApis (oidcIdpT * idp, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
    int err;

    // add a dedicate verb to check login/passwd from websocket
    //err= afb_api_add_verb(idp->oidc->apiv4, idp->uid, idp->info, checkLoginVerb, idp, NULL, 0, 0);
    err = afb_api_v4_add_verb_hookable (idp->oidc->apiv4, idp->uid, idp->info, checkLoginVerb, idp, NULL, 0, 0);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}

static int pcscRegisterAlias (oidcIdpT * idp, afb_hsrv * hsrv)
{
    int err;
    EXT_DEBUG ("[pcsc-register-alias] uid=%s login='%s'", idp->uid, idp->statics->aliasLogin);

    err = afb_hsrv_add_handler (hsrv, idp->statics->aliasLogin, pcscLoginCB, idp, EXT_HIGHEST_PRIO);
    if (!err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    EXT_ERROR ("[pcsc-register-alias] idp=%s fail to register alias=%s (pcscRegisterAlias)", idp->uid, idp->statics->aliasLogin);
    return 1;
}

// pcsc is a fake openid authority as it get everyting locally
static int pcscRegisterConfig (oidcIdpT * idp, json_object * idpJ)
{
    int err;

    pcscOptsT *pcscOpts= malloc(sizeof(pcscOptsT));
    memcpy (pcscOpts, &dfltOpts, sizeof(pcscOptsT));

    // check is we have custom options
    json_object *pluginJ = json_object_object_get (idpJ, "plugin");
    if (pluginJ) {
        err = wrap_json_unpack (pluginJ, "{s?i s?s !}"
            , "maxdev", &pcscOpts->readerMax
            , "avatar", &pcscOpts->avatarAlias
        );
        if (err) {
            EXT_ERROR ("[pcsc-config-opts] json parse fail 'plugin':{'maxdev':%d, 'avater':'%s'", pcscOpts->readerMax, pcscOpts->avatarAlias);
            goto OnErrorExit;
        }
    }

    // store default plugin options with idp context
    idp->ctx= (void*) pcscOpts;

    // only default profile is usefull
    oidcDefaultsT defaults = {
        .profiles = dfltProfiles,
        .statics = &dfltstatics,
        .credentials = &noCredentials,
        .wellknown = &dfltWellknown,
        .headers = &noHeaders,
    };

    // delegate config parsing to common idp utility callbacks
    err = idpCallbacks->parseConfig (idp, idpJ, &defaults, NULL);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}

// pcsc sample plugin exposes only one IDP
idpPluginT idppcscAuth[] = {
    {.uid = "pcsc",.info = "SmartCard/NFC mapping to pscd",.registerConfig = pcscRegisterConfig,.registerApis = pcscRegisterApis,.registerAlias= pcscRegisterAlias},
    {.uid = NULL}               // must be null terminated
};

// Plugin init call at config.json parsing time
int oidcPluginInit (oidcCoreHdlT * oidc, idpGenericCbT * idpGenericCbs)
{
    assert (idpGenericCbs->magic == MAGIC_OIDC_CBS);    // check provided callback magic

    // plugin is already loaded
    if (idpCallbacks) return 0;
    idpCallbacks = idpGenericCbs;

    int status = idpCallbacks->pluginRegister ("pcsc-plugin", idppcscAuth);
    return status;
}
