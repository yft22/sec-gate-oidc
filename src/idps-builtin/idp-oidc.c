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
 *
 *  References: https://phantauth.net/
*/

#define _GNU_SOURCE

#include <libafb/afb-v4.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "oidc-fedid.h"
#include "http-client.h"

#include <assert.h>
#include <string.h>
#include <locale.h>

static const httpKeyValT dfltHeaders[] = {
    {.tag = "Accept",.value = "application/json"},
    {.tag = "Authorization", .value = NULL},
    {NULL}  // terminator
};

static const oidcProfilsT dfltProfils[] = {
    {.loa = 1,.scope = "openid,profile"},
    {NULL}  // terminator
};

static const oidcWellknownT dfltWellknown = {
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/oidc/login",
    .aliasLogo = "/sgate/oidc/logo-64px.png",
    .sTimeout = 600
};

static httpOptsT dfltOpts = {
    .agent = HTTP_DFLT_AGENT,
    .headers = dfltHeaders,
    .follow = 1,
    .timeout= 10, // default authentication timeout 
    // .verbose=1
};

// duplicate key value if not null
static char *
json_object_dup_key_value (json_object * objJ, const char *key)
{
    char *value;
    value = (char *) json_object_get_string (json_object_object_get (objJ, key));
    if (value)
        value = strdup (value);
    return value;
}

// call when IDP respond to user profil wreq
// reference: https://docs.oidc.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT oidcAttrsGetByTokenCB (httpRqtT * httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *) httpRqt->userData;
    int err;

    // something when wrong
    if (httpRqt->status != 200) goto OnErrorExit;

    // unwrap user profil
    json_object *orgsJ = json_tokener_parse (httpRqt->body);
    if (!orgsJ || !json_object_is_type (orgsJ, json_type_array)) goto OnErrorExit;
    size_t count = json_object_array_length (orgsJ);
    rqtCtx->fedSocial->attrs = calloc (count + 1, sizeof (char *));
    for (int idx = 0; idx < count; idx++) {
        json_object *orgJ = json_object_array_get_idx (orgsJ, idx);
        rqtCtx->fedSocial->attrs[idx] = json_object_dup_key_value (orgJ, "login");
    }

    // we've got everything check federated user now
    err = fedidCheck(rqtCtx);
    if (err)  goto OnErrorExit;

    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("[oidc-fail-orgs] Fail to get user organisation status=%ld body='%s'", httpRqt->status, httpRqt->body);
    return HTTP_HANDLE_FREE;
}

// reference https://docs.oidc.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void
oidcGetAttrsByToken (idpRqtCtxT * rqtCtx, const char *orgApiUrl)
{
    char tokenVal[EXT_TOKEN_MAX_LEN];
    oidcIdpT *idp = rqtCtx->idp;
    rqtCtx->ucount++;

    snprintf (tokenVal, sizeof(tokenVal), "token %s", rqtCtx->token);
    httpKeyValT authToken[] = {
        {.tag = "Authorization",.value = tokenVal},
        {NULL} // terminator
    };

    // asynchronous wreq to IDP user profil https://docs.oidc.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG ("[oidc-attrs-get] curl -H 'Authorization: %s' %s\n", tokenVal, orgApiUrl);
    int err = httpSendGet (idp->oidc->httpPool, orgApiUrl, &dfltOpts, authToken, oidcAttrsGetByTokenCB, rqtCtx);
    if (err) EXT_ERROR ("[oidc-attrs-fail] curl -H 'Authorization: %s' %s\n", tokenVal, orgApiUrl);
    return;
}

// call when IDP respond to user profil wreq
// reference: https://docs.oidc.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT
oidcUserGetByTokenCB (httpRqtT * httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *) httpRqt->userData;
    oidcIdpT *idp = rqtCtx->idp;
    int err;

    // something when wrong
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // unwrap user profil
    json_object *profilJ = json_tokener_parse (httpRqt->body);
    if (!profilJ)
        goto OnErrorExit;

    // build social fedkey from idp->uid+oidc->id
    fedSocialRawT *fedSocial = calloc (1, sizeof (fedSocialRawT));
    fedSocial->fedkey = strdup (json_object_get_string (json_object_object_get (profilJ, "id")));
    fedSocial->idp = strdup (idp->uid);
    rqtCtx->fedSocial= fedSocial;

    fedUserRawT *fedUser = calloc (1, sizeof (fedUserRawT));
    fedUser->pseudo = json_object_dup_key_value (profilJ, "login");
    fedUser->avatar = json_object_dup_key_value (profilJ, "avatar_url");
    fedUser->name = json_object_dup_key_value (profilJ, "name");
    fedUser->company = json_object_dup_key_value (profilJ, "company");
    fedUser->email = json_object_dup_key_value (profilJ, "email");
    rqtCtx->fedUser= fedUser;

    // user is ok, let's map user organisation onto security attributes
    if (rqtCtx->profil->label) {
        const char *organizationsUrl = json_object_get_string (json_object_object_get (profilJ, rqtCtx->profil->label));
        if (organizationsUrl) {
            oidcGetAttrsByToken (rqtCtx, organizationsUrl);
        }
    } else {
        // no organisation attributes we've got everything check federated user now
        err = fedidCheck(rqtCtx);
        if (err)  goto OnErrorExit;
    }
    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("[oidc-fail-user-profil] Fail to get user profil from oidc status=%ld body='%s'", httpRqt->status, httpRqt->body);
    afb_hreq_reply_error (rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    idpRqtCtxFree(rqtCtx);
    fedSocialFreeCB(fedSocial);
    fedUserFreeCB(fedUser);
    return HTTP_HANDLE_FREE;
}

// from acces token wreq user profil
// reference https://docs.oidc.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void
oidcUserGetByToken (idpRqtCtxT * rqtCtx)
{
    char tokenVal[EXT_TOKEN_MAX_LEN];
    oidcIdpT *idp = rqtCtx->idp;

    snprintf (tokenVal, sizeof (tokenVal), "token %s", rqtCtx->token);
    httpKeyValT authToken[] = {
        {.tag = "Authorization",.value = tokenVal},
        {.tag = "grant_type", .value="authorization_code"},
        {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profil https://docs.oidc.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG ("[oidc-profil-get] curl -H 'Authorization: %s' %s\n", tokenVal, idp->wellknown->identityApiUrl);
    int err = httpSendGet (idp->oidc->httpPool, idp->wellknown->identityApiUrl,
                           &dfltOpts, authToken, oidcUserGetByTokenCB,
                           rqtCtx);
    if (err) goto OnErrorExit;
    return;

  OnErrorExit:
    afb_hreq_reply_error (rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    afb_hreq_unref (rqtCtx->hreq);
}

// call when oidc return a valid access_token
static httpRqtActionT
oidcAccessTokenCB (httpRqtT * httpRqt)
{
    assert (httpRqt->magic == MAGIC_HTTP_RQT);
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *) httpRqt->userData;

    // oidc returns "access_token=ffefd8e2f7b0fbe2de25b54e6a415c92a15491b8&scope=user%3Aemail&token_type=bearer"
    if (httpRqt->status != 200)
        goto OnErrorExit;

    // we should have a valid token or something when wrong
    json_object *responseJ = json_tokener_parse (httpRqt->body);
    if (!responseJ)
        goto OnErrorExit;

    rqtCtx->token = json_object_dup_key_value (responseJ, "access_token");
    if (!rqtCtx->token) goto OnErrorExit;

    EXT_DEBUG ("[oidc-auth-token] token=%s (oidcAccessTokenCB)", rqtCtx->token);

    // we have our wreq token let's try to get user profil
    oidcUserGetByToken (rqtCtx);

    // callback is responsible to free wreq & context
    json_object_put (responseJ);
    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("[fail-access-token] Fail to process response from oidc status=%ld body='%s' (oidcAccessTokenCB)", httpRqt->status, httpRqt->body);
    afb_hreq_reply_error (rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    return HTTP_HANDLE_FREE;
}

static int
oidcAccessToken (afb_hreq * hreq, oidcIdpT * idp, const char *redirectUrl, const char *code)
{
    assert (idp->magic == MAGIC_OIDC_IDP);
    char url[EXT_URL_MAX_LEN];
    oidcCoreHdlT *oidc = idp->oidc;
    int err;

    httpKeyValT params[] = {
        {.tag = "client_id",.value = idp->credentials->clientId},
        {.tag = "client_secret",.value = idp->credentials->secret},
        {.tag = "code",.value = code},
        {.tag = "redirect_uri",.value = redirectUrl},
        {.tag = "grant_type",.value = "authorization_code"},
        {.tag = "state",.value = afb_session_uuid (hreq->comreq.session)},
        {NULL}                  // terminator
    };

    idpRqtCtxT *rqtCtx = calloc (1, sizeof (idpRqtCtxT));
    // afb_hreq_addref (hreq); // prevent automatic href liberation
    rqtCtx->hreq = hreq;
    rqtCtx->idp = idp;
    err = afb_session_cookie_get (hreq->comreq.session, oidcIdpProfilCookie, (void **) &rqtCtx->profil);
    if (err)
        goto OnErrorExit;

    // send asynchronous post wreq with params in query // https://gist.oidc.com/technoweenie/419219
    err = httpBuildQuery (idp->uid, url, sizeof (url), NULL /* prefix */ , idp->wellknown->accessTokenUrl, params);
    if (err)
        goto OnErrorExit;

    httpKeyValT *headers= (httpKeyValT *)idp->userData;
    EXT_DEBUG ("[oidc-access-token] curl -H 'Authorization: %s' %s\n", headers[1].value, url);
    err = httpSendPost (oidc->httpPool, url, &dfltOpts, headers, (void *) 1 /*post */ , 0 /*no data */ , oidcAccessTokenCB, rqtCtx);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    afb_hreq_reply_error (hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

// this check idp code and either wreq profil or redirect to idp login page
int oidcLoginCB (afb_hreq * hreq, void *ctx) {
    oidcIdpT *idp = (oidcIdpT *) ctx;
    assert (idp->magic == MAGIC_OIDC_IDP);
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfilsT *profil = NULL;
    const oidcAliasT *alias = NULL;
    int err, status, aliasLoa;

    // check if wreq as a code
    const char *code = afb_hreq_get_argument (hreq, "code");
    const char *session = afb_session_uuid (hreq->comreq.session);
    afb_session_cookie_get (hreq->comreq.session, oidcAliasCookie, (void **) &alias);
    if (alias)
        aliasLoa = alias->loa;
    else
        aliasLoa = 0;

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url (hreq, idp->statics->aliasLogin, redirectUrl, sizeof (redirectUrl));
    if (status < 0)
        goto OnErrorExit;

    // if no code then set state and redirect to IDP
    if (!code) {
        char url[EXT_URL_MAX_LEN];
        const char *scope = afb_hreq_get_argument (hreq, "scope");

        // search for a scope fiting wreqing loa
        for (int idx = 0; idp->profils[idx].uid; idx++) {
            if (idp->profils[idx].loa >= aliasLoa) {
                // if no scope take the 1st profile with valid LOA
                if (scope && (strcmp (scope, idp->profils[idx].scope)))
                    continue;
                profil = &idp->profils[idx];
                break;
            }
        }

        // if loa wreqed and no profil fit exit without trying authentication
        if (!profil)
            goto OnErrorExit;

        // store wreqed profil to retreive attached loa and role filter if login succeded
        afb_session_cookie_set (hreq->comreq.session, oidcIdpProfilCookie, (void *) profil, NULL, NULL);

        httpKeyValT query[] = {
            {.tag = "client_id",.value = idp->credentials->clientId},
            {.tag = "response_type",.value = "code"},
            {.tag = "state",.value = session},
            {.tag = "scope",.value = profil->scope},
            {.tag = "redirect_uri",.value = redirectUrl},
            {.tag = "language",.value = setlocale (LC_CTYPE, "")},
            {NULL}              // terminator
        };

        // build wreq and send it
        err = httpBuildQuery (idp->uid, url, sizeof (url), NULL /* prefix */ ,
                              idp->wellknown->loginTokenUrl, query);
        if (err)
            goto OnErrorExit;

        EXT_DEBUG ("[oidc-redirect-url] %s (oidcLoginCB)", url);
        afb_hreq_redirect_to (hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);

    } else {
        // use state to retreive original wreq session uuid and restore original session before wreqing token
        const char *oidcState = afb_hreq_get_argument (hreq, "state");
        if (strcmp (oidcState, session)) {
            EXT_DEBUG ("[oidc-auth-code] missmatch session/state state=%s session=%s (oidcLoginCB)", oidcState, session);
            goto OnErrorExit;
        }

        EXT_DEBUG ("[oidc-auth-code] state=%s code=%s (oidcLoginCB)", oidcState, code);
        // wreq authentication token from tempry code
        err = oidcAccessToken (hreq, idp, redirectUrl, code);
        if (err)
            goto OnErrorExit;
    }
    return 1;  // we're done (0 would search for an html page)

  OnErrorExit:
    afb_hreq_reply_error (hreq, EXT_HTTP_UNAUTHORIZED);
    return 1;
}

// oidc is openid compliant. Provide default and delegate parsing to default ParseOidcConfigCB
int
oidcConfigCB (oidcIdpT * idp, json_object * configJ)
{

    oidcDefaultsT defaults = {
        .credentials = NULL,
        .statics = &dfltstatics,
        .wellknown = &dfltWellknown,
        .profils = dfltProfils,
        .headers = dfltHeaders,
    };
    int err = idpParseOidcConfig (idp, configJ, &defaults, NULL);
    if (err) goto OnErrorExit;

    // if timeout defined 
    if (idp->credentials->timeout) dfltOpts.timeout= idp->credentials->timeout;

    // prebuilt authentication token
    char *authstr;
    int len= asprintf (&authstr,"%s:%s", idp->credentials->clientId, idp->credentials->secret);
    httpKeyValT *headers=malloc(sizeof(dfltHeaders));
    memcpy(headers, dfltHeaders, sizeof(dfltHeaders));
    headers[1].value= curl_easy_escape(NULL, authstr, len);
    idp->userData= headers;
    free(authstr);

    return 0;

  OnErrorExit:
    return 1;
}
