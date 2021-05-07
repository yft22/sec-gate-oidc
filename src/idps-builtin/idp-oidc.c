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
#include "oidc-utils.h"
#include "idp-oidc.h"

#include <assert.h>
#include <string.h>
#include <locale.h>

// import idp authentication enum/label
extern const nsKeyEnumT idpAuthMethods[];

static const oidcProfilsT dfltProfils[] = {
    {.loa = 1,.scope = "openid,profile"},
    {NULL}  // terminator
};

static const oidcSchemaT dfltSchema = {
    .fedid="sub",
    .pseudo="preferred_username",
    .name="name",
    .email= "email",
    .avatar="picture",
    .company="company",
};

static const httpKeyValT dfltHeaders[] = {
    {.tag = "Content-type",.value = "application/x-www-form-urlencoded"},
    {.tag = "Accept",.value = "application/json"},
    {NULL}                      // terminator
};

static httpOptsT dfltOpts = {
    .agent = HTTP_DFLT_AGENT,
    .follow = 1,
    .timeout= 10, // default authentication timeout 
    // .verbose=1
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/oidc/login",
    .aliasLogo = "/sgate/oidc/logo-64px.png",
    .sTimeout = 600
};

// duplicate key value if not null
static char *json_object_dup_key_value (json_object * objJ, const char *key)
{
    char *value;
    value = (char *) json_object_get_string (json_object_object_get (objJ, key));
    if (value) value = strdup (value);
    return value;
}

// call when IDP respond to user profil wreq
// reference: https://docs.oidc.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT oidcUserGetByTokenCB (httpRqtT * httpRqt)
{
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *) httpRqt->userData;
    oidcIdpT *idp = rqtCtx->idp;
    oidcSchemaT *schema= (oidcSchemaT*) idp->userData;
    fedSocialRawT *fedSocial=NULL;
    fedUserRawT *fedUser=NULL;
    int err;

    // free previous access token
    free (rqtCtx->userData);

    // something when wrong
    if (httpRqt->status != 200) goto OnErrorExit;

    // unwrap user profil
    json_object *profilJ = json_tokener_parse (httpRqt->body);
    if (!profilJ) goto OnErrorExit;

    // build social fedkey from idp->uid+oidc->id
    fedSocial = calloc (1, sizeof (fedSocialRawT));
    fedSocial->fedkey = json_object_dup_key_value (profilJ, schema->fedid);
    fedSocial->idp = strdup (idp->uid);
    rqtCtx->fedSocial= fedSocial;

    fedUser = calloc (1, sizeof (fedUserRawT));
    fedUser->pseudo = json_object_dup_key_value (profilJ, schema->pseudo);
    fedUser->avatar = json_object_dup_key_value (profilJ, schema->avatar);
    fedUser->name = json_object_dup_key_value (profilJ, schema->name);
    fedUser->company = json_object_dup_key_value (profilJ, schema->company);
    fedUser->email = json_object_dup_key_value (profilJ, schema->email);
    rqtCtx->fedUser= fedUser;

    // no organisation attributes we've got everything check federated user now
    err = fedidCheck(rqtCtx);
    if (err)  goto OnErrorExit;

    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("[oidc-fail-user-profil] Fail to get user profil from oidc status=%ld body='%s'", httpRqt->status, httpRqt->body);
    afb_hreq_reply_error (rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    idpRqtCtxFree(rqtCtx);
    if (fedSocial) fedSocialFreeCB(fedSocial);
    if (fedUser)fedUserFreeCB(fedUser);
    return HTTP_HANDLE_FREE;
}

// from acces token wreq user profil
// reference https://docs.oidc.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void oidcUserGetByToken (idpRqtCtxT * rqtCtx)
{
    oidcIdpT *idp = rqtCtx->idp;

    httpKeyValT authToken[] = {
        {.tag = "Authorization",.value = rqtCtx->token},
        {.tag = "grant_type", .value="authorization_code"},
        {NULL}  // terminator
    };

    // asynchronous wreq to IDP user profil https://docs.oidc.com/en/rest/reference/orgs#list-organizations-for-the-authenticated-user
    EXT_DEBUG ("[oidc-profil-get] curl -H 'Authorization: %s' %s\n", rqtCtx->token, idp->wellknown->userinfo);
    int err = httpSendGet (idp->oidc->httpPool, idp->wellknown->userinfo, &dfltOpts, authToken, oidcUserGetByTokenCB, rqtCtx);
    if (err) goto OnErrorExit;
    return;

  OnErrorExit:
    afb_hreq_reply_error (rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    afb_hreq_unref (rqtCtx->hreq);
}

// call when oidc return a valid access_token
static httpRqtActionT oidcAccessTokenCB (httpRqtT * httpRqt)
{
    const char *tokenVal, *tokenType;
    assert (httpRqt->magic == MAGIC_HTTP_RQT);
    idpRqtCtxT *rqtCtx = (idpRqtCtxT *) httpRqt->userData;

    // free old post data
    free (rqtCtx->userData);

    if (httpRqt->status != 200) goto OnErrorExit;

    // we should have a valid token or something when wrong
    json_object *responseJ = json_tokener_parse (httpRqt->body);
    if (!responseJ) goto OnErrorExit;

    int err= wrap_json_unpack (responseJ, "{ss ss}"
        , "access_token", & tokenVal
        , "token_type", & tokenType
        );
    if (err) goto OnErrorExit;
    asprintf (&rqtCtx->token, "%s %s", tokenType, tokenVal);

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

static int oidcAccessToken (afb_hreq * hreq, oidcIdpT * idp, const char *redirectUrl, const char *code)
{
    assert (idp->magic == MAGIC_OIDC_IDP);
    oidcCoreHdlT *oidc = idp->oidc;
    int err, dataLen;
    oidcSchemaT *schema= (oidcSchemaT*)idp->userData;

    idpRqtCtxT *rqtCtx = calloc (1, sizeof (idpRqtCtxT));
    rqtCtx->hreq = hreq;
    rqtCtx->idp = idp;
    err = afb_session_cookie_get (hreq->comreq.session, oidcIdpProfilCookie, (void **) &rqtCtx->profil);
    if (err) goto OnErrorExit;

    switch (idp->wellknown->authMethod) {

        case IDP_CLIENT_SECRET_BASIC: {

            dataLen= asprintf ((char**)&rqtCtx->userData, "code=%s&redirect_uri=%s&grant_type=%s"
                , code
                , redirectUrl
                , "authorization_code"
            );

            httpKeyValT headers[] = {
                {.tag = "Content-type",.value = "application/x-www-form-urlencoded"},
                {.tag = "Accept",.value = "application/json"},
                {.tag = "Authorization",.value = schema->auth64},
                {NULL}  // terminator
            };

            EXT_DEBUG ("[oidc-access-token] curl -H 'Authorization: %s' -X post -d '%s' %s\n", schema->auth64, (char*)rqtCtx->userData, idp->wellknown->tokenid);
            err = httpSendPost (oidc->httpPool, idp->wellknown->tokenid, &dfltOpts, headers, rqtCtx->userData, dataLen , oidcAccessTokenCB, rqtCtx);
            break;
        }

        case IDP_CLIENT_SECRET_POST:    
            break;

        default: 
            EXT_DEBUG ("[oidc-auth-unknown] idp=%s unsupported authentication method=%d",idp->uid, idp->wellknown->authMethod);
            goto OnErrorExit;
    }
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    if (rqtCtx->userData) free(rqtCtx->userData);
    free (rqtCtx);
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
    if (alias) aliasLoa = alias->loa;
    else aliasLoa = 0;

    // add afb-binder endpoint to login redirect alias
    status = afb_hreq_make_here_url (hreq, idp->statics->aliasLogin, redirectUrl, sizeof (redirectUrl));
    if (status < 0) goto OnErrorExit;

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
        if (!profil) goto OnErrorExit;

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
        err = httpBuildQuery (idp->uid, url, sizeof (url), NULL /* prefix */ , idp->wellknown->authorize, query);
        if (err) goto OnErrorExit;

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

// request IDP wellknown endpoint and retreive config
static httpRqtActionT oidcDiscoveryCB (httpRqtT * httpRqt)
{
    assert (httpRqt->magic == MAGIC_HTTP_RQT);
    oidcIdpT *idp = (oidcIdpT*) httpRqt->userData;
    oidcWellknownT *wellknown= (oidcWellknownT*) idp->wellknown;
    json_object *authMethodJ;

    if (httpRqt->status != 200) goto OnErrorExit;

    // we should have a valid json object
    json_object *responseJ = json_tokener_parse (httpRqt->body);
    if (!responseJ) goto OnErrorExit;

    wrap_json_unpack (responseJ, "{s?s s?s s?s s?s s?o}"
         , "token_endpoint", &wellknown->tokenid
         , "authorization_endpoint", &wellknown->authorize
         , "userinfo_endpoint", &wellknown->userinfo
         , "jwks_uri", &wellknown->jwks
         , "token_endpoint_auth_methods_supported", &authMethodJ
        );

    if (!wellknown->tokenid || !wellknown->authorize || !wellknown->userinfo) goto OnErrorExit;

    // search for IDP supported authentication method
    if (authMethodJ) {
        for (int idx=0; idx < json_object_array_length(authMethodJ); idx++) {
            const char* method = json_object_get_string(json_object_array_get_idx(authMethodJ, idx));
            wellknown->authMethod =utilsMapValue (idpAuthMethods, method);
            if (wellknown->authMethod) break;
        }
    }
    // nothing defined let's try default
    if (!wellknown->authMethod) wellknown->authMethod= IDP_CLIENT_SECRET_DEFAULT;

    // callback is responsible to free wreq & context
    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("[fail-wellknown-discovery] Fail to process response from oidc status=%ld body='%s' (oidcDiscoveryCB)", httpRqt->status, httpRqt->body);
    return HTTP_HANDLE_FREE;
}

// oidc is openid compliant. Provide default and delegate parsing to default ParseOidcConfigCB
int oidcConfigCB (oidcIdpT * idp, json_object * configJ)
{

    oidcDefaultsT defaults = {
        .credentials = NULL,
        .wellknown = NULL,
        .headers = dfltHeaders,
        .statics = &dfltstatics,
        .profils = dfltProfils,
    };

    int err = idpParseOidcConfig (idp, configJ, &defaults, NULL);
    if (err) goto OnErrorExit;

        // copy default ldap options as idp private user data
    oidcSchemaT *schema= malloc (sizeof(oidcSchemaT));
    memcpy (schema, &dfltSchema, sizeof(oidcSchemaT));
    idp->userData= (void*)schema;

    // check is we have custom options
    json_object *schemaJ = json_object_object_get (configJ, "schema");
    if (schemaJ) {
        err = wrap_json_unpack (schemaJ, "{s?s s?s s?s s?s s?s s?s !}"
            , "fedid", &schema->fedid
            , "avatar", &schema->avatar
            , "pseudo",&schema->pseudo
            , "name", &schema->name
            , "email", &schema->email
            , "company", &schema->company
            );
        if (err) {
            EXT_ERROR ("[iodc-config-schema] json error 'schema' support json keys: fedid,avatar,pseudo,email,name");
            goto OnErrorExit;
        }
    }

    // prebuilt basic authentication token
    char *authstr;
    int len= asprintf (&authstr,"%s:%s", idp->credentials->clientId, idp->credentials->secret);
    char *auth64= httpEncode64(authstr, len);
    asprintf ((char**)&schema->auth64, "Basic %s", auth64);
    idp->userData=schema;
    free(authstr);
    free(auth64);

    // if discovery url is present request it now
    if (idp->wellknown->discovery) {
        int err = httpSendGet (idp->oidc->httpPool, idp->wellknown->discovery, &dfltOpts, NULL, oidcDiscoveryCB, idp);
        if (err) {
            EXT_CRITICAL ("[fail-wellknown-discovery] invalid url='%s' (oidcDiscoveryCB)", idp->wellknown->discovery);
            goto OnErrorExit;
        }
    }

    return 0;

  OnErrorExit:
    EXT_CRITICAL ("[fail-config-oidc] invalid config idp='%s' (oidcDiscoveryCB)", idp->uid);
    return 1;
}
