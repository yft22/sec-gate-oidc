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

#include <assert.h>
#include <string.h>
#include <locale.h>


// ldap context request handle for callbacks
typedef struct {
   char *login;
   char *passwd;
   char *userdn;
   oidcIdpT * idp;
   afb_hreq * hreq;
   struct afb_req_v4 *wreq; 
   fedSocialRawT *fedSocial;
   httpPoolT *httpPool;
   json_object *loginJ;
} ldapRqtCtxT;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials = { };
static const httpKeyValT noHeaders = { };

typedef struct {
    int gidsMax;
    const char *avatarAlias;
    const char *login;
    const char *uri;
    char *people;
    char *groups;
} ldapOptsT;

// dflt_xxxx config.json default options
static ldapOptsT ldapOpts = {
    .gidsMax = 16,
    .avatarAlias = "/sgate/ldap/avatar-dflt.png",
    .groups=NULL,
    .login=NULL,
};

static const oidcProfilsT dfltProfils[] = {
    {.loa = 1,.scope = "login"},
    {NULL}                      // terminator
};

static const oidcStaticsT dfltstatics = {
    .aliasLogin = "/sgate/ldap/login",
    .aliasLogo = "/sgate/ldap/logo-64px.png",
    .sTimeout = 600
};

static const oidcWellknownT dfltWellknown = {
    .loginTokenUrl = "/sgate/ldap/login.html",
    .identityApiUrl = NULL,
    .accessTokenUrl = NULL,
};

static void ldapRqtCtxFree (ldapRqtCtxT *rqtCtx) {
    if (rqtCtx->login) free (rqtCtx->login);
    if (rqtCtx->passwd) free (rqtCtx->passwd);
    if (rqtCtx->userdn) free(rqtCtx->userdn);
    if (rqtCtx->loginJ) json_object_put(rqtCtx->loginJ); 
}

static httpRqtActionT ldapAccessAttrsCB (httpRqtT * httpRqt)
{
    fedSocialRawT *fedSocial= httpRqt->userData;

    // something when wrong
    if (httpRqt->status < 0) goto OnErrorExit;

    // unwrap user groups from LDIF buffer
    // DN: cn=fulup,ou=Groups,dc=vannes,dc=iot
    // DN: cn=admin,ou=Groups,dc=vannes,dc=iot
    // DN: cn=skipail,ou=Groups,dc=vannes,dc=iot
    // DN: cn=matomo,ou=Groups,dc=vannes,dc=iot

  	// token not json
    static const char token[]=  "DN: ";
    fedSocial->attrs = calloc (ldapOpts.gidsMax+1, sizeof (char *));
	char *ptr = strtok(httpRqt->body, token);
	for (int idx=0; ptr != NULL; idx++)	{      
        static char cnString[]= "cn=";
        static int  cnLen=sizeof(cnString)-1;
        char *value= strcasestr (ptr, cnString);
        if (value) {

            // groups over gidsMax are ignored
            if (idx == ldapOpts.gidsMax) {
                EXT_ERROR ("[ldap-fail-groups] ldap->maxgids=%d too small (remaining groups ignored)", ldapOpts.gidsMax);
                fedSocial->attrs[idx]=NULL;
                break;
            }

            // extract groupname from LDIF cn=fulup,ou=Groups,dc=vannes,dc=iot\n
            for (int jdx=cnLen; value[jdx]; jdx++) {
                if (value[jdx] == ',' || value[jdx] == '\n') {
                    fedSocial->attrs[idx]= strndup(&value[cnLen], jdx-cnLen);
                    break;
                }
            }
        }
        // move to next cn= (next group)
        ptr = strtok(NULL, token);
	}

    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("[ldap-fail-groups] Fail to get user groups status=%ld body='%s'", httpRqt->status, httpRqt->body);
    return HTTP_HANDLE_FREE;
}

// reference https://docs.ldap.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void ldapAccessAttrs (ldapRqtCtxT * rqtCtx) {

    const char *curlQuery= utilsExpandJson (ldapOpts.groups, rqtCtx->loginJ);
    if (!curlQuery) {
        EXT_CRITICAL ("[curl-query-fail] fail to build curl ldap groups query=%s missing '%%login%%'", ldapOpts.login);
        goto OnErrorExit;
    }

    // build curl ldap options structure
    httpOptsT curlOpts= {
        .username= rqtCtx->userdn,
        .password= rqtCtx->passwd,
    };

     // asynchronous wreq to LDAP to check passwd and retreive user groups
    EXT_DEBUG ("[curl-ldap-auth] curl -u '%s::my_secret_passwd' '%s'\n", rqtCtx->userdn, curlQuery);
    int err = httpSendGet (rqtCtx->httpPool, curlQuery, &curlOpts, NULL, ldapAccessAttrsCB, rqtCtx->fedSocial);
    if (err) goto OnErrorExit;

    return;

  OnErrorExit:
    EXT_ERROR ("[curl-ldap-error] curl -u '%s::my_secret_passwd' '%s'\n", rqtCtx->userdn, curlQuery);
    return;
}

// call after user authenticate
static httpRqtActionT ldapAccessProfileCB (httpRqtT * httpRqt)
{
    static char errorMsg[]= "[ldap-fail-user-profil] Fail to get user profil from ldap (login/passwd ?)";
    ldapRqtCtxT *rqtCtx = (ldapRqtCtxT *) httpRqt->userData;
    oidcIdpT *idp = rqtCtx->idp;
    int err, start;
    char *value;
    afb_data_t reply;

    // reserve federation and social user structure
    fedUserRawT *fedUser = calloc (1, sizeof (fedUserRawT));
    fedSocialRawT *fedSocial = calloc (1, sizeof (fedSocialRawT));
    fedSocial->idp = strdup (idp->uid);
    rqtCtx->fedSocial= fedSocial;

    // something when wrong
    if (httpRqt->status < 0) goto OnErrorExit;

    // search for "DN:"
    static char dnString[]= "DN:";
    start=sizeof(dnString);
    value= strcasestr (&httpRqt->body[0], dnString);
    if (!value) goto OnErrorExit;
    for (int idx=0; value[idx]; idx++) {
        if (value[idx] == '\n') {
            value[idx]='\0';
            fedSocial->fedkey = strdup (&httpRqt->body[start]);
            start=idx+1;
            break;
        }
    }

    // search for "pseudo:"
    static char uidString[]= "uid:";
    value= strcasestr (&httpRqt->body[start], uidString);
    if (value) {
        for (int idx=sizeof(uidString); value[idx]; idx++) {
            if (value[idx] == '\n') {
                fedUser->pseudo= strndup(&value[sizeof(uidString)], idx-sizeof(uidString));
                break;
            }
        }
    }

    // search for "fullname:"
    static char gecosString[]= "gecos:";
    value= strcasestr (&httpRqt->body[start], gecosString);
    if (value) {
        for (int idx=sizeof(gecosString); value[idx]; idx++) {
            if (value[idx] == '\n') {
                fedUser->name= strndup(&value[sizeof(gecosString)], idx-sizeof(gecosString));
                break;
            }
        }
    }

    // search for "email:"
    static char mailString[]= "mail:";
    value= strcasestr (&httpRqt->body[start], mailString);
    if (value) {
        for (int idx=+sizeof(mailString); value[idx]; idx++) {
            if (value[idx] == '\n') {
                fedUser->email= strndup(&value[sizeof(mailString)], idx-sizeof(mailString));
                break;
            }
        }
    }

    // query federation ldap groups are handle asynchronously
    err = fedidCheck (idp, fedSocial, fedUser, rqtCtx->wreq, rqtCtx->hreq);
    if (err) goto OnErrorExit;

    // user is ok, let's map user organisation onto security attributes
    if (ldapOpts.groups) ldapAccessAttrs(rqtCtx);

    // free request handle
    ldapRqtCtxFree (rqtCtx);
    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("%s", errorMsg);

    if (rqtCtx->hreq) {
        afb_hreq_reply_error (rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    } else {
        afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, sizeof(errorMsg), NULL, NULL);
        afb_req_v4_reply_hookable (rqtCtx->wreq, -1, 1, &reply);
    }

    ldapRqtCtxFree(rqtCtx);
    fedSocialFreeCB(fedSocial);
    fedUserFreeCB(fedUser);
    return HTTP_HANDLE_FREE;
}

// check ldap login/passwd scope is unused
static int ldapAccessProfile (oidcIdpT * idp, const char *login, const char *passwd, afb_hreq *hreq, struct afb_req_v4 *wreq)
{
    int err;

    // prepare context for curl callbacks
    ldapRqtCtxT *rqtCtx= calloc (1, sizeof(ldapRqtCtxT));
    rqtCtx->hreq= hreq;
    rqtCtx->wreq= wreq;
    rqtCtx->idp= idp;
    rqtCtx->login=strdup(login);
    rqtCtx->passwd=strdup(passwd);
    rqtCtx->httpPool=idp->oidc->httpPool;    

    // place %%login%% with wreq.
    err= wrap_json_pack (&rqtCtx->loginJ, "{ss}", "login", login);
    if (err) goto OnErrorExit;

    // complete userdn login for authentication
    rqtCtx->userdn= utilsExpandJson (ldapOpts.login, rqtCtx->loginJ);
    if (!rqtCtx->userdn) {
        EXT_CRITICAL ("[curl-query-fail] fail to build curl ldap login=%s missing '%%login%%'", ldapOpts.login);
        goto OnErrorExit;
    }

    char *curlQuery= utilsExpandJson (ldapOpts.people, rqtCtx->loginJ);
    if (!curlQuery) {
        EXT_CRITICAL ("[curl-query-fail] fail to build curl ldap query=%s missing '%%login%%'", ldapOpts.login);
        goto OnErrorExit;
    }

    // build curl ldap options structure
    httpOptsT curlOpts= {
        .username= rqtCtx->userdn,
        .password= passwd,
    };

    // asynchronous wreq to LDAP to check passwd and retreive user groups
    EXT_DEBUG ("[curl-ldap-auth] curl -u '%s::my_secret_passwd' '%s'\n", rqtCtx->userdn, curlQuery);
    err = httpSendGet (rqtCtx->httpPool, curlQuery, &curlOpts, NULL, ldapAccessProfileCB, rqtCtx);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    ldapRqtCtxFree (rqtCtx);
    return 1;
}



// check user email/pseudo attribute
static void checkLoginVerb (struct afb_req_v4 *wreq, unsigned nparams, struct afb_data *const params[])
{
    const char *errmsg = "[ldap-login] invalid credentials";
    oidcIdpT *idp = (oidcIdpT *) afb_req_v4_vcbdata (wreq);
    struct afb_data *args[nparams];
    const char *login, *passwd = NULL, *scope = NULL;
    const oidcProfilsT *profil = NULL;
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

    // search for a matching profil if scope is selected then scope&loa should match
    for (int idx = 0; idp->profils[idx].uid; idx++) {
        profil = &idp->profils[idx];
        if (idp->profils[idx].loa >= aliasLoa) {
            if (scope && strcasecmp (scope, idp->profils[idx].scope)) continue;
            profil = &idp->profils[idx];
            break;
        }
    }
    if (!profil) {
        EXT_NOTICE ("[ldap-check-scope] scope=%s does not match wreqed loa=%d", scope, aliasLoa);
        goto OnErrorExit;
    }
    // check login password
    err = ldapAccessProfile (idp, login, passwd, NULL /*hreq*/, wreq);
    afb_req_addref(wreq);
    if (err) goto OnErrorExit;

    return; // curl ldap callback will respond to application

  OnErrorExit:

    afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg, strlen (errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable (wreq, -1, 1, &reply);
}


// when call with no login/passwd display form otherwise try to log user
int ldapLoginCB (afb_hreq * hreq, void *ctx)
{
    oidcIdpT *idp = (oidcIdpT *) ctx;
    assert (idp->magic == MAGIC_OIDC_IDP);
    char redirectUrl[EXT_HEADER_MAX_LEN];
    const oidcProfilsT *profil = NULL;
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
        for (int idx = 0; idp->profils[idx].uid; idx++) {
            profil = &idp->profils[idx];
            if (idp->profils[idx].loa >= aliasLoa) {
                // if no scope take the 1st profile with valid LOA
                if (scope && (strcmp (scope, idp->profils[idx].scope))) continue;
                profil = &idp->profils[idx];
                break;
            }
        }

        // if loa wreqed and no profil fit exit without trying authentication
        if (!profil) goto OnErrorExit;

        httpKeyValT query[] = {
            {.tag = "state",.value = afb_session_uuid (hreq->comreq.session)},
            {.tag = "scope",.value = profil->scope},
            {.tag = "redirect_uri",.value = redirectUrl},
            {.tag = "language",.value = setlocale (LC_CTYPE, "")},
            {NULL}              // terminator
        };

        // store wreqed profil to retreive attached loa and role filter if login succeded
        afb_session_cookie_set (hreq->comreq.session, oidcIdpProfilCookie, (void *) profil, NULL, NULL);

        // build wreq and send it
        err = httpBuildQuery (idp->uid, url, sizeof (url), NULL /* prefix */ , idp->wellknown->loginTokenUrl, query);
        if (err) goto OnErrorExit;

        EXT_DEBUG ("[ldap-redirect-url] %s (ldapLoginCB)", url);
        afb_hreq_redirect_to (hreq, url, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);

    } else {

        // we have a code check state to assert that the response was generated by us then wreq authentication token
        const char *state = afb_hreq_get_argument (hreq, "state");
        if (!state || strcmp (state, afb_session_uuid (hreq->comreq.session))) goto OnErrorExit;

        EXT_DEBUG ("[ldap-auth-code] login=%s (ldapLoginCB)", login);
        afb_session_cookie_get (hreq->comreq.session, oidcIdpProfilCookie, (void **) &profil);
        if (!profil) goto OnErrorExit;

        // Check received login/passwd
        err = ldapAccessProfile (idp, login, passwd, hreq, NULL /*wreq*/);
        if (err) goto OnErrorExit;
    }

    return 1;   // we're done

  OnErrorExit:
    afb_hreq_redirect_to (hreq, idp->wellknown->loginTokenUrl, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    return 1;
}

int ldapRegisterCB (oidcIdpT * idp, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
    int err;

    // add a dedicate verb to check login/passwd from websocket
    err= afb_api_add_verb(idp->oidc->apiv4, idp->uid, idp->info, checkLoginVerb, idp, NULL, 0, 0);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}

// ldap is a fake openid authority as it get everyting locally
int ldapConfigCB (oidcIdpT * idp, json_object * idpJ)
{
    int err;
    // only default profil is usefull
    oidcDefaultsT defaults = {
        .profils = dfltProfils,
        .statics = &dfltstatics,
        .credentials = &noCredentials,
        .wellknown = &dfltWellknown,
        .headers = &noHeaders,
    };

    // check is we have custom options
    json_object *pluginJ = json_object_object_get (idpJ, "schema");
    if (pluginJ) {
        err = wrap_json_unpack (pluginJ, "{ss ss ss ss s?s s?i}"
            , "uri", &ldapOpts.uri
            , "login", &ldapOpts.login
            , "groups", &ldapOpts.groups
            , "people", &ldapOpts.people
            , "avatar", &ldapOpts.avatarAlias
            , "gids", &ldapOpts.gidsMax
            );
        if (err) {
            EXT_ERROR ("[ldap-config-opts] json parse fail 'schema' requirer json keys: uri,login,groups,people");
            goto OnErrorExit;
        }

        // prebuild request adding ldap uri
        asprintf (&ldapOpts.groups, "%s/%s", ldapOpts.uri, ldapOpts.groups);
        asprintf (&ldapOpts.people, "%s/%s", ldapOpts.uri, ldapOpts.people);
    }
    // delegate config parsing to common idp utility callbacks
    err = idpParseOidcConfig (idp, idpJ, &defaults, NULL);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}
