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

#include <assert.h>
#include <string.h>
#include <locale.h>

/*
	// token not json
	char *ptr = strtok(httpRqt->body, "&");
	while(ptr != NULL)	{
		index= strncmp(ptr, tokenLabel, sizeof(tokenLabel)-1);
		if (!index) {
			accessToken= &ptr[sizeof(tokenLabel)-1];
			break;
		}
		ptr = strtok(NULL, "&");
	}
*/

// ldap context request handle for callbacks
typedef struct {
   oidcIdpT * idp;
   afb_hreq * hreq;
   struct afb_req_v4 *wreq; 
   const char *login;
   fedSocialRawT *fedSocial;
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
    .gidsMax = 64,
    .avatarAlias = "/sgate/ldap/avatar-dflt.png",
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

// call after user authenticate
static httpRqtActionT ldapAccessTokenCB (httpRqtT * httpRqt)
{
    ldapRqtCtxT *rqtCtx = (idpRqtCtxT *) httpRqt->userData;
    oidcIdpT *idp = rqtCtx->idp;
    int err, start;
    char *value;

    // reserve federation and social user structure
    fedUserRawT *fedUser = calloc (1, sizeof (fedUserRawT));
    fedSocialRawT *fedSocial = calloc (1, sizeof (fedSocialRawT));
    fedSocial->idp = strdup (idp->uid);

    // something when wrong
    if (httpRqt->status != 0 || httpRqt->body == NULL) goto OnErrorExit;

    // search for "DN:"
    static char dnString[]= "DN:";
    start=sizeof(dnString)-1;
    value= strcasestr (&httpRqt->body[0], dnString);
    if (!value) goto OnErrorExit;
    for (int idx=start; value[idx]; idx++) {
        if (value[idx] == '/n') {
            value[idx]='/0';
            fedSocial->fedkey = strdup (&httpRqt->body[start]);
            start=idx+1;
            break;
        }
    }

    // search for "pseudo:"
    static char uidString[]= "uid:";
    value= strcasestr (&httpRqt->body[start], uidString);
    if (value) {
        for (int idx=start; value[idx+sizeof(uidString)-1]; idx++) {
            if (value[idx] == '/n') {
                value[idx]='/0';
                fedUser->pseudo= strdup(&value[sizeof(uidString)-1]);
                break;
            }
        }
    }

    // search for "fullname:"
    static char gecosString[]= "gecos:";
    value= strcasestr (&httpRqt->body[start], gecosString);
    if (value) {
        for (int idx=start; value[idx+sizeof(gecosString)-1]; idx++) {
            if (value[idx] == '/n') {
                value[idx]='/0';
                fedUser->name= strdup(&value[sizeof(gecosString)-1]);
                break;
            }
        }
    }

    // search for "email:"
    static char mailString[]= "mail:";
    value= strcasestr (&httpRqt->body[start], mailString);
    if (value) {
        for (int idx=start; value[idx+sizeof(mailString)-1]; idx++) {
            if (value[idx] == '/n') {
                value[idx]='/0';
                fedUser->email= strdup(&value[sizeof(mailString)-1]);
                break;
            }
        }
    }

    // we may query now federation ldap groups are handle asynchronously
    err = fedidCheck (idp, fedSocial, fedUser, rqtCtx->wreq, rqtCtx->hreq);
    if (err) goto OnErrorExit;

    // complete federation social handle with ldap groups asynchronously
    if (ldapOpts.groups) {
        rqtCtx->fedSocial= fedSocial;
        ldapGetAttributs (rqtCtx);
    }

    idpRqtCtxFree (rqtCtx);

    return HTTP_HANDLE_FREE;

  OnErrorExit:
    EXT_CRITICAL ("[ldap-fail-user-profil] Fail to get user profil from ldap (login/passwd ???)");
    afb_hreq_reply_error (rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
    free (rqtCtx);
    fedSocialFreeCB(fedSocial);
    fedUserFreeCB(fedUser);
    return HTTP_HANDLE_FREE;
}

// check ldap login/passwd scope is unused
static int ldapAccessToken (oidcIdpT * idp, const char *login, const char *passwd, afb_hreq * hreq, struct afb_req_v4 *wreq)
{
    int status = 0, err;
    json_object *loginJ;

    // if passwd check passwd and retreive groups when login/passwd match
    if (!passwd) {
        EXT_NOTICE ("[curl-query-fail] login+passwd require login=%s passwd missing", login);
        goto OnErrorExit;
    }

    // place %login% with wreq.
    wrap_json_pack (&loginJ, "{ss}", "login", login);
    char *curlQuery= utilsExpandJson (ldapOpts.people, loginJ);
    if (!curlQuery) {
        EXT_CRITICAL ("[curl-query-fail] fail to build curl ldap query=%s missing '%login%'", ldapOpts.curlQuery);
        goto OnErrorExit;
    }

    // complete login for authentication
    char *curlUser= utilsExpandJson (ldapOpts.login, loginJ);
    if (!curlUser) {
        EXT_CRITICAL ("[curl-query-fail] fail to build curl ldap login=%s missing '%login%'", ldapOpts.login);
        goto OnErrorExit;
    }

    // build curl ldap options structure
    httpOptsT curlOpts= {
        .username= curlUser,
        .password= passwd,
    };

    // prepare context for curlcall back to response websock/rest request
    ldapRqtCtxT *rqtCtx= calloc (1, sizeof(ldapRqtCtxT));
    rqtCtx->hreq= hreq;
    rqtCtx->wreq= wreq;
    rqtCtx->idp= idp;
    rqtCtx->login=login;

    // asynchronous wreq to LDAP to check passwd and retreive user groups
    EXT_DEBUG ("[curl-ldap-auth] curl -u '%s::my_secret_passwd' '%s'\n", curlUser, curlQuery);
    int err = httpSendGet (idp->oidc->httpPool, curlQuery, &curlOpts, NULL, ldapAccessTokenCB, rqtCtx);
    if (err) goto OnErrorExit;

    return 0;

  OnErrorExit:
    return 1;
}



// check user email/pseudo attribute
static void
checkLoginVerb (struct afb_req_v4 *wreq, unsigned nparams, struct afb_data *const params[])
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
    err = ldapAccessToken (idp, login, passwd, NULL /*hreq*/, wreq);
    if (err) goto OnErrorExit;

    return; // curl ldap callback will respond to application

  OnErrorExit:

    afb_create_data_raw (&reply, AFB_PREDEFINED_TYPE_STRINGZ, errmsg, strlen (errmsg) + 1, NULL, NULL);
    afb_req_v4_reply_hookable (wreq, -1, 1, &reply);
}


// when call with no login/passwd display form otherwise try to log user
int
ldapLoginCB (afb_hreq * hreq, void *ctx)
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
        err = ldapAccessToken (idp, login, passwd, hreq, NULL /*wreq*/);
        if (err) goto OnErrorExit;
    }

    return 1;   // we're done

  OnErrorExit:
    afb_hreq_redirect_to (hreq, idp->wellknown->loginTokenUrl, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    return 1;
}

int
ldapRegisterCB (oidcIdpT * idp, struct afb_apiset *declare_set, struct afb_apiset *call_set)
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

// ldap is a fake openid authority as it get everyting locally
int
ldapConfigCB (oidcIdpT * idp, json_object * idpJ)
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
            , "peoples", &ldapOpts.people
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
