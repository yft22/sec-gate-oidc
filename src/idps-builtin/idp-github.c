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
 *  References: https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
*/

#define _GNU_SOURCE

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "oidc-fedid.h"
#include "http-client.h"

#include <libafb/core/afb-session.h>
#include <libafb/http/afb-hreq.h>
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

static const httpKeyValT dfltHeaders[]= {
	{.tag="Content-type", .value="application/x-www-form-urlencoded"},
	{.tag="Accept", .value="application/json"},
	{NULL}  // terminator
};

static const oidcProfilsT dfltProfils[]= {
	{.loa=1, .scope="user,email"},
	{NULL} // terminator
};

static const oidcWellknownT dfltWellknown= {
	 .loginTokenUrl  = "https://github.com/login/oauth/authorize",
	 .accessTokenUrl= "https://github.com/login/oauth/access_token",
	 .identityApiUrl= "https://api.github.com/user",
};

static const oidcStaticsT dfltstatics= {
  .aliasLogin="/sgate/github/login",
  .aliasLogo="/sgate/github/logo-64px.png",
  .timeout=600
};

static const httpOptsT dfltOpts= {
	.agent= HTTP_DFLT_AGENT,
	.headers= dfltHeaders,
	.follow=1,
	// .verbose=1
};

// duplicate key value if not null
static char * json_object_dup_key_value (json_object *objJ, const char *key) {
	char *value;
	value= (char*) json_object_get_string (json_object_object_get (objJ,key));
	if (value) value=strdup(value);
	return value;
}

// call when IDP respond to user profil request
// reference: https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
static httpRqtActionT githubUserGetByTokenCB (httpRqtT *httpRqt) {
	if (httpRqt->status != 200) goto OnErrorExit;
	idpRqtCtxT *rqtCtx= (idpRqtCtxT*) httpRqt->userData;
	oidcIdpT *idp= rqtCtx->idp;
	int err;

	// unwrap user profil
	json_object *profilJ= json_tokener_parse(httpRqt->body);
	if (!profilJ) goto OnErrorExit;
    fprintf (stderr, "**** user profil=%s\n", json_object_get_string (profilJ));

	// build social fedkey from idp->uid+github->id
	fedSocialRawT *fedKey= calloc (1, sizeof(fedSocialRawT));
    fedKey->fedkey= strdup (json_object_get_string (json_object_object_get (profilJ,"id")));
    fedKey->idp= strdup(idp->uid);

	fedUserRawT *fedUser= calloc (1, sizeof(fedUserRawT));
	fedUser->pseudo= json_object_dup_key_value (profilJ, "login");
	fedUser->avatar= json_object_dup_key_value (profilJ, "avatar_url");
	fedUser->name= json_object_dup_key_value (profilJ, "name");
	fedUser->company= json_object_dup_key_value (profilJ, "company");
	fedUser->email= json_object_dup_key_value (profilJ, "email");

	err= fedidCheck (rqtCtx->hreq, idp, fedKey, fedUser);
	if (err) goto OnErrorExit;

    free (rqtCtx);
	return HTTP_HANDLE_FREE;

OnErrorExit:
	EXT_CRITICAL ("[github-fail-user-profil] Fail to get user profil from github status=%ld body='%s'", httpRqt->status, httpRqt->body);
	afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
	return HTTP_HANDLE_FREE;
}

// from acces token request user profil
// reference https://docs.github.com/en/developers/apps/authorizing-oauth-apps#web-application-flow
static void githubUserGetByToken (idpRqtCtxT *rqtCtx, const char *accessToken) {
	char tokenVal [EXT_TOKEN_MAX_LEN];
	oidcIdpT *idp= rqtCtx->idp;

	snprintf(tokenVal, sizeof(tokenVal), "token %s", accessToken);
	httpKeyValT authToken[]= {
		{.tag="Authorization", .value=tokenVal},
		{NULL}  // terminator
	};

	// asynchronous request to IDP user profil service
	int err= httpSendGet(idp->oidc->httpPool, idp->wellknown->identityApiUrl, &dfltOpts, authToken, githubUserGetByTokenCB, rqtCtx);
	if (err) goto OnErrorExit;
	return;

OnErrorExit:
	afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
}

// call when github return a valid access_token
static httpRqtActionT githubAccessTokenCB (httpRqtT *httpRqt) {
	assert (httpRqt->magic == MAGIC_HTTP_RQT);
	idpRqtCtxT *rqtCtx= (idpRqtCtxT*) httpRqt->userData;
	const char *accessToken=NULL;

	// github returns "access_token=ffefd8e2f7b0fbe2de25b54e6a415c92a15491b8&scope=user%3Aemail&token_type=bearer"
	if (httpRqt->status != 200) goto OnErrorExit;

	// we should have a valid token or something when wrong
	json_object *responseJ= json_tokener_parse(httpRqt->body);
	if (!responseJ) goto OnErrorExit;
	accessToken= json_object_get_string (json_object_object_get(responseJ, "access_token"));
	if (!accessToken) goto OnErrorExit;

	EXT_DEBUG ("[github-auth-token] token=%s (githubAccessTokenCB)", accessToken);

	// we have our request token let's try to get user profil
	githubUserGetByToken (rqtCtx, accessToken);

	// callback is responsible to free request & context
	return HTTP_HANDLE_FREE;

OnErrorExit:
	EXT_CRITICAL ("[fail-access-token] Fail to process response from github status=%ld body='%s' (githubAccessTokenCB)", httpRqt->status, httpRqt->body);
	afb_hreq_reply_error(rqtCtx->hreq, EXT_HTTP_UNAUTHORIZED);
	return HTTP_HANDLE_FREE;
}

static int githubAccessToken (afb_hreq *hreq, oidcIdpT *idp, const char *redirectUrl, const char *code) {
	assert (idp->magic == MAGIC_OIDC_IDP);
	char url[EXT_URL_MAX_LEN];
	oidcCoreHdlT *oidc= idp->oidc;
	int err;

	httpKeyValT params[]= {
		{.tag="client_id"    , .value=idp->credentials->clientId},
		{.tag="client_secret", .value=idp->credentials->secret},
		{.tag="code"         , .value=code},
		{.tag="redirect_uri" , .value=redirectUrl},
		{.tag="state"        , .value=afb_session_uuid(hreq->comreq.session)},

		{NULL} // terminator
	};

	idpRqtCtxT *rqtCtx = calloc (1, sizeof(idpRqtCtxT));
	rqtCtx->hreq= hreq;
	rqtCtx->idp= idp;

	// send asynchronous post request with params in query // https://gist.github.com/technoweenie/419219
	err= httpBuildQuery (idp->uid, url, sizeof(url), NULL /* prefix */, idp->wellknown->accessTokenUrl, params);
	if (err) goto OnErrorExit;

	err= httpSendPost(oidc->httpPool, url, &dfltOpts, NULL/*token*/, (void*)1/*post*/,0 /*no data*/, githubAccessTokenCB, rqtCtx);
	if (err) goto OnErrorExit;

	return 0;

OnErrorExit:
	afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
	return 1;
}

// this check idp code and either request profil or redirect to idp login page
int githubLoginCB(afb_hreq *hreq, void *ctx) {
	oidcIdpT *idp= (oidcIdpT*)ctx;
	assert (idp->magic == MAGIC_OIDC_IDP);
	char redirectUrl [EXT_HEADER_MAX_LEN];
	const oidcProfilsT *profil=NULL;
	int err, status;

	// check if request as a code
	const char *code = afb_hreq_get_argument(hreq, "code");
	int requestedLoa =afb_session_get_loa (hreq->comreq.session, "ask");

	// add afb-binder endpoint to login redirect alias
    status= afb_hreq_make_here_url(hreq,idp->statics->aliasLogin,redirectUrl,sizeof(redirectUrl));
    if (status < 0) goto OnErrorExit;

	// if no code then set state and redirect to IDP
	if (!code) {
		char url[EXT_URL_MAX_LEN];

		// search for a scope fiting requesting loa
		for (int idx=0; idp->profils[idx].uid; idx++) {
			profil=&idp->profils[idx];
			if (idp->profils[idx].loa >= requestedLoa) {
				profil=&idp->profils[idx];
				break;
			}
		}

		// if loa requested and no profil fit exit without trying authentication
		if (requestedLoa && requestedLoa < profil->loa) goto OnErrorExit;

		httpKeyValT query[]= {
			{.tag="client_id"    , .value=idp->credentials->clientId},
			{.tag="response_type", .value="code"},
			{.tag="state"        , .value=afb_session_uuid(hreq->comreq.session)},
			{.tag="scope"        , .value=profil->scope},
			{.tag="redirect_uri" , .value=redirectUrl},
			{.tag="language"     , .value=setlocale(LC_CTYPE, "")},

			{NULL} // terminator
		};

		// store requested profil to retreive attached loa and role filter if login succeded
		afb_session_set_cookie (hreq->comreq.session, oidcIdpProfilCookie, (void*)profil, NULL);

		// build request and send it
		err= httpBuildQuery (idp->uid, url, sizeof(url), NULL /* prefix */, idp->wellknown->loginTokenUrl, query);
		if (err) goto OnErrorExit;

		EXT_DEBUG ("[github-redirect-url] %s (githubLoginCB)", url);
		afb_hreq_redirect_to(hreq, url, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);

	} else {

		// we have a code check state to assert that the response was generated by us then request authentication token
		const char *state= afb_hreq_get_argument(hreq, "state");
		if (strcmp (state, afb_session_uuid(hreq->comreq.session))) goto OnErrorExit;

		EXT_DEBUG ("[github-auth-code] code=%s (githubLoginCB)", code);

		// request authentication token from tempry code
		err= githubAccessToken (hreq, idp, redirectUrl, code);
		if (err) goto OnErrorExit;
	}

	return 1; // we're done

OnErrorExit:
	afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
	return 1;
}

// github is openid compliant. Provide default and delegate parsing to default ParseOidcConfigCB
int githubInitCB (oidcIdpT *idp, json_object *configJ, idpGenericCbT *oidcCB) {
	assert (oidcCB->magic == MAGIC_OIDC_CBS); // check provided callback magic

	oidcDefaultsT defaults = {
		. credentials= NULL,
		. statics=  &dfltstatics,
		. wellknown = &dfltWellknown,
		. profils=  dfltProfils,
		. headers = dfltHeaders,
	};
	int err = oidcCB->parseConfig (idp, configJ, &defaults, NULL);
	if (err) goto OnErrorExit;
	return 0;

OnErrorExit:
	return 1;
}

