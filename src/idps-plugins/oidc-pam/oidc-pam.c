/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 * 
 * WARNING: pam plugin requires read access to /etc/shadow 
 */

#define _GNU_SOURCE

#include <fedid-types.h>

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "oidc-fedid.h"

#define AFB_BINDING_VERSION 4
#include <afb/afb-binding-v4.h>
#include <libafb/core/afb-session.h>
#include <libafb/http/afb-hreq.h>

#include <assert.h>
#include <string.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <grp.h>
#include <pwd.h>

// keep track of oidc-idp.c generic utils callbacks
static idpGenericCbT *idpGenericCbs=NULL;

// provide dummy default values to oidc callbacks
static const oidcCredentialsT noCredentials={}; 
static const httpKeyValT noHeaders={};

typedef struct {
	int gidsMax;
	const char *avatarAlias;
} pamOptsT;

// dflt_xxxx config.json default options
static pamOptsT dfltOpts = {
	.gidsMax= 10,
	.avatarAlias= "/sgate/pam/avatar-dflt.png"
};

static const oidcProfilsT dfltProfils[]= {
	{.loa=1, .scope="login"},
	{NULL} // terminator
};

static const oidcStaticsT dfltstatics= {
  .aliasLogin="/sgate/pam/login",
  .aliasLogo="/sgate/pam/logo-64px.png",
  .timeout=600
};

static const oidcWellknownT dfltWellknown= {
	 .loginTokenUrl  = "/sgate/pam/login.html",
	 .identityApiUrl= "pam-check",
};

// simulate a user UI for passwd input
static int pamChalengeCB (int num_msg, const struct pam_message **msg, struct pam_response **resp, void *passwd)  {  
	struct pam_response *reply= malloc(sizeof(struct pam_response));
	reply->resp= strdup(passwd);
	reply->resp_retcode=0;

    *resp = reply; 
    return PAM_SUCCESS;  
}

// check pam login/passwd using scope as pam application
static int pamAccessToken (afb_hreq *hreq, oidcIdpT *idp, const oidcProfilsT *profil, const char *login, const char *passwd) {
	int status, err;
	pam_handle_t* pamh = NULL;
	gid_t groups[dfltOpts.gidsMax];
	int ngroups= dfltOpts.gidsMax;

	// Fulup TBD add encryption/decrypting based on session UUID
	// html5 var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
	// AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
	// AES_cbc_encrypt((unsigned char *)&ticket, enc_out, encslength, &enc_key, iv_enc, AES_ENCRYPT);

	// pam challenge callback to retreive user input (e.g. passwd)
    struct pam_conv conversion = {
        .conv= pamChalengeCB,
        .appdata_ptr= (void*) passwd,
    };

	// init pam transaction using scope as pam application
	status = pam_start(profil->scope, login, &conversion, &pamh);
	if (status != PAM_SUCCESS) goto OnErrorExit;

	// check passwd
	status = pam_authenticate(pamh, 0);
	if (status != PAM_SUCCESS) goto OnErrorExit;

	// login/passwd match let's retreive gids
    struct passwd* pw = getpwnam(login);
    if (pw == NULL) goto OnErrorExit;

	err= getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);
	if (err < 0) {
		EXT_CRITICAL ("[pam-auth-gids] opts{'gids':%d} too small", dfltOpts.gidsMax);
		goto OnErrorExit;
	}

	// build social fedkey from idp->uid+github->id
	fedSocialRawT *fedKey= calloc (1, sizeof(fedSocialRawT));
	char *fedkey;
    asprintf (&fedkey,"id:%d",pw->pw_uid);
	fedKey->fedkey= fedkey;
    fedKey->idp= strdup(idp->uid);

	fedUserRawT *fedUser= calloc (1, sizeof(fedUserRawT));
	fedUser->pseudo= strdup(pw->pw_name);
	fedUser->avatar= strdup (dfltOpts.avatarAlias);
	fedUser->name= strdup(pw->pw_gecos);
	fedUser->company= NULL;
	fedUser->email= NULL;

	err= idpGenericCbs->fedidCheck (hreq, idp, fedKey, fedUser);

	// close pam transaction
	pam_end(pamh, status);
	return 0;

 OnErrorExit:
	pam_end(pamh, status);
	return 1;
}


// check user email/pseudo attribute
static void pamCheckLoginPasswd(afb_req_v4 *request, unsigned nparams, afb_data_t const params[]) {
    afb_data_t args[nparams];
    const char *values[nparams];
    int err;

    if (nparams != 2) goto OnErrorExit;

    // retreive feduser from API argv[0]
    for (int idx=0; idx < 2; idx++) {
        err = afb_data_convert(params[idx], AFB_PREDEFINED_TYPE_STRINGZ, &args[idx]);
        values[idx]= afb_data_ro_pointer(args[idx]);
        if (err < 0) goto OnErrorExit;
    }

    // err= sqlUserAttrCheck (request, values[0], values[1]);
    afb_req_reply(request, err, 0, NULL);

    return;

OnErrorExit:
    afb_req_reply (request, -100, 0, NULL);
}


// when call with no login/passwd display form otherwise try to log user
int pamLoginCB(afb_hreq *hreq, void *ctx) {
	oidcIdpT *idp= (oidcIdpT*)ctx;
	assert (idp->magic == MAGIC_OIDC_IDP);
	char redirectUrl [EXT_HEADER_MAX_LEN];
	const oidcProfilsT *profil=NULL;
	int err, status;

	// check if request as a code
	const char *login = afb_hreq_get_argument(hreq, "login");
	const char *passwd = afb_hreq_get_argument(hreq, "passwd");

	int requestedLoa =afb_session_get_loa (hreq->comreq.session, "ask");

	// add afb-binder endpoint to login redirect alias
    status= afb_hreq_make_here_url(hreq,idp->statics->aliasLogin,redirectUrl,sizeof(redirectUrl));
    if (status < 0) goto OnErrorExit;

	// if no code then set state and redirect to IDP
	if (!login || !passwd) {
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

		EXT_DEBUG ("[pam-redirect-url] %s (pamLoginCB)", url);
		afb_hreq_redirect_to(hreq, url, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);

	} else {

		// we have a code check state to assert that the response was generated by us then request authentication token
		const char *state= afb_hreq_get_argument(hreq, "state");
		if (!state || strcmp (state, afb_session_uuid(hreq->comreq.session))) goto OnErrorExit;

		EXT_DEBUG ("[pam-auth-code] login=%s (pamLoginCB)", login);
        afb_session_get_cookie (hreq->comreq.session, oidcIdpProfilCookie, (void**)&profil);
		if (!profil) goto OnErrorExit;

		// request authentication token from tempry code
		err= pamAccessToken (hreq, idp, profil, login, passwd);
		if (err) goto OnErrorExit;
	}

	return 1; // we're done

OnErrorExit:
	afb_hreq_reply_error(hreq, EXT_HTTP_UNAUTHORIZED);
	return 1;
}


// pam is a fake openif authority as it get everyting locally
int pamInitCB (oidcIdpT *idp, json_object *idpJ, idpGenericCbT *idpConfigCbs) {
	int err;
	assert (idpConfigCbs->magic == MAGIC_OIDC_CBS); // check provided callback magic

	// save generic idp utility callbacks
	idpGenericCbs = idpConfigCbs;

    // only default profil is usefull
	oidcDefaultsT defaults = {
		. profils    = dfltProfils,
		. statics    = &dfltstatics,
		. credentials= &noCredentials,
		. wellknown  = &dfltWellknown,
		. headers    = &noHeaders,
	};

	// check is we have custom options
	json_object *pluginJ= json_object_object_get (idpJ, "plugin");
	if (pluginJ) {
		err= wrap_json_unpack (pluginJ, "{s?i s?s}"
			,"gids", &dfltOpts.gidsMax
			,"avatar", &dfltOpts.avatarAlias
		);
		if (err) {
			EXT_ERROR ("[pam-config-opts] json parse fail 'plugin':{'gids': %d, 'avatar':'%s'", dfltOpts.gidsMax, dfltOpts.avatarAlias);
			goto OnErrorExit;
		}
	}

	// delegate config parsing to common idp utility callbacks
	err = idpGenericCbs->parseConfig (idp, idpJ, &defaults, NULL);
	if (err) goto OnErrorExit;

	// add a dedicate verb to check login/passwd from websocket
	err= afb_api_add_verb(idp->oidc->apiv4, dfltWellknown.identityApiUrl, idp->info, pamCheckLoginPasswd, NULL, NULL, NULL, 0);
	if (err) goto OnErrorExit;

	return 0;

 OnErrorExit:
	return 1;
}

// pam sample plugin exposes only one IDP
idpPluginT idpPamAuth[] = {
  {.uid="pam-login" , .info="use Linux pam login to check user/passwd", .ctx="login", .initCB=pamInitCB, .loginCB=pamLoginCB},
  {.uid= NULL} // must be null terminated
};

// Plugin registration call at config parsing time
int oidcPluginRegister (oidcCoreHdlT *oidc, pluginRegisterCbT registerCB) {

	// plugin is already loaded
	if (idpGenericCbs) return 0;

	// make sure plugin get read access to shadow
	int handle= open ("/etc/shadow", O_RDONLY);
	if (handle < 0) {
		EXT_CRITICAL ("[pam-auth-permission] missing permissio=O_RDONLY file=/etc/shadow (pamLoginCB)");
		goto OnErrorExit;
	}
	close (handle);

    int status= registerCB ("pam-plugin", idpPamAuth);
    return status;

OnErrorExit:
	return -1;	
}