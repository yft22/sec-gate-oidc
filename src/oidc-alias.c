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

#define _GNU_SOURCE

#include "oidc-core.h"
#include "oidc-alias.h"
#include "oidc-idsvc.h"
#include "http-client.h"

#define WITH_LIBMICROHTTPD 1
#include <libafb/extend/afb-extension.h>
#include <libafb/core/afb-session.h>
#include <libafb/http/afb-hsrv.h>
#include <libafb/http/afb-hreq.h>
#include <libafb/core/afb-common.h>

#include <string.h>
#include <microhttpd.h>
#include <locale.h>

// dummy unique value for session key
MAGIC_OIDC_SESSION(oidcIdpLoa);
MAGIC_OIDC_SESSION(oidcIdpRoles);
MAGIC_OIDC_SESSION(oidcAliasCookie);

int aliasCheckRoles (afb_session *session, oidcAliasT *alias) {
	char **avaliableRoles;
	int requestCount=0, matchCount=0;

	// search within profile if we have the right role
	int err= afb_session_get_cookie(session, oidcIdpRoles, (void**)&avaliableRoles);
	if (err) goto OnErrorExit;

	// this should be replaced by Cynagora request
	for (int idx=0; alias->roles[idx]; idx++) {
		requestCount++;
		for (int jdx=0; avaliableRoles[jdx]; idx++) {
			if (!strcasecmp (alias->roles[idx], avaliableRoles[jdx])) {
				matchCount++;
				break;
			}
		}
	}
	// check roles match
	if (requestCount != matchCount) goto OnErrorExit;
	return 0;

OnErrorExit:
	return 1;
};

static void aliasFreeCookie (void* ctx) {
	oidcCookieT *cookie= (oidcCookieT*)ctx;
	free (cookie->url);
	free (cookie);
}

// create aliasFrom cookie and redirect to login page
static void aliasRedirectLogin (afb_hreq *hreq, oidcAliasT *alias) {
	oidcCookieT *cookie= malloc (sizeof(oidcCookieT));
    int err;

	cookie->url= strdup (hreq->url);
	cookie->alias=alias;
	afb_session_set_cookie (hreq->comreq.session, oidcAliasCookie, cookie, aliasFreeCookie);
	afb_req_common_set_token (&hreq->comreq, NULL);

	char url[EXT_URL_MAX_LEN];
	httpKeyValT query[]= {
			{.tag="action"    , .value="login"},
			{.tag="state"     , .value=afb_session_uuid(hreq->comreq.session)},
			{.tag="language"  , .value=setlocale(LC_CTYPE, "")},

			{NULL} // terminator
	};

    err= httpBuildQuery (alias->uid, url, sizeof(url), NULL /* prefix */, alias->oidc->globals->loginUrl, query);
	if (err) {
        EXT_ERROR ("[fail-login-redirect] fail to build redirect url (aliasRedirectLogin)");
        goto OnErrorExit;
    }

	EXT_DEBUG ("[alias-redirect-login] %s (aliasRedirectLogin)", url);
	afb_hreq_redirect_to(hreq, url, HREQ_QUERY_INCL, HREQ_REDIR_TMPY);
    return;

OnErrorExit:
	afb_hreq_redirect_to(hreq, alias->oidc->globals->loginUrl, HREQ_QUERY_EXCL, HREQ_REDIR_TMPY);
}

static int aliasCheckLoaCB (afb_hreq *hreq, void *ctx) {
	oidcAliasT *alias= (oidcAliasT*)ctx;
	int currentLoa;

	// in case session create failed
	if (!hreq->comreq.session) {
		EXT_ERROR ("[fail-hreq-session] fail to initialise hreq session (aliasCheckLoaCB)");
		afb_hreq_reply_error (hreq, EXT_HTTP_CONFLICT);
		goto OnRedirectExit;
	}

	EXT_NOTICE ("session uuid=%s (aliasCheckLoaCB)", afb_session_uuid(hreq->comreq.session));

	// if LOA too weak redirect to authentication  //afb_session_close ()
	currentLoa=  afb_session_get_loa (hreq->comreq.session, oidcIdpLoa);
	if (alias->loa > currentLoa) {
		json_object *eventJ;

		wrap_json_pack (&eventJ, "{si ss ss si si}"
			, "status", STATUS_OIDC_AUTH_DENY
			, "uid", alias->uid
			, "url", alias->url
			, "loa-target", alias->loa
			, "loa-session", currentLoa
		);

		// try to push event to notify the access deny and replay with redirect to login
		idscvPushEvent (hreq, eventJ);
		aliasRedirectLogin (hreq, alias);
		goto OnRedirectExit;
	}

	if (alias->roles) {
		int err= aliasCheckRoles (hreq->comreq.session, alias);
		if (err) {
			aliasRedirectLogin (hreq, alias);
			goto OnRedirectExit;
		}
	}

	// change hreq bearer
	afb_req_common_set_token (&hreq->comreq, NULL);
	return 0;

OnRedirectExit:
	return 1;
}

int aliasRegisterOne (oidcCoreHdlT *oidc, oidcAliasT *alias, afb_hsrv *hsrv) {
	const char* rootdir;
	int status;

	status= afb_hsrv_add_handler(hsrv, alias->url, aliasCheckLoaCB, alias, alias->priority);
	if (status != AFB_HSRV_OK) goto OnErrorExit;

	// if alias full path does not start with '/' then prefix it with http_root_dir
	if (alias->path[0] == '/') rootdir="";
	else rootdir= afb_common_rootdir_get_path();

	status= afb_hsrv_add_alias_path(hsrv, alias->url, rootdir, alias->path, alias->priority-1, 0 /*not relax*/);
	if (status != AFB_HSRV_OK) goto OnErrorExit;

	EXT_DEBUG ("[alias-register] uid=%s loa=%d url='%s' fullpath='%s/%s'", alias->uid, alias->loa, alias->url, rootdir, alias->path);
	return 0;

OnErrorExit:
	EXT_ERROR("[alias-fail-register] fail to register alias uid=%s url=%s fullpath=%s/%s", alias->uid, alias->url, rootdir, alias->path);
	return 1;
}

static int idpParseOneAlias (oidcCoreHdlT *oidc, json_object *aliasJ, oidcAliasT *alias) {
	json_object *rolesJ=NULL;

	int err= wrap_json_unpack (aliasJ, "{ss,s?s,s?s,s?s,s?i,s?i,s?o}"
		, "uid", &alias->uid
		, "info", &alias->info
		, "url", &alias->url
		, "path", &alias->path
		, "prio", &alias->priority
		, "loa", &alias->loa
		, "role", rolesJ
		);
	if (err) {
		EXT_CRITICAL ("[idp-alias-error] oidc=%s parsing fail profil expect: uid,url,fullpath,prio,loa,role (idpParseOneAlias)", oidc->uid);
		goto OnErrorExit;
	}

	// provide some defaults value based on uid
	if (!alias->url) asprintf ((char**)&alias->url,"/%s", alias->uid);
	if (!alias->path) asprintf ((char**)&alias->path,"$ROOTDIR/%s", alias->uid);

	if (rolesJ) {
		const char **roles;
		int count;
		switch (json_object_get_type (rolesJ)) {

			case json_type_array:
				count= (int)json_object_array_length(rolesJ);
				roles= calloc(count+1, sizeof(char*));

				for (int idx=0; idx < count; idx ++) {
					json_object *roleJ= json_object_array_get_idx(rolesJ, idx);
					roles[idx]= json_object_get_string(roleJ);
				}
				break;

			case json_type_object:
				roles = calloc (2, sizeof(char*));
				roles[0]= json_object_get_string(rolesJ);
				break;

			default:
				EXT_CRITICAL("[idp-alias-error] oidc=%s role should be json_array|json_object (idpParseOneAlias)", oidc->uid);
				goto OnErrorExit;
		}
		alias->roles=roles;
	}
	alias->oidc= oidc;
	return 0;

OnErrorExit:
  return 1;
}

oidcAliasT *aliasParseConfig (oidcCoreHdlT *oidc, json_object *aliasesJ) {

    oidcAliasT *aliases;
    int err;

	switch (json_object_get_type (aliasesJ)) {
				int count;

				case json_type_array:
					count= (int)json_object_array_length(aliasesJ);
					aliases= calloc (count+1, sizeof(oidcAliasT));

					for (int idx=0; idx < count; idx ++) {
						json_object *aliasJ= json_object_array_get_idx(aliasesJ, idx);
						err= idpParseOneAlias (oidc, aliasJ, &aliases[idx]);
						if (err) goto OnErrorExit;
					}
					break;

				case json_type_object:
					aliases = calloc (2, sizeof(oidcAliasT));
					err= idpParseOneAlias (oidc, aliasesJ, &aliases[0]);
					if (err) goto OnErrorExit;
					break;

				default:
					EXT_CRITICAL("[idp-aliases-error] idp=%s alias should be json_array|json_object (aliasParseConfig)", oidc->uid);
					goto OnErrorExit;
			}
			return aliases;

 OnErrorExit:
  return NULL;
}

