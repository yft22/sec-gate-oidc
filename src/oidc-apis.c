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
#include "oidc-apis.h"

#include <assert.h>
#include <afb/afb-binding-v4.h>
#include <libafb/core/afb-v4.h>
#include <libafb/core/afb-api-v4.h>
#include <libafb/core/afb-string-mode.h>
#include <libafb/apis/afb-api-ws.h>
#include <afb/afb-auth.h>

int apisCreateSvc (oidcCoreHdlT *oidc, oidcApisT *apiSvc, afb_apiset *declare_set, afb_apiset *call_set, afb_verb_v4 *apiVerbs) {
	char apiUri [EXT_URL_MAX_LEN];
	afb_api_v4 *apiv4;

	// register API
	int status= afb_api_v4_create(
		&apiv4, declare_set, call_set,
		apiSvc->uid, Afb_String_Const,
		apiSvc->info, Afb_String_Const,
		0, // noconcurrency unset
		NULL, NULL, // pre-initcb + ctx
		NULL, Afb_String_Const // no binding.so path
	);
	if (status) goto OnErrorExit;

	// add oidc context to internal api
	oidc->apiv4= apiv4;
	afb_api_v4_set_userdata(apiv4, oidc);

	// add verb to API
	int err= afb_api_v4_set_verbs_hookable (apiv4, apiVerbs);
	if (err) goto OnErrorExit;

	snprintf (apiUri, sizeof(apiUri), "unix:@%s", apiSvc->uid);
	afb_api_ws_add_server (apiUri, declare_set, call_set);

	return 0;

OnErrorExit:
	return 1;
	EXT_CRITICAL ("[fail-api-create] ext=%s api=%s fail to register (apisCreateSvc)", oidc->uid, apiSvc->uid);
}

// import API client from uri and map corresponding roles into apis hashtable
int apisRegisterOne (oidcCoreHdlT *oidc, oidcApisT *api, afb_apiset *declare_set, afb_apiset *call_set) {
    int err, index;

    // if API is not runnning within the binder register client API
    if (api->uri[0] != '@') {
	    int err= afb_api_ws_add_client(api->uri, declare_set, call_set, !api->lazy);
	    if (err) goto OnErrorExit;
    }

	// Extract API from URI 
    for (index=0; api->uri[index]; index ++) {
        if (api->uri[index] == '@' || api->uri[index] == '/') break;
    }

    // If needed create an alias
    if (api->uri[index]) {
        if (strcasecmp (&api->uri[index+1], api->uid)) {
            err= afb_alias_api(&api->uri[index+1],api->uid);
            if (err) goto OnErrorExit;
        }

    }

	// register api for later loa/roles check
	HASH_ADD_KEYPTR(hh, oidc->apisHash, api->uid, strlen(api->uid), api);  // **** FULUP TBD still needed 

	return 0;

OnErrorExit:
	EXT_ERROR ("[oidc-api-not-found] ext=%s fail to connect to api=%s uri=%s (apisRegisterOne)", oidc->uid, api->uid, api->uri);
	return 1;
}

static int apisParseOne (oidcCoreHdlT *oidc, json_object *apiJ, oidcApisT *api) {
	json_object *rolesJ=NULL;

	int err= wrap_json_unpack (apiJ, "{ss,s?s,s?s,s?i,s?i,s?o}"
		, "uid", &api->uid
		, "info", &api->info
		, "uri", &api->uri
		, "loa", &api->loa
		, "lazy", &api->lazy
		, "role", &rolesJ
		);
	if (err) {
		EXT_CRITICAL ("[idp-api-error] idpmake=%s parsing fail profil expect: uid,uri,loa,role (apisParseOne)", oidc->uid);
		goto OnErrorExit;
	}

	// provide some defaults value based on uid
	if (!api->uri) asprintf ((char**)&api->uri,"unix:@%s", api->uid);

	if (rolesJ) {
		const char **roles;
		switch (json_object_get_type (rolesJ)) {
			int count;

			case json_type_array:
				count= (int)json_object_array_length(rolesJ);
				roles= calloc(count+1, sizeof(char*));

				for (int idx=0; idx < count; idx ++) {
					json_object *roleJ= json_object_array_get_idx(rolesJ, idx);
					roles[idx]= json_object_get_string(roleJ);
				}
				break;

			case json_type_string:
				roles = calloc (2, sizeof(char*));
				roles[0]= json_object_get_string(rolesJ);
				break;

			default:
				EXT_CRITICAL("[idp-apis-error] idp=%s role should be json_array|json_string (apisParseOne)", oidc->uid);
				goto OnErrorExit;
		}
		api->roles=roles;
		api->oidc=oidc;
	}
return 0;

OnErrorExit:
  return 1;
}

oidcApisT *apisParseConfig (oidcCoreHdlT *oidc, json_object *apisJ) {
    oidcApisT *apis;
    int err;

	switch (json_object_get_type (apisJ)) {
				int count;

				case json_type_array:
					count= (int)json_object_array_length(apisJ);
					apis= calloc (count+1, sizeof(oidcApisT));

					for (int idx=0; idx < count; idx ++) {
						json_object *apiJ= json_object_array_get_idx(apisJ, idx);
						err= apisParseOne (oidc, apiJ, &apis[idx]);
						if (err) goto OnErrorExit;
					}
					break;

				case json_type_object:
					apis = calloc (2, sizeof(oidcApisT));
					err= apisParseOne (oidc, apisJ, &apis[0]);
					if (err) goto OnErrorExit;
					break;

				default:
					EXT_CRITICAL("[idp-apis-error] idp=%s apis should be json_array|json_object (apisParseConfig)", oidc->uid);
					goto OnErrorExit;
			}
			return apis;

 OnErrorExit:
  return NULL;
}
