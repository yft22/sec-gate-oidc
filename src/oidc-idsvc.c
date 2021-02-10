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
#include "oidc-idsvc.h"
#include "oidc-apis.h"
#include "oidc-idp.h"
#include "oidc-alias.h"

#define AFB_BINDING_VERSION 4
#include <afb/afb-binding.h>
#include <libafb/core/afb-req-common.h>
#include <libafb/core/afb-session.h>

#include <string.h>

static const char unauthorizedMsg[]="[unauthorized-api-call] authenticate to upgrade session/loa (idsvcList)";


static void idsvcPing (afb_req_x4_t request, unsigned nparams, afb_data_x4_t const params[]) {
    static int count=0;
    char *response;
    afb_data_t reply;

    asprintf (&response, "Pong=%d", count++);
    AFB_REQ_NOTICE (request, "idp:ping count=%d", count);

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, response, strlen(response)+1, free, NULL);
    afb_req_reply(request, 0, 1, &reply);

    return;
}

static void idsvcList (afb_req_x4_t request, unsigned nparams, afb_data_x4_t const params[]) {
    afb_data_t reply;
    oidcCookieT *aliasCookie;
    json_object *idpsJ;

    // retreive OIDC global context from API handle
  	oidcCoreHandleT *oidc= afb_api_get_userdata(afb_req_get_api(request));
    if (!oidc || oidc->magic != MAGIC_OIDC_MAIN) goto OnErrorExit;

    // retrieve current request LOA from session (to be fixed by Jose)
    struct afb_req_common *reqcom= *(struct afb_req_common **)request;

    AFB_REQ_NOTICE (request, "session uuid=%s (idsvcList)", afb_session_uuid(reqcom->session));
    afb_session_get_cookie (reqcom->session, oidcAliasCookie, (void**)&aliasCookie);

    // build IDP list with corresponding scope for requested LOA
    if (aliasCookie) idpsJ= idpLoaProfilsGet (oidc, aliasCookie->alias->loa);
    else idpsJ= idpLoaProfilsGet (oidc, 0);

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, idpsJ, 0, (void*)json_object_put, idpsJ);
    afb_req_reply(request, 0, 1, &reply);

    return;

OnErrorExit:
    AFB_REQ_ERROR (request, unauthorizedMsg);
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, unauthorizedMsg, sizeof(unauthorizedMsg), NULL, NULL);
    afb_req_reply (request, -1, 1, &reply);
}


// Static verb not depending on shell json config file
static afb_verb_t idsvcVerbs[] = {
    /* VERB'S NAME         FUNCTION TO CALL         SHORT DESCRIPTION */
    { .verb = "ping",     .callback = idsvcPing    , .info = "oidc ping test"},
    { .verb = "info",     .callback = idsvcPing    , .info = "oidc introspection"},
    { .verb = "list",     .callback = idsvcList    , .info = "oidc request idp list/scope for a given LOA level"},

    { NULL} // terminator
};

int idsvcDeclare (oidcCoreHandleT *oidc, afb_apiset *declare_set, afb_apiset *call_set) {

    oidcApisT apiSvc={
        .uid = oidc->uid,
        .info= "internal oidc idp api",
        .uri = "@oidc",
        .loa = 0,
    };

    int err= apisCreateSvc (oidc, &apiSvc, declare_set, call_set, idsvcVerbs);
    if (err) goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}