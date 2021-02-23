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
#include "oidc-fedid.h"

#define AFB_BINDING_VERSION 4
#include <afb/afb-binding.h>
#include <libafb/core/afb-req-common.h>
#include <libafb/core/afb-session.h>
#include <libafb/http/afb-hreq.h>

#include <string.h>

MAGIC_OIDC_SESSION(idsvcEvtCookie);
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

// get result from /fedid/create-user
static void idsvcCreateUsrCB(void *ctx, int status, unsigned nreplies, const afb_data_t replies[], afb_req_x4_t request) {
    char *errorMsg= "[user-create-fail]  (idsvcRegisterUsrCB)";
    afb_data_t reply[1],  argv[2];
    fedUserRawT *fedUser=NULL;
    oidcProfilsT *profil=NULL;
    json_object *profilJ;

    if (status) goto OnErrorExit;

    // retrieve current request LOA from session (to be fixed by Jose)
    struct afb_req_common *reqcom= *(struct afb_req_common **)request;

    // user is registrated and loggin let's send current profil
    afb_session_get_cookie (reqcom->session, oidcIdpProfilCookie, (void**)&profil);
    if (!profil) goto OnErrorExit;

    wrap_json_pack (&profilJ, "{ss ss si}"
        , "uid", profil->uid
        , "scope", profil->scope
        , "loa", profil->loa
    );
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_JSON_C, profilJ, 0, (void*)json_object_put, profilJ);

    afb_req_reply(request, 0, 1, reply);
    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
    return;
}

// get result from /fedid/user-unique
static void idsvcRegisterUsrCB(void *ctx, int status, unsigned nreplies, afb_data_t const replies[], afb_req_x4_t request) {
    char *errorMsg= "[user-not-unique] email or pseudo already in federated store (idsvcRegisterUsrCB)";
    afb_data_t reply[1],  argv[2];
    fedUserRawT *fedUser=NULL;
    fedSocialRawT *fedSocial=NULL;

    // if user is not unique return an error to HTML5 app
    if (status != 0) goto OnErrorExit;

    // retrieve current request LOA from session (to be fixed by Jose)
    struct afb_req_common *reqcom= *(struct afb_req_common **)request;

    // retreive user from session cookie
    afb_session_get_cookie (reqcom->session, oidcFedUserCookie, (void**) &fedUser);
    if (!fedUser) goto OnErrorExit;

    afb_session_get_cookie (reqcom->session, oidcFedSocialCookie, (void**) &fedSocial);
    if (!fedSocial) goto OnErrorExit;

    // user is new let's register it within fedid DB
    afb_create_data_raw(&argv[0], fedUserObjType, fedUser, 0, fedUserFreeCB, fedUser);
    afb_create_data_raw(&argv[1], fedSocialObjType, fedSocial, 0, fedSocialFreeCB, fedSocial);
    afb_req_subcall (request, API_OIDC_USR_SVC, "user-create", 2, argv, afb_req_subcall_on_behalf, idsvcCreateUsrCB, NULL);

    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
}

// Return all information we have on current session (profil, loa, idp, ...)
static void idsvcRegisterUsr(afb_req_x4_t request, unsigned nparams, afb_data_x4_t const params[]) {
    char *errorMsg= "[fail-get-session] no session running anonymous mode";
    afb_data_t reply[1], argv[1];
    afb_data_t args[nparams];
    afb_event_t evtCookie=NULL;
    const oidcProfilsT *profil=NULL;
   	fedUserRawT *fedUser;
	const fedSocialRawT *fedSocial;
    json_object *profilJ;
    int err;

    if (nparams != 1) goto OnErrorExit;

    // retrieve current request LOA from session (to be fixed by Jose)
    struct afb_req_common *reqcom= *(struct afb_req_common **)request;
    afb_session_get_cookie (reqcom->session, oidcIdpProfilCookie, (void**)&profil);
    if (!profil) goto OnErrorExit;

    // retreive fedsocial from session
	afb_session_get_cookie (reqcom->session, oidcFedSocialCookie, (void **) &fedSocial);

    // retreive feduser from API argv[0]
    err = afb_data_convert(params[0], fedUserObjType, &args[0]);
    if (err < 0) goto OnErrorExit;

    // push feduser into session as callback will need it
    fedUser= (void*) afb_data_ro_pointer(args[0]);
    fedUser->ucount++; // protect feduser as it us used both as a cookie and a param
    afb_session_set_cookie (reqcom->session, oidcFedUserCookie, fedUser, fedUserFreeCB);

    // verify pseudo and email unicity
    afb_create_data_raw(&argv[0], fedUserObjType, fedUser, 0, fedUserFreeCB, fedUser);
    afb_req_subcall (request, API_OIDC_USR_SVC, "user-unique", 1, argv, afb_req_subcall_on_behalf, idsvcRegisterUsrCB, NULL);

    return;    

OnErrorExit:
    AFB_REQ_ERROR (request, errorMsg);
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
}

// Return all information we have on current session (profil, loa, idp, ...)
static void idsvcSessionGet (afb_req_x4_t request, unsigned nparams, afb_data_x4_t const params[]) {
    char *errorMsg= "[fail-get-session] no session running anonymous mode";
    afb_data_t reply[3];
    afb_event_t evtCookie=NULL;
    const oidcProfilsT *profil=NULL;
   	fedUserRawT *fedUser;
	fedSocialRawT *fedSocial;
    json_object *profilJ;

    // retrieve current request LOA from session (to be fixed by Jose)
    struct afb_req_common *reqcom= *(struct afb_req_common **)request;
    afb_session_get_cookie (reqcom->session, oidcIdpProfilCookie, (void**)&profil);
    if (!profil) goto OnErrorExit;

    wrap_json_pack (&profilJ, "{ss ss si}"
        , "uid", profil->uid
        , "scope", profil->scope
        , "loa", profil->loa
    );

    afb_session_get_cookie (reqcom->session, oidcFedUserCookie, (void**) &fedUser);
	afb_session_get_cookie (reqcom->session, oidcFedSocialCookie, (void **) &fedSocial);

    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_JSON_C, profilJ, 0, (void*)json_object_put, profilJ);
    afb_create_data_raw(&reply[1], fedUserObjType, fedUser, 0, fedUserFreeCB, fedUser);
    afb_create_data_raw(&reply[2], fedSocialObjType, fedSocial, 0, fedSocialFreeCB, fedSocial);

    afb_req_reply (request, 0, 3, reply);

    return;    

OnErrorExit:
    AFB_REQ_ERROR (request, errorMsg);
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
}


// if not already done create and register a session event
static void idsvcSubscribe (afb_req_x4_t request, unsigned nparams, afb_data_x4_t const params[]) {
    const char *errorMsg = "[fail-event-create] hoops internal error (idsvcSubscribe)";
    int err;
    char *response;
    afb_data_t reply;
    afb_event_t evtCookie=NULL;

    // retrieve current request LOA from session (to be fixed by Jose)
    struct afb_req_common *reqcom= *(struct afb_req_common **)request;
    afb_session_get_cookie (reqcom->session, idsvcEvtCookie, (void**)&evtCookie);
    if (!evtCookie) {
       err= afb_api_new_event(afb_req_get_api(request), afb_session_uuid(reqcom->session), &evtCookie);
       if (err < 0) goto OnErrorExit;
       afb_session_set_cookie (reqcom->session, idsvcEvtCookie, (void*)evtCookie, NULL);
       afb_req_subscribe(request, evtCookie);
    }

    asprintf (&response, "session-uuid=%s", afb_session_uuid(reqcom->session));
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, response, strlen(response)+1, free, NULL);
    afb_req_reply(request, 0, 1, &reply);

    return;

OnErrorExit:
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, &reply);
}

// Push a json object event to html5 application
int idscvPushEvent (afb_hreq *hreq, json_object *eventJ) {
    int count;
    afb_event_t evtCookie=NULL;
    afb_data_t reply;

    afb_session_get_cookie (hreq->comreq.session, idsvcEvtCookie, (void**)&evtCookie);
    if (!evtCookie) goto OnErrorExit;

    // create an API-V4 json param
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON, eventJ, 0, (void*) json_object_put, eventJ);
    count = afb_event_push (evtCookie, 1, &reply);

    // no one listening clear event and cookie
    if (count <= 0) {
        afb_event_unref (evtCookie);
        afb_session_set_cookie (hreq->comreq.session, idsvcEvtCookie, NULL, NULL);
    }
 
    return count;

OnErrorExit:
    json_object_put(eventJ);
    return -1;    
}

// return the list of autorities matching requested LOA
static void idsvcList (afb_req_x4_t request, unsigned nparams, afb_data_x4_t const params[]) {
    afb_data_t reply;
    oidcCookieT *aliasCookie;
    json_object *idpsJ;

    // retreive OIDC global context from API handle
  	oidcCoreHdlT *oidc= afb_api_get_userdata(afb_req_get_api(request));
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
    { .verb = "ping",     .callback = idsvcPing    , .info = "ping test"},
    { .verb = "list",     .callback = idsvcList    , .info = "request idp list/scope for a given LOA level"},
    { .verb = "subscribe", .callback = idsvcSubscribe, .info = "subscribe to sgate private client session events"},
    { .verb = "session",  .callback = idsvcSessionGet, .info = "retreive current client session [profil, user, social]"},
    { .verb = "register", .callback = idsvcRegisterUsr, .info = "register federated user profile into local fedid store"},

    { NULL} // terminator
};

int idsvcDeclare (oidcCoreHdlT *oidc, afb_apiset *declare_set, afb_apiset *call_set) {

    oidcApisT apiSvc={
        .uid = oidc->uid,
        .info= "internal oidc idp api",
        .uri = "@oidc",
        .loa = 0,
    };

    // register verbs
    int err= apisCreateSvc (oidc, &apiSvc, declare_set, call_set, idsvcVerbs);
    if (err) goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}