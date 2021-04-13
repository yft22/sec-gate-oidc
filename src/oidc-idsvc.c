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

#include <string.h>

#include <libafb/afb-v4.h>
#include <libafb/afb-core.h>
#include <libafb/afb-http.h>

#include "oidc-core.h"
#include "oidc-idsvc.h"
#include "oidc-apis.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "oidc-fedid.h"

MAGIC_OIDC_SESSION(idsvcEvtCookie);
static const char unauthorizedMsg[]="[unauthorized-api-call] authenticate to upgrade session/loa (idpsList)";

static void idsvcPing (afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    static int count=0;
    char *response;
    afb_data_t reply;

    asprintf (&response, "Pong=%d", count++);
    AFB_REQ_NOTICE (request, "idp:ping count=%d", count);

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, response, strlen(response)+1, NULL, NULL);
    afb_req_reply(request, 0, 1, &reply);

    return;
}

// get result from /fedid/create-user
static void userCheckAttrCB(void *ctx, int status, unsigned argc, const afb_data_t argv[], afb_req_t request) {
    char *errorMsg= "[user-attr-fail]  (userCheckAttrCB)";
    afb_data_t reply[1],  argd[2];
    fedUserRawT *fedUser=NULL;
    oidcProfilsT *profil=NULL;
    json_object *profilJ;

    // return creation status to HTML5
    if (status < 0) goto OnErrorExit;
    afb_req_reply(request, status, 0, NULL);
    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
    return;
}

// check user email/pseudo attribute
static void userCheckAttr(afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    int err;

    if (argc != 1) goto OnErrorExit;
    afb_req_subcall (request, API_OIDC_USR_SVC, "attr-check", argc, argv, afb_req_subcall_on_behalf, userCheckAttrCB, NULL);

OnErrorExit:
    afb_req_reply (request, -100, 0, NULL);
}

// get result from /fedid/create-user
static void userGetIdpsCB(void *ctx, int status, unsigned argc, const afb_data_t argv[], afb_req_t request) {
    char *errorMsg= "[user-link-fail] internal error (userGetIdpsCB)";
    fedSocialRawT *fedSocial=NULL, *fedToLink;
    json_object * idpsJ, *responseJ;
    afb_data_t reply[1];
    int err;

    // convert and retreive input arguments
    afb_data_t argd[2];
    const afb_type_t argt[]= {fedUserIdpsObjType, NULL};
    err= afb_data_array_convert (argc, argv, argt, argd);
    if (err < 0) goto OnErrorExit;
    char ** idps= (void*) afb_data_ro_pointer(argd[0]);

    // retreive oidc config from current alias cookie
    oidcAliasT *alias=NULL;
    afb_session *session= afb_req_v4_get_common(request)->session;
    afb_session_cookie_get (session, oidcAliasCookie, (void**)&alias);
    if (!alias) goto OnErrorExit;

    // Keep track of current fedsocial authentication to link account
   	afb_session_cookie_get (session, oidcFedSocialCookie, (void **) &fedSocial);
    if (!fedSocial) goto OnErrorExit;
    // store fedsocial cookie for further use
    fedToLink=malloc(sizeof(fedSocialRawT));
    memcpy (fedToLink, fedSocial, sizeof(fedSocialRawT));
    // afb_session_cookie_set (session, oidcFedSocialCookie, (void **) &fedSocial, fedSocial, fedSocialFreeCB, fedSocial);

    idpsJ= idpLoaProfilsGet(alias->oidc, 0, NULL);

    err= wrap_json_pack (&responseJ, "{ss so}"
        , "target", alias->oidc->globals->fedlinkUrl
        , "idps", idpsJ
    );
    if (err) goto OnErrorExit;

fprintf (stderr, "**** userGetIdpsCB responsej=%s\n", json_object_get_string(responseJ));
    afb_create_data_raw(reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0, (void*)json_object_put, responseJ);
    afb_req_reply(request, 0, 1, reply);

    // return creation status to HTML5
    if (status < 0) goto OnErrorExit;
    afb_req_reply(request, status, 0, NULL);
    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
    return;
}

// Link two IDP account with a single federated user
static void userGetIdps(afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    int err;

    if (argc != 1) goto OnErrorExit;
    afb_req_subcall (request, API_OIDC_USR_SVC, "social-idps", argc, argv, afb_req_subcall_on_behalf, userGetIdpsCB, NULL);

OnErrorExit:
    afb_req_reply (request, -100, 0, NULL);
}

// get result from /fedid/create-user
static void userRegisterCB(void *ctx, int status, unsigned argc, const afb_data_t argv[], afb_req_t request) {
    char *errorMsg= "[user-create-fail]  (idsvcuserRegisterCB)";
    afb_data_t reply[1],  argd[2];
    fedUserRawT *fedUser=NULL;
    oidcProfilsT *profil=NULL;
    oidcAliasT *alias=NULL;
    json_object *aliasJ;
    afb_session *session= afb_req_v4_get_common(request)->session;

    // return creation status to HTML5
    if (status < 0) goto OnErrorExit;

    // return destination alias
    afb_session_cookie_get (session, oidcAliasCookie, (void**)&alias);
    wrap_json_pack (&aliasJ, "{ss}"
	    , "target", alias->url ?: "/"
    );
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_JSON_C, aliasJ, 0, (void*) json_object_put, aliasJ);
    afb_req_reply(request, status, 1, reply);
    return;

OnErrorExit:
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
    return;
}

// Try to store fedsocial and feduser into local store
static void userRegister(afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    char *errorMsg= "[user-register-fail] invalid request";
    afb_event_t evtCookie=NULL;
    const oidcProfilsT *profil=NULL;
	const fedSocialRawT *fedSocial;
    int err;

    if (argc != 1) goto OnErrorExit;

    // convert input arguments
    afb_data_t reply[1], argd[2];
    const afb_type_t argt[]= {fedUserObjType, NULL};
    err= afb_data_array_convert (argc, argv, argt, argd);
    if (err < 0) goto OnErrorExit;
    fedUserRawT *fedUser= (void*) afb_data_ro_pointer(argd[0]);

    // retrieve current request LOA from session (to be fixed by Jose)
    afb_session *session= afb_req_v4_get_common(request)->session;
    afb_session_cookie_get (session, oidcIdpProfilCookie, (void**)&profil);
    if (!profil) goto OnErrorExit;

fprintf (stderr, "*** userRegister session uid=%s\n", afb_session_uuid(session));

    // retreive fedsocial from session
   	afb_session_cookie_get (session, oidcFedSocialCookie, (void **) &fedSocial);
    if (!fedSocial) goto OnErrorExit;


    afb_session_cookie_set (session, oidcFedUserCookie, fedUser, (void*)afb_data_unref, argd[0]);

    // user is new let's register it within fedid DB
    afb_data_addref(argd[0]);
    err= afb_create_data_raw(&argd[1], fedSocialObjType, fedSocial, 0, fedSocialFreeCB, (void*)fedSocial);
    if (err < 0) goto OnErrorExit;

    afb_req_subcall (request, API_OIDC_USR_SVC, "user-create", 2, argd, afb_req_subcall_on_behalf, userRegisterCB, NULL);
    return;

OnErrorExit:
    AFB_REQ_ERROR (request, errorMsg);
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
    if (argd[0]) afb_data_array_unref(argc, argd);
}

// Return all information we have on current session (profil, loa, idp, ...)
static void sessionGet (afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    char *errorMsg= "[fail-get-session] no session running anonymous mode";
    afb_data_t reply[3];
    afb_event_t evtCookie=NULL;
    const oidcProfilsT *profil=NULL;
   	fedUserRawT *fedUser;
	fedSocialRawT *fedSocial;
    json_object *profilJ;

    // retrieve current request LOA from session (to be fixed by Jose)
    afb_session *session= afb_req_v4_get_common(request)->session;
    afb_session_cookie_get (session, oidcIdpProfilCookie, (void**)&profil);
    if (!profil) goto OnErrorExit;

    wrap_json_pack (&profilJ, "{ss ss si}"
        , "uid", profil->uid
        , "scope", profil->scope
        , "loa", profil->loa
    );

    afb_session_cookie_get (session, oidcFedUserCookie, (void**) &fedUser);
	afb_session_cookie_get (session, oidcFedSocialCookie, (void **) &fedSocial);
    afb_create_data_raw(&reply[0], fedUserObjType, fedUser, 0, fedUserFreeCB, fedUser);
    afb_create_data_raw(&reply[1], fedSocialObjType, fedSocial, 0, NULL, NULL); // keep feduser
    afb_create_data_raw(&reply[2], AFB_PREDEFINED_TYPE_JSON_C, profilJ, 0, (void*)json_object_put, profilJ);

    afb_req_reply (request, 0, 3, reply);
    return;

OnErrorExit:
    AFB_REQ_ERROR (request, errorMsg);
    afb_create_data_raw(&reply[0], AFB_PREDEFINED_TYPE_STRINGZ, errorMsg, strlen(errorMsg)+1, NULL, NULL);
    afb_req_reply (request, -1, 1, reply);
}


// if not already done create and register a session event
static void subscribeEvent (afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    const char *errorMsg = "[fail-event-create] hoops internal error (idsvcSubscribe)";
    int err;
    char *response;
    afb_data_t reply;
    afb_event_t evtCookie=NULL;

    // retrieve current request LOA from session (to be fixed by Jose)
    afb_session *session= afb_req_v4_get_common(request)->session;
    afb_session_cookie_get (session, idsvcEvtCookie, (void**)&evtCookie);
    if (!evtCookie) {
       err= afb_api_new_event(afb_req_get_api(request), afb_session_uuid(session), &evtCookie);
       if (err < 0) goto OnErrorExit;
       afb_session_cookie_set (session, idsvcEvtCookie, (void*)evtCookie, NULL,NULL);
       afb_req_subscribe(request, evtCookie);
    }

    asprintf (&response, "session-uuid=%s", afb_session_uuid(session));
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

    afb_session_cookie_get (hreq->comreq.session, idsvcEvtCookie, (void**)&evtCookie);
    if (!evtCookie) goto OnErrorExit;

    // create an API-V4 json param
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON, eventJ, 0, (void*) json_object_put, eventJ);
    count = afb_event_push (evtCookie, 1, &reply);

    // no one listening clear event and cookie
    if (count <= 0) {
        afb_event_unref (evtCookie);
        afb_session_cookie_set (hreq->comreq.session, idsvcEvtCookie, NULL, NULL,NULL);
    }

    return count;

OnErrorExit:
    json_object_put(eventJ);
    return -1;
}


// return the list of autorities matching requested LOA
static void idpsList (afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    int err;
    afb_data_t reply;
    json_object *idpsJ, *responseJ, *aliasJ;
    oidcAliasT *alias;

    // retreive OIDC global context from API handle
  	oidcCoreHdlT *oidc= afb_api_get_userdata(afb_req_get_api(request));
    if (!oidc || oidc->magic != MAGIC_OIDC_MAIN) goto OnErrorExit;

    // retrieve current request LOA from session (to be fixed by Jose)
    afb_session *session= afb_req_v4_get_common(request)->session;

    AFB_REQ_NOTICE (request, "session uuid=%s (idpsList)", afb_session_uuid(session));
    afb_session_cookie_get (session, oidcAliasCookie, (void**)&alias);

    // build IDP list with corresponding scope for requested LOA
    if (alias) {
        idpsJ= idpLoaProfilsGet (oidc, alias->loa, NULL);
        wrap_json_pack (&aliasJ, "{ss ss* ss si}"
            , "uid", alias->uid
            , "info", alias->info
			, "url", alias->url
			, "loa", alias->loa
        );

    } else {
        idpsJ= idpLoaProfilsGet(oidc, 0, NULL);
        aliasJ=NULL;
    }

    err= wrap_json_pack (&responseJ, "{so so*}"
        , "idps", idpsJ
        , "alias", aliasJ
        );
    if (err) goto OnErrorExit;

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0, (void*)json_object_put, responseJ);
    afb_req_reply(request, 0, 1, &reply);

    return;

OnErrorExit:
    AFB_REQ_ERROR (request, unauthorizedMsg);
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, unauthorizedMsg, sizeof(unauthorizedMsg), NULL, NULL);
    afb_req_reply (request, -1, 1, &reply);
}

// return the list of autorities matching requested LOA
static void urlsList (afb_req_t request, unsigned argc, afb_data_t const argv[]) {
    int err;
    afb_data_t reply;
    json_object *responseJ;

    // retreive OIDC global context from API handle
  	oidcCoreHdlT *oidc= afb_api_get_userdata(afb_req_get_api(request));
    if (!oidc || oidc->magic != MAGIC_OIDC_MAIN) goto OnErrorExit;

    err=wrap_json_pack (&responseJ, "{ss ss ss ss ss}"
        , "login",      oidc->globals->loginUrl
        , "fedlink",    oidc->globals->loginUrl
        , "register",   oidc->globals->loginUrl
        , "remove",     oidc->globals->loginUrl
        , "error",      oidc->globals->errorUrl
    );
    if (err) goto OnErrorExit;

    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_JSON_C, responseJ, 0, (void*)json_object_put, responseJ);
    afb_req_reply(request, 0, 1, &reply);

    return;

OnErrorExit:
    AFB_REQ_ERROR (request, unauthorizedMsg
    );
    afb_create_data_raw(&reply, AFB_PREDEFINED_TYPE_STRINGZ, unauthorizedMsg, sizeof(unauthorizedMsg), NULL, NULL);
    afb_req_reply (request, -1, 1, &reply);
}


// Static verb not depending on shell json config file
static afb_verb_t idsvcVerbs[] = {
    /* VERB'S NAME         FUNCTION TO CALL         SHORT DESCRIPTION */
    { .verb = "ping",         .callback = idsvcPing,     .info = "ping test"},
    { .verb = "url-list",     .callback = urlsList,      .info = "request wellknown url list"},
    { .verb = "idp-list",     .callback = idpsList,      .info = "request idp list/scope for a given LOA level"},
    { .verb = "evt-subs",     .callback = subscribeEvent,.info = "subscribe to sgate private client session events"},
    { .verb = "get-session",  .callback = sessionGet,    .info = "retreive current client session [profil, user, social]"},
    { .verb = "usr-register", .callback = userRegister,  .info = "register federated user profile into local fedid store"},
    { .verb = "usr-idps-link",.callback = userGetIdps,   .info = "return pseudo/email idps list before linking user multiple IDPs"},
    { .verb = "chk-attribute",.callback = userCheckAttr, .info = "check user attribute within local store"},
    { NULL} // terminator
};

int idsvcDeclare (oidcCoreHdlT *oidc, afb_apiset *declare_set, afb_apiset *call_set) {
    int err;

    oidcApisT apiSvc={
        .uid = oidc->api,
        .info= "internal oidc idp api",
        .uri = "@oidc",
        .loa = 0,
    };

    // register fedid type
    err= fedUserObjTypesRegister();
    if (err) goto OnErrorExit;

    // register verbs
    err= apisCreateSvc (oidc, &apiSvc, declare_set, call_set, idsvcVerbs);
    if (err) goto OnErrorExit;

    return 0;

OnErrorExit:
    return 1;
}