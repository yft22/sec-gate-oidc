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

#include <libafb/afb-v4.h>
#include <libafb/apis/afb-api-ws.h>

#include "oidc-defaults.h"
#include "oidc-core.h"
#include "oidc-alias.h"
#include "oidc-apis.h"
#include "oidc-idp.h"
#include "http-client.h"
#include "oidc-idsvc.h"

#include <stdlib.h>
#include <stdio.h>
#include <argp.h>
#include <json-c/json.h>
#include <wrap-json.h>

AFB_EXTENSION (oidc-sgate)
    const struct argp_option AfbExtensionOptionsV1[] = {
        {.name = "logo",.key = 'L',.arg = 0,.doc = "requires a logo"},
        {.name = 0,.key = 0,.doc = 0}
    };

static oidGlobalsT * globalConfig (json_object * globalJ)
{
    int err;
    json_object *commentJ;
    oidGlobalsT *global = (oidGlobalsT *) calloc (1, sizeof (oidGlobalsT));

    if (globalJ) {
        err =
            wrap_json_unpack (globalJ, "{s?o s?s s?s s?s s?s s?s s?i s?i}"
            , "info", &commentJ, "login", &global->loginUrl
            , "error", &global->errorUrl
            , "register", &global->registerUrl
            , "federate", &global->fedlinkUrl
            , "home", &global->homeUrl
            , "cache", &global->tCache
            , "timeout", &global->sTimeout);
        if (err < 0) goto OnErrorExit;
    }

    if (!global->loginUrl) global->loginUrl = URL_OIDC_USR_LOGIN;
    if (!global->registerUrl) global->registerUrl = URL_OIDC_USR_REGISTER;
    if (!global->fedlinkUrl) global->fedlinkUrl = URL_OIDC_USR_FEDLINK;
    if (!global->homeUrl) global->homeUrl = URL_OIDC_USR_HOME;
    if (!global->errorUrl) global->errorUrl = URL_OIDC_USR_ERROR;
    if (!global->tCache) global->tCache = URL_OIDC_AUTH_CACHE;
    if (!global->sTimeout) global->sTimeout = EXT_SESSION_TIMEOUT;

    return (global);

  OnErrorExit:
    free (global);
    return NULL;
}

// Pase and load config.json info oidc global context
int AfbExtensionConfigV1 (void **ctx, struct json_object *oidcJ, char const *uid)
{
    oidcCoreHdlT *oidc = calloc (1, sizeof (oidcCoreHdlT));
    oidc->magic = MAGIC_OIDC_MAIN;
    oidc->uid = AfbExtensionManifest.name;
    json_object_get (oidcJ);
    int err;

    // init idp plugin global registry
    err = idpPLuginRegistryInit ();
    if (err) goto OnErrorExit;

    json_object *idpsJ = NULL, *aliasJ = NULL, *apisJ = NULL, *globalJ = NULL;
    err =
        wrap_json_unpack (oidcJ, "{s?s,s?s,s?o,s?o,s?o,s?o,s?o,s?i}"
            , "api", &oidc->api
            , "info", &oidc->info
            , "globals", &globalJ
            , "idp", &idpsJ
            , "idps", &idpsJ
            , "alias", &aliasJ
            , "apis", &apisJ
            , "verbose", &oidc->verbose
        );
    if (err) {
        EXT_CRITICAL ("[oidc-parsing-error] ext=%s requires: idp(s),alias,apis (AfbExtensionConfigV1)", oidc->uid);
        goto OnErrorExit;
    }

    if (!oidc->api) oidc->api = oidc->uid;
    oidc->globals = globalConfig (globalJ);
    oidc->idps = (oidcIdpT *) idpParseConfig (oidc, idpsJ);
    oidc->aliases = (oidcAliasT *) aliasParseConfig (oidc, aliasJ);
    oidc->apis = (oidcApisT *) apisParseConfig (oidc, apisJ);
    if (!oidc->idps || !oidc->aliases || !oidc->apis || !oidc->globals) goto OnErrorExit;

    *ctx = oidc;
    return 0;

  OnErrorExit:
    *ctx = NULL;
    return -1;
}

// import APIs with corresponding callback
int AfbExtensionDeclareV1 (void *ctx, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *) ctx;
    int err;
    if (!oidc) goto OnErrorExit;
    EXT_NOTICE ("Extension %s got to declare", oidc->uid);

    if (oidc->fedapi) {
        err = afb_api_ws_add_client (oidc->fedapi, declare_set, call_set, 1);
        EXT_ERROR ("[oidc-fedapi-not-found] ext=%s fail to connect to fedidp=%s  (AfbExtensionDeclareV1)", oidc->uid, oidc->fedapi);
        if (err) goto OnErrorExit;
    }
    // declare internal identity service api
    err = idsvcDeclare (oidc, declare_set, call_set);
    if (err) goto OnErrorExit;

    for (int idx = 0; oidc->idps[idx].uid; idx++) {
        err = idpRegisterOne (oidc, &oidc->idps[idx], declare_set, call_set);
        if (err) goto OnErrorExit;
    }

    for (int idx = 0; oidc->apis[idx].uid; idx++) {
        err = apisRegisterOne (oidc, &oidc->apis[idx], declare_set, call_set);
        if (err) goto OnErrorExit;
    }

    return 0;

  OnErrorExit:
    EXT_CRITICAL ("[oidc-declare-ext-fail] ext=%s fail to declare oidc API (AfbExtensionDeclareV1)", oidc->uid);
    return -1;
}

int AfbExtensionHTTPV1 (void *ctx, afb_hsrv * hsrv)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *) ctx;
    int err;
    if (!oidc) goto OnErrorExit;
    EXT_NOTICE ("Extension %s got to http", oidc->uid);

    // create libcurl http multi pool
    //oidc->httpPool= httpCreatePool(hsrv->efd, glueGetCbs(), oidc->verbose);
    oidc->httpPool = httpCreatePool (NULL, glueGetCbs (), oidc->verbose);
    if (!oidc->httpPool) goto OnErrorExit;

    for (int idx = 0; oidc->idps[idx].uid; idx++) {
        err = idpRegisterLogin (oidc, &oidc->idps[idx], hsrv);
        if (err) goto OnErrorExit;
    }

    for (int idx = 0; oidc->aliases[idx].uid; idx++) {
        err = aliasRegisterOne (oidc, &oidc->aliases[idx], hsrv);
        if (err) goto OnErrorExit;
    }

    return 0;

  OnErrorExit:
    return -1;
}

int AfbExtensionServeV1 (void *ctx, afb_apiset * call_set)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *) ctx;
    if (!oidc) goto OnErrorExit;
    EXT_NOTICE ("Extension %s got to serve", oidc->uid);

    return 0;

  OnErrorExit:
    return -1;
}

int AfbExtensionExitV1 (void *ctx, afb_apiset * declare_set)
{
    oidcCoreHdlT *oidc = (oidcCoreHdlT *) ctx;

    if (!oidc) goto OnErrorExit;
    EXT_NOTICE ("Extension %s exit", oidc->uid);
    return 0;

  OnErrorExit:
    return -1;
}
