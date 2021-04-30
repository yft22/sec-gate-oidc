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

#include <sys/types.h>
#include <uuid/uuid.h>
#include <time.h>

#include "oidc-defaults.h"
#include "oidc-utils.h"

static char*GetEnviron(const char *label, void *dflt, void *userdata) {
    const char*key= dflt;
    const char*value;

    if (!label) return NULL;

    value= getenv(label);
    if (!value) {
        if (key) {
            value=key;
        } else {
            value="#undef";
        }
    }
    return (char*)value;
}

static char*GetUuidString(const char *label, void *dflt, void *userdata) {
    char *uuid = malloc(37);
    uuid_t binuuid;

    uuid_generate_random(binuuid);
    uuid_unparse_lower(binuuid, uuid);
    return uuid;
}

static char*GetDateString(const char *label, void *dflt, void *userdata) {
    #define MAX_DATE_LEN 80
    time_t now= time(NULL);
    char *date= malloc(MAX_DATE_LEN);
    struct tm *time= localtime(&now);

    strftime (date, MAX_DATE_LEN, "%d-%b-%Y %T (%Z)",time);
    return date;
}

// Warning: REDDEFLT_CB will get its return free
oidcDefaultsT oidcVarDefaults[]= {
    // static strings
    {"LOGNAME"        , GetEnviron, SPAWN_MEM_STATIC, (void*)"Unknown"},
    {"HOSTNAME"       , GetEnviron, SPAWN_MEM_STATIC, (void*)"localhost"},
    {"HOME"           , GetEnviron, SPAWN_MEM_STATIC, (void*)"/sgate"},

    {"TODAY"          , GetDateString, SPAWN_MEM_DYNAMIC, NULL},
    {"UUID"           , GetUuidString, SPAWN_MEM_DYNAMIC, NULL},

    {NULL, GetEnviron, SPAWN_MEM_STATIC, NULL} /* sentinel and default callback */
};
