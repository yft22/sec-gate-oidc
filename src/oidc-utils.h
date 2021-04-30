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


#pragma once

#include <json-c/json.h>

#ifndef OIDC_MAX_ARG_LEN
#define OIDC_MAX_ARG_LEN 1024
#endif

#ifndef OIDC_MAX_ARG_LABEL
#define OIDC_MAX_ARG_LABEL 64
#endif

typedef enum {
    OIDC_MEM_STATIC=0,
    OIDC_MEM_DYNAMIC,
} oidcMemDefaultsE;

typedef char*(*oidcGetDefaultCbT)(const char *label, void *ctx, void *userdata);
typedef struct {
    const char *label;
    oidcGetDefaultCbT callback;
    oidcMemDefaultsE  allocation;
    void *ctx;
} oidcDefaultsT;
extern oidcDefaultsT oidcVarDefaults[];

const char* utilsExpandString (oidcDefaultsT *defaults, const char* inputS, const char* prefix, const char* trailer, void *ctx);
const char *utilsExpandKeyCtx (const char* src, void *ctx);
const char* utilsExpandKey (const char* inputString);
const char* utilsExpandJson (const char* src, json_object *keysJ);
