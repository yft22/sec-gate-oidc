/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 */
#pragma once

#include <sys/types.h>
#include <wrap-json.h>
#include "pcsc-utils.h"

#define PCSC_MAX_DEV 16 // default max connected readers

typedef enum {
    PCSC_ACTION_UNKNOWN=0,
    PCSC_ACTION_READ,
    PCSC_ACTION_WRITE,
    PCSC_ACTION_ADMIN,
} pcscActionE;

typedef struct {
    const char *uid;
    const u_int8_t sec; // sector number (0 for mifare)
    const u_int8_t blk; // block number for NFC tag-2
    u_int8_t *data;
    unsigned long dlen;
    const pcscKeyT *key;
    pcscActionE action;
} pcscCmdT;

typedef struct {
    const char *reader;
    int maxdev;
    int verbose;
    const char *info;
    pcscCmdT *cmds;
    pcscKeyT *keys;
    unsigned long timeout;
} pcscConfigT;

pcscConfigT *pcscParseConfig (json_object *configJ, const int verbosity);
pcscKeyT *pcscKeyByUid (pcscConfigT *config, const char *keyUid);