/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 */
#pragma once

#include "pcsc-glue.h"

#include <sys/types.h>
#include <wrap-json.h>
#include <uthash.h>

#define PCSC_MAX_DEV 16 // default max connected readers
#define PCSC_CONFIG_MAGIC 789654123

typedef enum {
    PCSC_ACTION_UNKNOWN=0,
    PCSC_ACTION_READ,
    PCSC_ACTION_WRITE,
    PCSC_ACTION_TRAILER,
    PCSC_ACTION_UUID,
} pcscActionE;

typedef struct {
    const char *uid;
    const u_int8_t sec; // sector number (0 for mifare)
    const u_int8_t blk; // block number for NFC tag-2
    u_int8_t *data;
    ulong dlen;
    const pcscKeyT *key;
    pcscActionE action;
    pcscTrailerT *trailer;
    int group;
    UT_hash_handle hh;
} pcscCmdT;

typedef struct {
    const char *uid;
    ulong magic;
    const char *reader;
    ulong timeout;
    int maxdev;
    int verbose;
    const char *info;
    pcscCmdT *cmds;
    pcscKeyT *keys;
    pcscCmdT *hTable;
} pcscConfigT;

pcscConfigT *pcscParseConfig (json_object *configJ, const int verbosity);
pcscCmdT *pcscCmdByUid (pcscConfigT *config, const char *cmdUid);
int pcscExecOneCmd(pcscHandleT *handle, const pcscCmdT *cmd, u_int8_t *data);