/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 * sample config file
    {
        "info" : "free config comment",
        "reader": "reader name",
        "keys": [
            {"uid":"abc, "idx": 0, "value":"asci value" }
            {"uid":"cde, "idx": 1, "value":["0x01","0x02","0x03","0x04","0x05","0x06"] }
            ...
        ],
        "cmds": [
            {"uid":"aaa", "action":"read", "blk": xx, "len": 32},
            {"uid":"bbb", "action":"read", "blk": xx, "len": 16, "key":"keyuuid"},
            {"uid":"yyy", "action":"write", "blk": xx, "data": "my_asci_data"},
            {"uid":"zzz", "action":"write", "blk": xx, "data": ["0xab", "0x01", ....]},
            {"uid":"zzz", "action":"write", "blk": xx, "data": ["0xab", "0x01", ....]},
        ]
    }
*/

#define _GNU_SOURCE

#include "pcsc-config.h"
#include <libafb/sys/verbose.h>

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wrap-json.h>

typedef struct {
    const char *label;
    const int  value;
} pcscKeyEnumT;

static const pcscKeyEnumT pcscActionsE[] = {
    {"read"  , PCSC_ACTION_READ},
    {"write" , PCSC_ACTION_WRITE},
    {"admin" , PCSC_ACTION_ADMIN},
    {NULL} // terminator
};

// search for key label within key/value array
static int pcscLabel2Value (const pcscKeyEnumT *keyvals, const char *label) {
    int value=0;
    if (!label) goto OnDefaultExit;

    for (int idx=0; keyvals[idx].label; idx++) {
        if (!strcasecmp (label,keyvals[ idx].label)) {
            value= keyvals[idx].value;
            break;
        }
    }
    return value;

OnDefaultExit:
    return keyvals[0].value;
}

// parse keys or command value as asci string or hexa array
static int pcscParseOneValue (json_object *valueJ, u_int8_t **value, unsigned long *len) {

    switch (json_object_get_type (valueJ)) {
        const char *byteS, *valueS;
        u_int8_t *valueB;
        int err, byte;
        size_t count;

        case json_type_string:
            valueS= json_object_get_string (valueJ);
            *len= strlen(valueS);
            *value=(u_int8_t*) strdup(valueS);
            break;

        case json_type_array:
            count = json_object_array_length(valueJ);
            valueB= calloc (count+1, sizeof(u_int8_t));

            for (int idx=0; idx < count; idx++) {
                byteS= json_object_get_string (json_object_array_get_idx(valueJ, idx));
                err= sscanf (byteS, "0x%2x", &byte);
                if (err <0) goto OnErrorExit;
                if (byte > 255) goto OnErrorExit;
                valueB[idx]= (u_int8_t)byte;
            }

            *len= count;
            *value= valueB;
            break;

        default:
            goto OnErrorExit;

    }
    return 0;

OnErrorExit:
    EXT_CRITICAL ("[pcsc-onevalue-fail] key/cmd value should be asci/string or array of hexa/string (pcscParseOneValue)");
    return -1;
}

static int pcscParseOneKey (pcscConfigT *config, json_object *keyJ, pcscKeyT *key)
{
    int err;
    json_object *valueJ=NULL;

    // {"uid":"abc, "idx": 0, "value":"asci value" }
    err= wrap_json_unpack (keyJ, "{ss,s?i,so !}"
        ,"uid", &key->uid
        ,"idx", &key->kidx
        ,"value", &valueJ
    );
    if (err) {
        EXT_CRITICAL ("[pcsc-onekey-fail] json supported keys:[uid,idx,value] (pcscParseOneKey)");
        goto OnErrorExit;
    }

    // value should be an asci string or an array of hexa valueB
    unsigned long klen;
    err= pcscParseOneValue (valueJ, &key->kval, &klen);
    if (err) goto OnErrorExit;
    key->klen= (uint8_t)klen;

    return 0;

OnErrorExit:
    return -1;
}

// search a key from its uid
pcscKeyT *pcscKeyByUid (pcscConfigT *config, const char *keyUid) {
    pcscKeyT *key=NULL;

    if (config->keys) {
        for (int idx=0; config->keys[idx].uid; idx++) {
            if (!strcasecmp ( config->keys[idx].uid, keyUid)) {
                key= &config->keys[idx];
                break;
            }
        }
    }
    return key;
}

static int pcscParseOneCmd (pcscConfigT *config, json_object *cmdJ, pcscCmdT *cmd)
{
    int err;
    json_object *dataJ=NULL;
    const char *keyUid=NULL, *cmdAction;

    // {"uid":"zzz", "action":"write", "blk": xx, "key":"kuid","data": ["0xab", "0x01", ....]},
    err= wrap_json_unpack (cmdJ, "{ss,ss,s?i,s?i,s?i,s?s,s?o !}"
        ,"uid", &cmd->uid
        ,"action", &cmdAction
        ,"sec", &cmd->sec
        ,"blk", &cmd->blk
        ,"len", &cmd->dlen
        ,"key", &keyUid
        ,"data", &dataJ
    );
    if (err) {
        EXT_CRITICAL ("[pcsc-onecmd-fail] json supported keys:[uid,action,blk,key,data,len] (pcscParseOneCmd)");
        goto OnErrorExit;
    }

    // check action
    cmd->action = pcscLabel2Value (pcscActionsE, cmdAction);
    switch (cmd->action) {
        case PCSC_ACTION_READ:
            if (!cmd->dlen || dataJ) {
                EXT_CRITICAL ("[pcsc-onecmd-fail] uid=%s action=%s len:mandatory data:forbiden (pcscParseOneCmd)", cmd->uid,cmdAction);
                goto OnErrorExit;
            }
            cmd->dlen += PCSC_MIFARE_STATUS_LEN; // reserve 2 byte for Mifare read status
            break;

        case PCSC_ACTION_WRITE:
            if (!dataJ || cmd->dlen) {
                EXT_CRITICAL ("[pcsc-onecmd-fail] uid=%s action=%s len:forbiden data:mandatory (pcscParseOneCmd)", cmd->uid,cmdAction);
                goto OnErrorExit;
            }
            err= pcscParseOneValue (dataJ, &cmd->data, &cmd->dlen);
            if (err) goto OnErrorExit;
            break;

        case PCSC_ACTION_ADMIN:
            if (dataJ) {
                err= pcscParseOneValue (dataJ, &cmd->data, &cmd->dlen);
                if (err) goto OnErrorExit;
            }
            break;

        default:
            EXT_CRITICAL ("[pcsc-onecmd-fail] uid=%s action=%s unknown (pcscParseOneCmd)", cmd->uid,cmdAction);
            goto OnErrorExit;
    }

    // if key is defined search for it
    if (keyUid) {
        cmd->key= pcscKeyByUid (config, keyUid);
        if (!cmd->key) {
            EXT_CRITICAL ("[pcsc-onecmd-fail] cmd=%s keys=%s non found within defined keys] (pcscParseOneCmd)", cmd->uid, keyUid);
            goto OnErrorExit;
        }
    }

    return 0;

OnErrorExit:
    return -1;
}

pcscConfigT *pcscParseConfig (json_object *configJ, const int verbosity)
{
    int err;
    pcscConfigT *config = calloc (1, sizeof(pcscConfigT));
    json_object *cmdsJ=NULL, *keysJ=NULL;
    config->verbose= verbosity;
    config->maxdev= PCSC_MAX_DEV;

    err= wrap_json_unpack (configJ, "{s?s ss s?i s?i s?i s?o s?o !}"
        , "info", &config->info
        , "reader", &config->reader
        , "maxdev", &config->maxdev
        , "debug", &config->verbose
        , "timeout", &config->timeout
        , "cmds", &cmdsJ
        , "keys", &keysJ
    );
    if (err) {
        EXT_CRITICAL ("[pcsc-config-fail] config json supported keys:[into,reader,cmds,keys] (pcscParseConfig)");
        goto OnErrorExit;
    }

    if (keysJ && !cmdsJ) {
        EXT_CRITICAL ("[pcsc-config-fail] key 'cmds' mandatory when 'keys' present (pcscParseConfig)");
        goto OnErrorExit;
    }


    // parse keys and create a hash table
    switch (json_object_get_type (keysJ)) {
        size_t kcount;

        case json_type_object:
            config->keys= calloc (2, sizeof(pcscKeyT));
            err= pcscParseOneKey (config, keysJ, &config->keys[0]);
            if (err) goto OnErrorExit;
            break;

        case json_type_array:
            kcount= json_object_array_length (keysJ);
            config->keys= calloc (kcount+1, sizeof(pcscKeyT));
            for (int idx=0; idx < kcount; idx++) {
                json_object *keyJ= json_object_array_get_idx (keysJ, idx);
                err= pcscParseOneKey (config, keyJ, &config->keys[idx]);
                if (err) goto OnErrorExit;
            }
            break;

        case json_type_null:
            // use default keys
            break;

        default:
            EXT_CRITICAL ("[pcsc-config-fail] keys should be  (pcscParseConfig)");
            goto OnErrorExit;
    }

    // parse commands
    switch (json_object_get_type (cmdsJ)) {
        size_t ccount;

        case json_type_object:
            config->cmds= calloc (2, sizeof(pcscCmdT));
            err= pcscParseOneCmd (config, cmdsJ, &config->cmds[0]);
            if (err) goto OnErrorExit;
            break;

        case json_type_array:
            ccount= json_object_array_length (cmdsJ);
            config->cmds= calloc (ccount+1, sizeof(pcscCmdT));
            for (int idx=0; idx < ccount; idx++) {
                json_object *cmdJ= json_object_array_get_idx (cmdsJ, idx);
                err= pcscParseOneCmd (config, cmdJ, &config->cmds[idx]);
                if (err) goto OnErrorExit;
            }
            break;

        case json_type_null:
            // use default cmds
            break;

        default:
            EXT_CRITICAL ("[pcsc-config-fail] cmds should be json object or array of object (pcscParseConfig)");
            goto OnErrorExit;
    }
    return  config;

OnErrorExit:
    return NULL;
}