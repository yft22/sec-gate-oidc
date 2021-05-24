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

#define PCSC_HANDLE_MAGIC 852963147
#define PCSC_DFLT_TIMEOUT 60 // default reader change status in seconds
#define PCSC_READER_DEV_MAX 8
#define PCSC_MIFARE_STATUS_LEN 2 // number of byte added to read buffer for Mifare status
#define PCSC_MIFARE_KEY_LEN 6 // keyA/B len (byte)
#define PCSC_MIFARE_ACL_LEN 3+1 // Access Control Bits len (3 bytes + 1 byte userdata)


// redefine debug/log to avoid conflict
#ifndef EXT_EMERGENCY
#define EXT_EMERGENCY(...)            _VERBOSE_(Log_Level_Emergency, __VA_ARGS__)
#define EXT_ALERT(...)                _VERBOSE_(Log_Level_Alert, __VA_ARGS__)
#define EXT_CRITICAL(...)             _VERBOSE_(Log_Level_Critical, __VA_ARGS__)
#define EXT_ERROR(...)                _VERBOSE_(Log_Level_Error, __VA_ARGS__)
#define EXT_WARNING(...)              _VERBOSE_(Log_Level_Warning, __VA_ARGS__)
#define EXT_NOTICE(...)               _VERBOSE_(Log_Level_Notice, __VA_ARGS__)
#define EXT_INFO(...)                 _VERBOSE_(Log_Level_Info, __VA_ARGS__)
#define EXT_DEBUG(...)                _VERBOSE_(Log_Level_Debug, __VA_ARGS__)
#endif

typedef enum {
    PCSC_OPT_UNKNOWN=0,
    PCSC_OPT_TIMEOUT,
    PCSC_OPT_VERBOSE,
} pcscOptsE;

typedef enum {
    ATR_UNKNOWN=0,
    ATR_MIFARE_1K,
    ATR_MIFARE_4K,
    ATR_MIFARE_UL,
    ATR_MIFARE_MINI,
    ATR_FELICA_212K,
    ATR_FELICA_424K,
} atrCardidEnumT;

typedef struct {
    const char *uid;
    u_int8_t *kval;
    u_int8_t klen;
    u_int8_t kidx;
} pcscKeyT;

typedef struct {
    u_int8_t *acls;
    u_int8_t alen;
    pcscKeyT *keyA;
    pcscKeyT *keyB;
} pcscTrailerT;

typedef struct pcscHandleS pcscHandleT; // opaque handle for client apps
typedef int (*pcscStatusCbT) (pcscHandleT *handle, unsigned long state);

pcscHandleT *pcscConnect (const char *readerName);
int pcscSetOpt (pcscHandleT *handle, pcscOptsE opt, unsigned long value);
const char* pcscReaderName (pcscHandleT *handle);
const char* pcscErrorMsg (pcscHandleT *handle);
int pcscDisconnect (pcscHandleT *handle);

int pcscReaderCheck (pcscHandleT *handle, int ticks);
pthread_t pcscReaderMonitor (pcscHandleT *handle, pcscStatusCbT callback, void *ctx);

int pcsWriteTrailer (pcscHandleT *handle, const char *uid, u_int8_t secIdx, u_int8_t blkIdx, const pcscKeyT *key, const pcscTrailerT *trailer);
int pcsWriteBlock (pcscHandleT *handle, const char *uid, u_int8_t secIdx, u_int8_t blkIdx, u_int8_t *dataBuf, unsigned long dataLen, const pcscKeyT *key);
int pcscReadBlock (pcscHandleT *handle, const char *uid, u_int8_t secIdx, u_int8_t blkIdx, u_int8_t *data, unsigned long *dlen, const pcscKeyT *key);
u_int64_t pcscGetCardUuid (pcscHandleT *handle);
void* pcscGetCtx (pcscHandleT *handle);
