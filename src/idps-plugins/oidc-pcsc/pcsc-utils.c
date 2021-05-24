/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 * general utilities to read/write smart card with pcsc-lite
 *  ATR http://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09_sup.pdf
 *  CMD https://docs.springcard.com/books/SpringCore/PCSC_Operation/APDU_Interpreter/Standard_instructions/UPDATE_BINARY
 *  MiFare https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf (for trailer #8.6.3 & #8.7.2)
 *  Default keyA='FFFF-FFFF-FFFF' Access-bits='FF0780'
 */
#define _GNU_SOURCE

#include "pcsc-utils.h"

#include <libafb/sys/verbose.h>

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include <winscard.h>
#include <pcsclite.h>


typedef union {
    u_int16_t  id;
    BYTE data[2];
} atrIsoCardid;

typedef struct {
  atrCardidEnumT uid;
  atrIsoCardid  cardid;
} isoAtrCardIdMapT;

static BYTE defaultKey[]= {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static BYTE pcPsRid[]= {0xA0,0x00,0x00,0x03,0x06};

static isoAtrCardIdMapT isoArtCardIds[] = {
    {.uid=ATR_MIFARE_1K,   .cardid={.data= {0x00, 0x01}}},
    {.uid=ATR_MIFARE_4K,   .cardid={.data= {0x00, 0x02}}},
    {.uid=ATR_MIFARE_UL,   .cardid={.data= {0x00, 0x03}}},
    {.uid=ATR_MIFARE_MINI, .cardid={.data= {0x00, 0x26}}},
    {.uid=ATR_FELICA_212K, .cardid={.data= {0xF0, 0x11}}},
    {.uid=ATR_FELICA_424K, .cardid={.data= {0xF0, 0x12}}},

    {.uid= ATR_UNKNOWN} // trailer
};

typedef union {
    BYTE data[20];
    struct  {
        BYTE Header;
        BYTE T0;
        BYTE TD1;
        BYTE TD2;
        BYTE T1;
        BYTE Tk;
        BYTE length;
        BYTE rid[5];
        BYTE Standard;
        BYTE cardid[2];
        BYTE rfu[4];
        BYTE checkSum;
    } value;
} isoAtrDataP3T;


typedef struct pcscHandleS {
  unsigned long magic;
  const char *readerName;
  int readerId;
  atrCardidEnumT cardId;
  u_int64_t uuid;
  BYTE keyA[6];
  BYTE keyB[6];
  SCARDCONTEXT hContext;
  SCARDHANDLE hCard;
  const SCARD_IO_REQUEST *pioSendPci;
  DWORD  activeProtocol;
  pthread_t threadId;
  unsigned long timeout;
  unsigned long verbose;
  const char *error;
  pcscStatusCbT callback;
  void *ctx;
} pcscHandleT;

static long pcscSendCmd (pcscHandleT *handle, const char *cmdUid, const char *action, const u_int8_t *cmdBuf, long cmdLen, u_int8_t *dataBuf, long unsigned *dataLen)
{
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    long unsigned bufferLen= *dataLen;
    long rv;

    if (handle->verbose) {
	    printf("\n -- action=%s\n -- len=%lu sending:[", action, cmdLen);
	    for (int i=0; i<cmdLen; i++) printf("0x%02X,", cmdBuf[i]);
	    printf("]\n");
    }

	rv = SCardTransmit(handle->hCard, handle->pioSendPci, cmdBuf, cmdLen, NULL, dataBuf, dataLen);
    if (rv !=  SCARD_S_SUCCESS) {
        handle->error= pcsc_stringify_error(rv);
        goto OnErrorExit;
    }

    if (handle->verbose) {
    	printf(" -- len=%lu/%lu received: [", *dataLen, bufferLen);
	    for (int idx=0; idx< *dataLen; idx++) printf("0x%02X,", dataBuf[idx]);
	    printf("]\n");
    }

    // checked smartcard is happy response and by 0x90,x00
    if (dataBuf[*dataLen-2] != 0x90 || dataBuf[*dataLen-1] != 0x00) {
        handle->error= "Smartcard CMD refused (auth?)";
        rv= SCARD_STATE_INUSE;
        goto OnErrorExit;
    }

    // close buffer in case it would be used as ascii and remove Mifare status from readlen
    dataBuf[*dataLen-PCSC_MIFARE_STATUS_LEN]='\0';

    return rv;

OnErrorExit:
    EXT_DEBUG ("[pcsc-transmit-error] uid=%s action=%s error=%s (pcscSendCmd)\n", cmdUid, action, handle->error);
    return rv;
}

// search cardId within supported ATR
static atrCardidEnumT isoAtrParseCard (pcscHandleT *handle, BYTE *buffer, DWORD len) {
    isoAtrDataP3T *atr;
    atrCardidEnumT atrUid=ATR_UNKNOWN;
    atrIsoCardid   cardid;

    switch (len) {

        case sizeof(isoAtrDataP3T):
            // mirefare1K= .data={0x3B,0x8F,0x80,0x01,0x80,0x4F,0x0C,0xA0,0x00,0x00,0x03,0x06,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x6A}
            atr= (isoAtrDataP3T*)buffer;

            // check we are facing a MyFare RID
            if (memcmp (atr->value.rid, pcPsRid, sizeof(pcPsRid))) goto OnErrorExit;

            // move cardid as int16 in case value is not aligned
            memcpy (cardid.data, atr->value.cardid, sizeof(cardid));

            // search for cardid within supported list
            for (int idx=0; isoArtCardIds[idx].uid != ATR_UNKNOWN; idx++) {
                if (isoArtCardIds[idx].cardid.id == cardid.id) {
                    atrUid= isoArtCardIds[idx].uid;
                    break;
                }
            }
            break;

        default:
            goto OnErrorExit;
    }

    return atrUid;

OnErrorExit:
    handle->error= "pcsc unsupported ATR smartcard model";
    return ATR_UNKNOWN;
}

// get card UUID (block 0 read only execpt on Chineese smartcard)
u_int64_t pcscCheckCardUuid (pcscHandleT *handle) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    UCHAR receiveBuffer[32];
    DWORD receiveLength = sizeof(receiveBuffer);
    BYTE cmdData[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
    u_int64_t uuid=0;
    long rv;

    rv= pcscSendCmd (handle, "scard-uuid", "get", cmdData, sizeof(cmdData), receiveBuffer, &receiveLength);
    if (rv != SCARD_S_SUCCESS) goto OnErrorExit;
    for (int idx= 0; idx != receiveLength-2; idx++) {
        uuid <<= 8;
        uuid |= (u_int64_t)receiveBuffer[idx];
    }
    return uuid;

OnErrorExit:
    return 0;
}


// try to read data bloc
int pcscReadBlock (pcscHandleT *handle, const char *uid,  u_int8_t secIdx, u_int8_t blkIdx, u_int8_t *data, unsigned long *dlen, const pcscKeyT *key)
{
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    long rv=0;
    u_int8_t *keyVal;
    u_int8_t keyIdx;
    BYTE status[32];
    unsigned long lenToRead = *dlen-PCSC_MIFARE_STATUS_LEN;

    if (handle->verbose) fprintf (stderr, "\n# pcscReadBlock reader=%s cmd=%s scard=%ld blk=%d dlen=%ld\n", handle->readerName, uid, handle->uuid, blkIdx, *dlen);
    switch (handle->cardId) {

        case ATR_MIFARE_1K:
        case ATR_MIFARE_4K:

            // assert request is possible
            if (lenToRead > 64L ||  lenToRead % 16L) {
                handle->error= "Invalid ATR_MIFARE_CLASSIC dlen should be mod/16";
                goto OnErrorExit;
            }

            if (!key) {
                keyVal= defaultKey;
                keyIdx =0; // keyA
            }
            else {
                if (key->klen != 6) {
                    handle->error= "Invalid MIFARE_CLASSIC keyken should 6";
                    goto OnErrorExit;
                }
                keyVal= key->kval;
                keyIdx= key->kidx;
            }

            // load key
            if (!keyVal) keyVal= defaultKey;
            const u_int8_t keyCmd[] = {0xFF, 0x82, 0x00, 0x00, 0x06, keyVal[0], keyVal[1], keyVal[2], keyVal[3], keyVal[4], keyVal[5]};
            unsigned long keyStatusLen= sizeof(status);
            rv= pcscSendCmd (handle, uid, "loadkey", keyCmd, sizeof(keyCmd), status, &keyStatusLen);
	        if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

            // send authentication block
            const u_int8_t authCmd[] = {0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, secIdx, blkIdx, 0x60|keyIdx, 0x00};
            unsigned long authStatusLen= sizeof(status);
            rv= pcscSendCmd (handle, uid, "authent", authCmd, sizeof(authCmd), status, &authStatusLen);
	        if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

            break;

        case ATR_MIFARE_UL:
            // no authentication
            if ((blkIdx*4 + lenToRead) > 38*4L || (lenToRead % 4L)) {
                handle->error= "Invalid ATR_MIFARE_UL dlen should be mod/4";
                goto OnErrorExit;
            }

            break;

        default:
            handle->error= "Unsupported smart card model";
            goto OnErrorExit;
    }

    // try to read bloc
 	u_int8_t readBlk[] = { 0xFF, 0xB0, secIdx, blkIdx, 0x10};
    rv= pcscSendCmd (handle, uid, "read", readBlk, sizeof(readBlk), data, dlen);
	if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_ERROR ("[pcsc-readblk-fail] cmd=%s action:read err=%s", uid, handle->error);
    return -1;
}

// try to read data bloc
int pcsWriteBlock (pcscHandleT *handle, const char *uid,  u_int8_t secIdx, u_int8_t blkIdx, u_int8_t *dataBuf, unsigned long dataLen, const pcscKeyT *key)
{
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    long rv=0;
    u_int8_t *keyVal;
    u_int8_t keyIdx;
    BYTE status[32];

    if (handle->verbose) fprintf (stderr, "\n# pcsWriteBlock reader=%s cmd=%s scard=%ld blk=%d dlen=%ld\n", handle->readerName, uid, handle->uuid, blkIdx, dataLen);
    switch (handle->cardId) {

        case ATR_MIFARE_1K:
        case ATR_MIFARE_4K:

            // assert request is possible
            if (dataLen > 0x40 || dataLen % 16L) {
                handle->error= "Invalid MIFARE_CLASSIC dlen should be mod/16";
                goto OnErrorExit;
            }

            if (!key) {
                keyVal= defaultKey;
                keyIdx =0; // keyA
            }
            else {
                if (key->klen != 6) {
                    handle->error= "Invalid MIFARE_CLASSIC keyken should 6";
                    goto OnErrorExit;
                }
                keyVal= key->kval;
                keyIdx= key->kidx;
            }
            BYTE keyCmd[] = {0xFF, 0x82, 0x00, 0x00, 0x06, keyVal[0], keyVal[1], keyVal[2], keyVal[3], keyVal[4], keyVal[5]};
            unsigned long keyStatusLen= sizeof(status);
            rv= pcscSendCmd (handle, uid, "key", keyCmd, sizeof(keyCmd), status, &keyStatusLen);
            if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

            // send authentication block
            BYTE authCmd[] = {0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, secIdx, blkIdx, 0x60|keyIdx, 0x00};
            unsigned long authStatusLen= sizeof(status);
            rv= pcscSendCmd (handle, uid, "authent", authCmd, sizeof(authCmd), status, &authStatusLen);
            if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

            break;

        case ATR_MIFARE_UL:
            // no authentication
            if ((blkIdx*4 + dataLen) > 38*4L || (dataLen % 4L)) {
                handle->error= "Invalid MIFARE_UL (dlen should be mod/4)";
                goto OnErrorExit;
            }
            break;

        default:
            handle->error="Unsupported smartcard model";
            goto OnErrorExit;
    }

    // Add data to pcsc update command block
    {
        BYTE writeCmd[] = { 0xFF, 0xD6, secIdx, blkIdx, 0x10};
        BYTE bufferRqt[dataLen+sizeof(writeCmd)];
        memcpy (&bufferRqt[0], writeCmd, sizeof(writeCmd));
        memcpy (&bufferRqt[sizeof(writeCmd)], dataBuf, dataLen);
        unsigned long length= dataLen+sizeof(writeCmd);

        rv= pcscSendCmd (handle, uid, "write", bufferRqt, sizeof(bufferRqt), dataBuf, &length);
        if (rv != SCARD_S_SUCCESS) goto OnErrorExit;
    }

    return 0;

OnErrorExit:
    EXT_ERROR("[pcsc-writeblk-fail] cmd=%s action=write err=%s", uid, handle->error);
    return -1;
}

int pcscCardCheckAtr(pcscHandleT *handle)
{
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    char readerName[MAX_READERNAME]="";
    BYTE atrData[MAX_ATR_SIZE]="";
    DWORD readerLen= sizeof(readerName);
    DWORD atrLen= sizeof(atrData);
    DWORD readerState;
    long rv=-1;

    // make sure reader as a card
    if (!handle->hCard) {
        EXT_ERROR ("[pcsc-reader-status] should 1st use pcscReaderCheck to reader=%s presence", handle->readerName);
        goto OnErrorExit;
    }

    // use status to retreive smart cart ATR
    rv = SCardStatus(handle->hCard, readerName, &readerLen, &readerState, &handle->activeProtocol, atrData, &atrLen);
    if (rv != SCARD_S_SUCCESS) {
        handle->error= pcsc_stringify_error(rv);
        goto OnErrorExit;
    }

    handle->cardId = isoAtrParseCard (handle, atrData, atrLen);
    if (handle->cardId == ATR_UNKNOWN) goto OnErrorExit;

    return 0;

OnErrorExit:
    EXT_CRITICAL ("[pcsc-sccard-atr] Fail get smart card atr reader=%s. (pcscCardCheckAtr=%s)", handle->readerName, pcsc_stringify_error(rv));
    return -1;
}

// wait for reader status and wait for smart card
int pcscReaderCheck (pcscHandleT *handle, int ticks)
{
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    long rv;

	rv = SCardConnect(handle->hContext, handle->readerName, SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &handle->hCard, &handle->activeProtocol);

    if (rv ==  SCARD_E_NO_SMARTCARD) {
        SCARD_READERSTATE rgReaderStates;
        rgReaderStates.szReader = handle->readerName; // reader ID to test
        rgReaderStates.dwCurrentState = SCARD_STATE_UNAWARE;

        if (handle->verbose) fprintf(stderr, "Please Insert a smartcard in reader=%s\n", handle->readerName);
        for (int idx=0; idx < ticks; idx++) {
            // wait for card to be inserted
            // wait timeout second for card to be inserted
            rv = SCardGetStatusChange(handle->hContext, 10000, &rgReaderStates, 1);
            if (rv != SCARD_S_SUCCESS)  goto OnErrorExit;

            if (rgReaderStates.dwCurrentState != rgReaderStates.dwEventState) {
                rgReaderStates.dwCurrentState = rgReaderStates.dwEventState;

                // card is present
                if (rgReaderStates.dwEventState & SCARD_STATE_PRESENT) break;
                if (handle->verbose) fprintf (stderr, ".");
            }
        }
        if (handle->verbose) fprintf (stderr, "\n");
   	    rv = SCardConnect(handle->hContext, handle->readerName, SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &handle->hCard, &handle->activeProtocol);
    }

    if (rv != SCARD_S_SUCCESS)  goto OnErrorExit;

    // set up the io request
    switch(handle->activeProtocol)
    {
        case SCARD_PROTOCOL_T0:
            handle->pioSendPci = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            handle->pioSendPci = SCARD_PCI_T1;
            break;
        default:
            EXT_CRITICAL("[pcsc-sccard-check] SCARD_PCI Unknown protocol (SCardConnect)");
            goto OnErrorExit;
    }

    return 0;

OnErrorExit:
    handle->error= pcsc_stringify_error(rv);
    EXT_CRITICAL ("[pcsc-sccard-check] Fail get connect smart card reader=%s. (SCardConnect=%s)", handle->readerName, pcsc_stringify_error(rv));
    return -1;
}

// thread monitoring reader status change
static void *pcscThreadMonitor (void *ptr) {
    pcscHandleT *handle = (pcscHandleT*)ptr;
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    long rv;

    SCARD_READERSTATE rgReaderStates;
    rgReaderStates.szReader = handle->readerName; // reader ID to test
    rgReaderStates.dwCurrentState = SCARD_STATE_UNAWARE;

    // loop forever until reader is disconnected
    while (1) {
            // wait timeout second for card to be inserted
            rv = SCardGetStatusChange(handle->hContext, handle->timeout*1000, &rgReaderStates, 1);
            if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

            if (rgReaderStates.dwCurrentState != rgReaderStates.dwEventState) {
                rgReaderStates.dwCurrentState = rgReaderStates.dwEventState;

                // card was inserted retreive uuid/atr
                if (rgReaderStates.dwEventState & SCARD_STATE_PRESENT) {

                    rv = SCardConnect(handle->hContext, handle->readerName, SCARD_SHARE_SHARED,
                        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &handle->hCard, &handle->activeProtocol);
                    if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

                    // set up the io request
                    switch(handle->activeProtocol)
                    {
                        case SCARD_PROTOCOL_T0:
                            handle->pioSendPci = SCARD_PCI_T0;
                            break;
                        case SCARD_PROTOCOL_T1:
                            handle->pioSendPci = SCARD_PCI_T1;
                            break;
                        default:
                            EXT_CRITICAL("[pcsc-sccard-check] SCARD_PCI Unknown protocol (SCardConnect)");
                            goto OnErrorExit;
                    }
                }

            // card was removed cleanup UUID/ATR
            if (rgReaderStates.dwEventState & SCARD_STATE_EMPTY) {
                handle->uuid=0;
                handle->cardId=ATR_UNKNOWN;
            }

            if (handle->verbose) fprintf (stderr, "\n -- async: reader=%s status=0x%lx\n", handle->readerName, rgReaderStates.dwEventState);
            handle->callback (handle, rgReaderStates.dwEventState);
        }

    }
    return NULL;

OnErrorExit:
    handle->error= pcsc_stringify_error(rv);
    EXT_CRITICAL ("[pcsc-thread-monitor] Reader not avaliable thread exited err=%s", handle->error);
    return NULL;
}

// start a posix thread to monitor reader status
pthread_t pcscReaderMonitor (pcscHandleT *handle, pcscStatusCbT callback, void *ctx) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    handle->ctx= ctx;
    handle->callback=callback;
    int err;

    err= pthread_create (&handle->threadId, NULL, pcscThreadMonitor, (void*) handle);
    if (err) goto OnErrorExit;
    return handle->threadId;

OnErrorExit:
    handle->error= strerror(errno);
    EXT_CRITICAL ("[pcsc-sccard-monitor] Fail start monitoring thread reader=%s. (pcscReaderMonitor err=%s)", handle->readerName, strerror(errno)) ;
    return 0;
}

int pcscDisconnect (pcscHandleT *handle) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    long rv;
    int err;

    if (handle->threadId) {
        err= pthread_kill (handle->threadId, SIGSTOP);
        if (err) {
            EXT_NOTICE ("[pcsc-disconnect-thread] fail to stop monitoring thread");
        }
    }

  	rv = SCardReleaseContext(handle->hContext);
	if (rv != SCARD_S_SUCCESS) goto OnErrorExit;

    handle->magic=0;
    free (handle);
    return 0;

OnErrorExit:
    EXT_CRITICAL ("[pcsc-disconnect-fail] fail to free pcsc handle err=%s", pcsc_stringify_error(rv));
    return -1;
}

// search for reader and create corresponding pcsc-lite handle
pcscHandleT *pcscConnect (const char *readerName) {
    pcscHandleT *handle= calloc (1, sizeof(pcscHandleT));
    handle->timeout= PCSC_DFLT_TIMEOUT;
  	handle->activeProtocol= -1;
    long rv;

    // connect to pcscd as system user
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &handle->hContext);
	if (rv != SCARD_S_SUCCESS) {
        EXT_CRITICAL ("[pcsc-init-fail] to found pcscd ressource manager [check pcscd -d]. (SCardEstablisscardCtx=%s)", pcsc_stringify_error(rv));
        goto OnErrorExit;
    }

    // get reader list (hoops!!! a string with token split by '\0')
    DWORD readerLiStatusLen=SCARD_AUTOALLOCATE;
    LPSTR readerListStr= NULL;
  	rv = SCardListReaders(handle->hContext, NULL, (LPSTR)&readerListStr, &readerLiStatusLen);
  	if (rv != SCARD_S_SUCCESS) {
        EXT_CRITICAL ("[pcsc-reader-scan] Fail to list pcscd reader [check pcsc-ccid supported reader]. (SCardListReaders=%s)", pcsc_stringify_error(rv));
        goto OnErrorExit;
    }

    // extract reader name from tokenized string
    int readerCount=0;
    const char* readerList[PCSC_READER_DEV_MAX];
    for (char *ptr= readerListStr; *ptr != '\0'; ptr += strlen(ptr)+1) {
        if (readerCount == PCSC_READER_DEV_MAX) {
            EXT_CRITICAL ("[pcsc-reader-scan] too many readers increase 'maxdev=%d' (remaining ignored)", PCSC_READER_DEV_MAX);
            break;
        }
		readerList[readerCount++]= ptr;
	}

    // if readername == NULL take 1st one from the list else search within the list
    if (readerName) {
        handle->readerId=-1;
        for (int idx=0; idx < readerCount; idx++) {
            EXT_DEBUG ("reader[%d]=%s", idx, readerList[idx]);
            if (strcasestr (readerList[idx], readerName)) {
            handle->readerId= idx;
            handle->readerName= strdup(readerList[idx]);
            break;
            }
        }
        if (handle->readerId < 0 ) {
            EXT_CRITICAL ("[pcsc-reader-unknown] reader=%s", handle->readerName);
            if (handle->verbose) {
                EXT_NOTICE ("-- reader list count=%d", readerCount);
                for (int jdx=0; jdx < readerCount-1; jdx++) {
                    EXT_NOTICE (" -- reader[%d]=%s", jdx, readerList[jdx]);
                }
            }
            goto OnErrorExit;
        }
    } else {
        handle->readerId= 0;
        handle->readerName= strdup (readerList[0]);
    }
    handle->magic= PCSC_HANDLE_MAGIC;
    return (handle);

OnErrorExit:
    free (handle);
    return NULL;
}

// setter for reader options
int pcscSetOpt (pcscHandleT *handle, pcscOptsE option, unsigned long value) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);

    // if no value keep defaults
    if (value) {
        switch (option) {
        case PCSC_OPT_TIMEOUT:
            handle->timeout= value;
            break;
        case PCSC_OPT_VERBOSE:
            handle->verbose= value;
            break;

        default:
            goto OnErrorExit;
        }
    }
    return 0;

OnErrorExit:
    EXT_CRITICAL ("[pcsc-opt-unknown] Invalid option (pcscSetOpt)");
    return -1;
}

// check card UUID
u_int64_t pcscGetCardUuid (pcscHandleT *handle) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    int err;

    // if card atr not decoded to it now
    if (!handle->cardId) {
        err = pcscCardCheckAtr(handle);
        if (err) goto OnErrorExit;
    }

    // if uuid not store check it now
    if (!handle->uuid) handle->uuid= pcscCheckCardUuid (handle);
    return (handle->uuid);

OnErrorExit:
    return 0;
}

// Create access control bit trailer https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf
static size_t pcscMifareTrailer (pcscHandleT *handle, const pcscTrailerT *trailer, u_int8_t *dataBuf, size_t dataLen)
{
    static size_t dlen= 2*PCSC_MIFARE_KEY_LEN + PCSC_MIFARE_ACL_LEN;
    u_int8_t dfltAcls[]={0xFF,0x07,0x80,0x69};

    if (trailer->keyA->klen != PCSC_MIFARE_KEY_LEN || (trailer->keyB && trailer->keyB->klen != PCSC_MIFARE_KEY_LEN)) {
        handle->error= "Mifare Keylen should equal PCSC_MIFARE_KEY_LEN(len:6)";
        goto OnErrorExit;
    }

    if (dataLen < dlen) {
        handle->error= "Mifare Header data buffer too small (min:16)";
        goto OnErrorExit;
    }

    if (!trailer->keyA) {
        handle->error= "Mifare trailer keyA mandatory";
        goto OnErrorExit;
    }

    // default reset data to NULL and write KEYA
    memset (dataBuf,0, dlen);
    memcpy (&dataBuf[0], trailer->keyA->kval, PCSC_MIFARE_KEY_LEN);

    if (trailer->acls) memcpy (&dataBuf[PCSC_MIFARE_KEY_LEN], trailer->acls, PCSC_MIFARE_ACL_LEN);
    else memcpy (&dataBuf[PCSC_MIFARE_KEY_LEN], dfltAcls, PCSC_MIFARE_ACL_LEN);

    if (trailer->keyB) memcpy (&dataBuf[PCSC_MIFARE_KEY_LEN+PCSC_MIFARE_ACL_LEN], trailer->keyB->kval, PCSC_MIFARE_KEY_LEN);

    return dlen;

OnErrorExit:
    EXT_ERROR("[pcsc-trailer-fail] cmd=Mifare action=MkTrailer err=%s", handle->error);
    return 0;
}

// Write trailer access control key/bits
int pcsWriteTrailer (pcscHandleT *handle, const char *uid, u_int8_t secIdx, u_int8_t blkIdx, const pcscKeyT *key, const pcscTrailerT *trailer)
{
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    u_int8_t data[16];
    int err;

    if (handle->verbose) fprintf (stderr, "\n# pcsWriteTrailer reader=%s cmd=%s scard=%ld blk=%d\n", handle->readerName, uid, handle->uuid, blkIdx);
    switch (handle->cardId) {

        case ATR_MIFARE_1K:
        case ATR_MIFARE_4K:

            // WARNING !!! invalid keys/acls may bick your smart card check  http://calc.gmss.ru/Mifare1k/
            if (!trailer || !trailer->acls || !trailer->keyA || !trailer->keyB) {
                handle->error = "Fatal: Trailer with KEYS[A+B]/ACLS mandatory for access control header\n";
                goto OnErrorExit;
            }

            // check blockIdx is a trailer
            if (blkIdx % 4 != 3) {
                handle->error = "Fatal: Trailer Mifare invalid block (should be last sector one)\n";
                goto OnErrorExit;
            }

            size_t dlen= pcscMifareTrailer (handle, trailer, data, sizeof(data));
            if (dlen == 0) goto OnErrorExit;

            err= pcsWriteBlock (handle, uid, secIdx, blkIdx, data, dlen, key);
            if (err) goto OnErrorExit;
            break;

        default:
            handle->error = "Trailer access bits unsupported smart card model";
            goto OnErrorExit;
    }
    return 0;

OnErrorExit:
    return -1;
}

const char* pcscReaderName (pcscHandleT *handle) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    return (handle->readerName);
}

const char* pcscErrorMsg (pcscHandleT *handle) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    return (handle->error);
}

void* pcscGetCtx (pcscHandleT *handle) {
    assert (handle->magic == PCSC_HANDLE_MAGIC);
    return (handle->ctx);
}
