/*
 * Copyright (C) 2021 "IoT.bzh"
 * Author "Fulup Ar Foll" <fulup@iot.bzh>
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.
 *
 * WARNING: pcsc plugin requires read access to /etc/shadow
 * Reference:
 *  http://pcscworkgroup.com/Download/Specifications/pcsc3_v2.01.09_sup.pdf
 */

#define _GNU_SOURCE

#include "pcsc-utils.h"
#include "pcsc-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#include <wrap-json.h>
#include <libafb/utils/json-locator.h>

static struct option options[] = {
	{"verbose", optional_argument, 0,  'v' },
	{"config", required_argument, 0,  'c' },
	{0, 0, 0, 0 } // trailer
};

typedef struct {
    const char*cnfpath;
    int verbose;
    int index;
} pcscParamsT;

pcscParamsT *parseArgs(int argc, char *argv[]) {
	pcscParamsT *params = calloc (1, sizeof(pcscParamsT));
 	int index;

	for (int done=0; !done;) {
		int option = getopt_long(argc, argv, "v::c:", options, &index);
		if (option == -1) {
			params->index= optind;
			break;
		}

		// option return short option even when long option is given
		switch (option) {
			case 'v':
				params->verbose++;
  				if (optarg)	params->verbose = atoi(optarg);
				break;

			case 'c':
				params->cnfpath=optarg;
				break;

			default:
				goto OnErrorExit;
		}
	}

    return params;

OnErrorExit:
	fprintf (stderr, "usage: pcsc-main --config=... [--verbose]\n");
	return NULL;
}

int main (int argc, char *argv[])
{
    int err;
    pcscParamsT *params= parseArgs (argc, argv);
    if (!params) goto OnErrorExit;

    json_object *configJ;
    err= json_locator_from_file (&configJ, params->cnfpath);
    //json_object *configJ= json_tokener_parse(buffer);
    if (!configJ) {
        fprintf (stderr, "Fail to parse params.json (try jq < %s\n", params->cnfpath);
        goto OnErrorExit;
    }

    // parse json config
    pcscConfigT *config= pcscParseConfig (configJ, params->verbose);
    if (!config) goto OnErrorExit;

    // create pcsc handle and set options
    pcscHandleT *handle =pcscConnect (config->reader);
    if (!handle) {
        fprintf (stderr, "Fail to connect to reader=%s\n", config->reader);
        goto OnErrorExit;
    }

    // set options
    pcscSetOpt (handle, PCSC_OPT_VERBOSE, config->verbose);
    pcscSetOpt (handle, PCSC_OPT_TIMEOUT, config->timeout);

    // get reader status and wait 10 timeout for card
    err= pcscReaderCheck (handle, 10);
    if (err) {
       fprintf (stderr, "Fail to detect scard on reader=%s error=%s\n", pcscReaderName(handle), pcscErrorMsg(handle));
       goto OnErrorExit;
    }

    // try to get card UUID (work with almost any model)
    u_int64_t uuid= pcscGetCardUuid (handle);
    if (!uuid) {
        fprintf (stderr, "Fail reading smart card UUID error=%s\n", pcscErrorMsg(handle));
        goto OnErrorExit;
    }
    fprintf (stderr, " -- Reader=%s smart uuid=%ld\n", config->reader, uuid);

    u_int8_t trailer[16];
    // http://calc.gmss.ru/Mifare1k/ (too complex to build by hand !!!)
    // ---
    // blk-0:   (C10 C20 C30)= 000 (|C10|C20|C30)= 111 (transport config)
    // blk-1:   (C11 C21 C31)= 000 (|C11|C21|C31)= 111
    // blk-2:   (C12 C22 C32)= 000 (|C12|C22|C32)= 111
    // trailer: (C13 C23 C33)= 001 (|C13|C23|C33)= 110 (transport config)
    // ---
    // Byte-6 |C23|C22|C21|C20 0xFF 1111-1111  |C13|C12|C11|C10
    // Byte-7  C13,C12,C11,C10 0x07 0000-0111  |C33|C32|C31|C30
    // Byte-8  C33,C32,C31,C30 0x80 1000-0000   C23,C22,C21,C20
    // ----

    // loop on commands
    for (int idx=0; config->cmds[idx].uid; idx++) {
        const pcscCmdT *cmd= &config->cmds[idx];
        unsigned long dlen= cmd->dlen;
        pcscKeyT *keyA, *keyB;
        u_int8_t data[dlen];

        switch (cmd->action) {

            case PCSC_ACTION_READ:
                err= pcscReadBlock (handle, cmd->uid, cmd->sec, cmd->blk, data, &dlen, cmd->key);
                if (err) goto OnErrorExit;
                if (!params->verbose) {
                    printf ("cmd=%s len=%ld", cmd->uid, dlen);
                    for (int idx=0; idx < dlen; idx++) printf("%02X ", data[idx]);
                    printf ("\n");
                }
                break;

            case PCSC_ACTION_WRITE:
                err= pcsWriteBlock (handle, cmd->uid, cmd->sec, cmd->blk, cmd->data, cmd->dlen, cmd->key);
                if (err) goto OnErrorExit;
                break;

            case PCSC_ACTION_ADMIN: {
                // read=keyA write=keyB online ACL calculator http://calc.gmss.ru/Mifare1k/
                u_int8_t acls[]= {0xF0,0xF7,0x80,0x56};
                keyA= pcscKeyByUid(config,"key-a");
                keyB= pcscKeyByUid(config,"key-b");

                if (!keyA || !keyB) {
                   fprintf (stderr, "Fatal: key-a & key-b should be defined before setting ACLs bits\n");
                   goto OnErrorExit;
                }

                err= pcscMifareTrailer (handle, keyA, acls, keyB, trailer);
                if (err) goto OnErrorExit;

                err= pcsWriteBlock (handle, cmd->uid, cmd->sec, cmd->blk, trailer, cmd->dlen, cmd->key);
                if (err) goto OnErrorExit;
                } break;

            default:
                goto OnErrorExit;
        }
    }

    err= pcscDisconnect (handle);
    if (err) goto OnErrorExit;

    if (params->verbose) fprintf (stderr, "OK: Success Exit\n");
    exit (0);

OnErrorExit:
    if (params->verbose) fprintf (stderr, "FX: Error Exit\n");
    exit (1);
}