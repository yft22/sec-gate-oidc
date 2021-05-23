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
#include  <signal.h>
#include  <setjmp.h>
#include <pthread.h>

#include <pcsclite.h>

#include <wrap-json.h>
#include <libafb/utils/json-locator.h>

static struct option options[] = {
	{"verbose", optional_argument, 0,  'v' },
	{"config", required_argument , 0,  'c' },
	{"group", optional_argument  , 0,  'g' },
	{"force", optional_argument  , 0,  'f' },
	{"async", optional_argument  , 0,  'a' },
	{"help" , optional_argument  , 0,  'h' },
	{0, 0, 0, 0 } // trailer
};

typedef struct {
    const char*cnfpath;
    int verbose;
    int index;
    int group;
    int forced;
    int async;
    pcscConfigT *config;
} pcscParamsT;

pcscParamsT *parseArgs(int argc, char *argv[]) {
	pcscParamsT *params = calloc (1, sizeof(pcscParamsT));
 	int index;

    if (argc < 2) goto OnErrorExit;

	for (int done=0; !done;) {
		int option = getopt_long(argc, argv, "v::c:g:f::a::", options, &index);
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

			case 'g':
				params->group=atoi(optarg);
				break;

			case 'f':
                params->forced++;
                if (optarg) params->forced=atoi(optarg);
				break;

			case 'a':
                params->async++;
                if (optarg) params->async=atoi(optarg);
				break;

			case 'h':
			default:
				goto OnErrorExit;
		}
	}

    return params;

OnErrorExit:
	fprintf (stderr, "usage: pcsc-test --config=/xxx/my-config.json [--async] [--group=-+0-9] [--verbose] [--force]\n");
	return NULL;
}

// execute commands from requested group
static int execGroupCmd (pcscHandleT *handle, pcscParamsT *params) {
    pcscConfigT *config= params->config;
    int jump=0;
    int err;

    // loop on defined commands
    for (int idx=0; config->cmds[idx].uid; idx++) {
        const pcscCmdT *cmd= &config->cmds[idx];
        u_int8_t data[cmd->dlen];

        if (params->group >= cmd->group  || abs(params->group) == cmd->group) {
            jump=1;
            err= pcscExecOneCmd (handle, cmd, data);
            if (err) {
                fprintf (stderr, " -- Fail Executing command uid=%s error=%s\n", cmd->uid, pcscErrorMsg(handle));
                if (!params->forced) goto OnErrorExit;
            }
        } else {
            if (params->verbose) {
                if (jump) {
                    fprintf (stderr, "\n");
                    jump=0;
                }
                fprintf (stderr, " -- Ignoring cmd=%s group=%d\n", cmd->uid, cmd->group);
            }
        }
    }
    return 0;

OnErrorExit:
    return -1;
}

// in asynchronous mode CB is call each time reader status change
static int readerMonitorCB (pcscHandleT *handle, unsigned long state) {
    pcscParamsT *params = (pcscParamsT*) pcscGetCtx(handle);
    int err;

    if (state & SCARD_STATE_PRESENT) {
        fprintf (stderr, " -- event: reader=%s card=0x%lx inserted\n", pcscReaderName(handle), pcscGetCardUuid(handle));
        err= execGroupCmd (handle, params);
        if (!params->verbose) fprintf (stderr, " -- exec : 'group=%d' done (--verbose for detail)\n", params->group);
        if (err) goto OnErrorExit;
    } else {
        fprintf (stderr, " -- event: reader=%s removed (waiting for new card)\n", pcscReaderName(handle));
    }
    return 0;

OnErrorExit:
	fprintf (stderr, "Fatal: closing pcsc monitoring\n");
	return -1;
}

// signal handler
static jmp_buf  JumpBuffer;
void  sigHandlerCB(int  sig) {
    longjmp(JumpBuffer, 1);
}

int main (int argc, char *argv[])
{
    int err;
    pcscParamsT *params= parseArgs (argc, argv);
    if (!params) goto OnErrorExit;

    // trap ctrl-C and memory fault
    signal(SIGINT , sigHandlerCB);
    signal(SIGSEGV, sigHandlerCB);
    if (setjmp(JumpBuffer) != 0) goto OnSignalExit;

    json_object *configJ;
    err= json_locator_from_file (&configJ, params->cnfpath);
    //json_object *configJ= json_tokener_parse(buffer);
    if (!configJ) {
        fprintf (stderr, "Fail to parse params.json (try jq < %s\n", params->cnfpath);
        goto OnErrorExit;
    }

    // parse json config and store with params for asynchronous callback
    pcscConfigT *config= pcscParseConfig (configJ, params->verbose);
    if (!config) goto OnErrorExit;
    params->config= config;

    // create pcsc handle and set options
    pcscHandleT *handle =pcscConnect (config->reader);
    if (!handle) {
        fprintf (stderr, "Fail to connect to reader=%s\n", config->reader);
        goto OnErrorExit;
    }

    // set options
    pcscSetOpt (handle, PCSC_OPT_VERBOSE, config->verbose);
    pcscSetOpt (handle, PCSC_OPT_TIMEOUT, config->timeout);

    // check async handling
    if (params->async) {
        pthread_t tid;

        // start smartcard reader monitoring pass params as context to handle option in CB
        tid= pcscReaderMonitor (handle, readerMonitorCB, (void*)params);
        if (!tid) {
            fprintf (stderr, " -- Fail monitoring reader reader=%s error=%s\n", pcscReaderName(handle), pcscErrorMsg(handle));
            if (!params->forced) goto OnErrorExit;
        }
        fprintf (stderr, " -- Waiting: %ds events for reader=%s (ctrl-C to quit)\n", params->async, pcscReaderName(handle));
        pthread_join(tid, NULL); // infinit wait for monitor to quit

    } else {

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
        err= execGroupCmd (handle, params); // synchronous command exec
        if (err) goto OnErrorExit;
    }

    err= pcscDisconnect (handle);
    if (err) goto OnErrorExit;

    if (params->verbose) fprintf (stderr, "OK: Success Exit\n\n");
    exit (0);

OnErrorExit:
    fprintf (stderr, "FX: Error Exit\n\n");
    exit (1);

OnSignalExit:
    fprintf (stderr, "\nFX: On Signal Exit\n\n");
    exit (1);
}