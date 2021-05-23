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
	{"group", optional_argument, 0,  'g' },
	{0, 0, 0, 0 } // trailer
};

typedef struct {
    const char*cnfpath;
    int verbose;
    int index;
    int group;
} pcscParamsT;

pcscParamsT *parseArgs(int argc, char *argv[]) {
	pcscParamsT *params = calloc (1, sizeof(pcscParamsT));
 	int index;

	for (int done=0; !done;) {
		int option = getopt_long(argc, argv, "v::c:g:", options, &index);
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

			default:
				goto OnErrorExit;
		}
	}

    return params;

OnErrorExit:
	fprintf (stderr, "usage: pcsc-main --config=... [--group=xx] [--verbose]\n");
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

    // loop on defined commands
    int jump=0;
    for (int idx=0; config->cmds[idx].uid; idx++) {
        const pcscCmdT *cmd= &config->cmds[idx];
        u_int8_t data[cmd->dlen];

        if (cmd->group == params->group) {
            jump=1;
            err= pcscCmdExec (handle, cmd, data);
            if (err) {
                fprintf (stderr, " -- Fail Executing command uid=%s error=%s\n", cmd->uid, pcscErrorMsg(handle));
                goto OnErrorExit;
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

    err= pcscDisconnect (handle);
    if (err) goto OnErrorExit;

    if (params->verbose) fprintf (stderr, "OK: Success Exit\n\n");
    exit (0);

OnErrorExit:
    fprintf (stderr, "FX: Error Exit\n\n");
    exit (1);
}