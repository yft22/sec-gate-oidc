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

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "oidc-utils.h"

// Extract $KeyName and replace with $Key Env or default Value
static int utilExpandEnvKey (oidcDefaultsT *defaults, int *idxIn, const char *inputS, int *idxOut, char *outputS, int maxlen, void *userdata) {
    char envkey[OIDC_MAX_ARG_LABEL];
    char *envval=NULL;
    int index;

    // get envkey from $ to any 1st non alphanum character
    for (int idx=0; inputS[*idxIn] != '\0'; idx++) {

        (*idxIn)++; // intial $ is ignored
        if (inputS[*idxIn] >= '0' && inputS[*idxIn] <= 'z') {
            if (idx == sizeof(envkey)) goto OnErrorExit;
            envkey[idx]= inputS[*idxIn] & ~32; // move to uppercase
        } else {
            (*idxIn)--; // keep input separation character
            envkey[idx]='\0';
            break;
        }
    }

    // Search for a default key
    for (index=0; defaults[index].label; index++) {
        if (!strcmp (envkey, defaults[index].label)) {
            envval = (*(oidcGetDefaultCbT)defaults[index].callback) (defaults[index].label, defaults[index].ctx, userdata);
            if (!envval) goto OnErrorExit;
            for (int jdx=0; envval[jdx]; jdx++) {
                if (*idxOut >= maxlen) goto OnErrorExit;
                outputS[(*idxOut)++]= envval[jdx];
            }
            if (defaults[index].allocation == OIDC_MEM_DYNAMIC) free (envval);
        }
    }

    // if label was not found but default callback is defined Warning default should use static memory
    if (!envval && defaults[index].callback) {
        envval = (*(oidcGetDefaultCbT)defaults[index].callback) (defaults[index].label, defaults[index].ctx, userdata);
        if (envval) {
            for (int jdx=0; envval[jdx]; jdx++) {
                if (*idxOut >= maxlen) goto OnErrorExit;
                outputS[(*idxOut)++]= envval[jdx];
            }
        }
    }
    if (defaults[index].allocation == OIDC_MEM_DYNAMIC) free (envval);

    if (!envval) goto OnErrorExit;
    return 0;

OnErrorExit:
    { // label not expanded, provide some usefull debug information
        int index=0;
        envval="???unset_config_defaults????";
        outputS[index++]='$';
        for (int jdx=0; envkey[jdx]; jdx++) {
            if (index >= maxlen-2) {
            outputS[index] = '\0';
            return 1;
            }
            outputS[index++]= envkey[jdx];
        }
        outputS[index++] = '=';

        for (int jdx=0; envval[jdx]; jdx++) {
            if (index >= maxlen-1) {
                outputS[index] = '\0';
                return 1;
            }
            outputS[index++]= envval[jdx];
        }
        outputS[index] = '\0';
        return 1;
    }
}

const char *utilsExpandString (oidcDefaultsT *defaults, const char* inputS, const char* prefix, const char* trailer, void *userdata) {
    int count=0, idxIn, idxOut=0;
    char outputS[OIDC_MAX_ARG_LEN];
    int err;

    if (prefix) {
        for (int idx=0; prefix[idx]; idx++) {
            if (idxOut == OIDC_MAX_ARG_LEN) goto OnErrorExit;
            outputS[idxOut]=prefix[idx];
            idxOut++;
        }
    }

    // search for a $within string input format
    for (idxIn=0; inputS[idxIn] != '\0'; idxIn++) {

        if (inputS[idxIn] != '$') {
            if (idxOut == OIDC_MAX_ARG_LEN)  goto OnErrorExit;
            outputS[idxOut++] = inputS[idxIn];

        } else {
            if (count == OIDC_MAX_ARG_LABEL) goto OnErrorExit;
            err=utilExpandEnvKey (defaults, &idxIn, inputS, &idxOut, outputS, OIDC_MAX_ARG_LEN, userdata);
            if (err) {
                fprintf (stderr, "ERROR: [utilsExpandString] ==> %s <== (check xxxx-defaults.c)\n", outputS);
                goto OnErrorExit;
            }
            count ++;
        }
    }

    // if we have a trailer add it now
    if (trailer) {
        for (int idx=0; trailer[idx]; idx++) {
            if (idxOut == OIDC_MAX_ARG_LEN) goto OnErrorExit;
            outputS[idxOut]=trailer[idx];
            idxOut++;
        }
    }

    // close the string
    outputS[idxOut]='\0';

    // string is formated replace original with expanded value
    return strdup(outputS);

  OnErrorExit:
    return NULL;

}

// default basic string expansion
const char *utilsExpandKey (const char* src) {
    if (!src) goto OnErrorExit;
    const char *outputString= utilsExpandString (oidcVarDefaults, src, NULL, NULL, NULL);
    return outputString;

  OnErrorExit:
    return NULL;
}

// default basic string expansion
const char *utilsExpandKeyCtx (const char* src, void *ctx) {
    if (!src) goto OnErrorExit;
    const char *outputString= utilsExpandString (oidcVarDefaults, src, NULL, NULL, ctx);
    return outputString;

  OnErrorExit:
    return NULL;
}

// replace any %key% with its coresponding json value (warning: json is case sensitive)
const char *utilsExpandJson (const char* src, json_object *keysJ) {
    int srcIdx, destIdx=0, labelIdx, expanded=0;
    char dst[OIDC_MAX_ARG_LEN], label[OIDC_MAX_ARG_LABEL];
    const char *response;
    json_object *labelJ;
    char separator = -1;

    if (!keysJ) return (src);
    if (!src) goto OnErrorExit;

    for (srcIdx=0; src[srcIdx]; srcIdx++) {

        // replace "%%" by '%'
        if (src[srcIdx] == '%' || src[srcIdx] == '?') {
            separator= src[srcIdx];
            if (src[srcIdx+1] == separator) {
                dst[destIdx++]= src[srcIdx];
                srcIdx++;
                continue;
            }
        }

        if (src[srcIdx] != separator) {
            dst[destIdx++]= src[srcIdx];

        } else {
            expanded=1;
            labelIdx=0;
            // extract expansion label for source argument
            for (srcIdx=srcIdx+1; src[srcIdx]  ; srcIdx++) {
                if (src[srcIdx] !=  separator) {
                    label[labelIdx++]= src[srcIdx];
                    if (labelIdx == OIDC_MAX_ARG_LABEL) goto OnErrorExit;
                } else break;
            }

            // close label string and remove trailling '%' from destination
            label[labelIdx]='\0';

            // search for expansion label within keysJ
            labelJ= json_object_object_get (keysJ, label);
            if (!labelJ) {
                if (separator == '%') goto OnErrorExit;
            } else {
                // add label value to destination argument
                const char *labelVal= json_object_get_string(labelJ);
                for (labelIdx=0; labelVal[labelIdx]; labelIdx++) {
                    dst[destIdx++] = labelVal[labelIdx];
                }
            }
        }
    }
    dst[destIdx++] = '\0';

    // when expanded make a copy of dst into params
    if (!expanded) {
        response=src;
    } else {
        // fprintf (stderr, "utilsExpandJson: '%s' => '%s'\n", src, dst);
        response= strdup(dst);
    }

    return response;

  OnErrorExit:
        return NULL;
}