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

#include "oidc-core.h"
#include "oidc-idp.h"
#include "oidc-alias.h"
#include "http-client.h"

#include <libafb/core/afb-session.h>
#include <libafb/http/afb-hreq.h>
#include <assert.h>
#include <string.h>
#include <locale.h>

#include <fedid-types.h>

typedef struct {
    void *raw;
    json_object *json;
} oidcProfilObjectT;

fedidCheckRegister (fedUserRawT *userRaw, fedSocialRawT *socialRaw, json_object *sourceJ) {
    int err;
    afb_data_t userData, socialData;
    err= afb_create_data_raw(&userData, userObjType, fedUserObjType, 0, fedidProfileFreeCB, userProfil);

void afb_api_v4_call_hookable(
	struct afb_api_v4 *apiv4,
	const char *apiname,
	const char *verbname,
	unsigned nparams,
	struct afb_data * const params[],
	void (*callback)(
		void *closure,
		int status,
		unsigned nreplies,
		struct afb_data * const replies[],
		struct afb_api_v4 *api),
	void *closure
);


}