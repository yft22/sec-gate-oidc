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

#pragma once

#include "oidc-core.h"
#include "oidc-http/http-client.h"

extern void* oidcIdpProfilCookie;

typedef struct {
  const char *loginTokenUrl;
  const char *accessTokenUrl;
  const char *identityApiUrl;
} oidcWellknownT;

typedef struct {
  const char *clientId;
  const char *secret;
} oidcCredentialsT;

typedef struct {
  const char *uid;
  const char *info;
  const char *scope;
  const char *label;
  int loa;
} oidcProfilsT;

typedef struct oidcAlcsS {
  int loa;
  int timeout;
  const char *aliasAuth;
  const char *aliasLogin;
} oidcAlcsT;

typedef struct oidcIdpS {
  int magic;
  const char *uid;
  const char *info;
  const char *logo;
  const oidcCredentialsT *credentials;
  const oidcWellknownT *wellknown;
  const httpKeyValT *headers;
  const oidcProfilsT *scopes;
  const oidcAlcsT *acls;
  const oidcProfilsT *profils;
  void *ctx;
  const idpPluginT *plugin;
  oidcCoreHdlT *oidc;
} oidcIdpT;

typedef struct {
  const oidcCredentialsT *credentials;
  const oidcAlcsT *acls;
  const oidcWellknownT *wellknown;
  const oidcProfilsT *profils;
  const httpKeyValT *headers;
} oidcDefaultsT;

// generic IDP utility callback
typedef struct idpGenericCbS {
  const oidcMagicT magic;
  const oidcCredentialsT* (*parseCredentials) (oidcIdpT *idp, json_object *credentialJ, const oidcCredentialsT *defaults);
  const oidcAlcsT* (*parseAcls) (oidcIdpT *idp, json_object *aclsJ, const oidcAlcsT *defaults);
  const oidcWellknownT* (*parseWellknown) (oidcIdpT *idp, json_object *wellknownJ, const oidcWellknownT *defaults);
  const httpKeyValT* (*parseHeaders) (oidcIdpT *idp, json_object *headersJ, const httpKeyValT *defaults);
  int (*parseConfig) (oidcIdpT *idp, json_object *configJ, oidcDefaultsT *defaults, void*ctx);
} idpGenericCbT;


typedef struct idpPluginS{
  const char *uid;
  const char *info;
  int (*initCB)(oidcIdpT *idp, json_object *idpJ, idpGenericCbT *oidcCB);
  int (*loginCB)(struct afb_hreq *hreq, void *ctx);
  void *ctx;
} idpPluginT;


// request handle
typedef struct {
	afb_hreq *hreq;
	oidcIdpT *idp;
	int loa;
} idpRqtCtxT;

// idp exported functions
const oidcIdpT *idpParseConfig (oidcCoreHdlT *oidc, json_object *idpsJ);
int idpRegisterOne (oidcCoreHdlT *oidc, oidcIdpT *idp, afb_hsrv *hsrv);
json_object *idpLoaProfilsGet (oidcCoreHdlT *oidc, int loa);
int idpPLuginRegistryInit(void);