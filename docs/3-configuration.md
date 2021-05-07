# Configuration

## afb-oidc-sgate AFB binder config

oidc-sgate uses the new V4 afb-binder config file.  *It is highly recommended to check your config.json with a json linter after any modification.*

```bash
# check config.json validity with JQ
jq < oidc-config.json
```

### Binder standard config

The initial part of oidc-config.json is common to any afb-binder V4.

```json
{
  "name": "afb-oidc",
  "verbose": 2,
  "port": 1234,
  "https": false,
  "https-cert": "../conf.d/project/ssl/devel-cert.pem",
  "https-key": "../conf.d/project/ssl/devel-key.pem",
  "extension": "./package/lib/afb-oidc-sgate.extso",
  "rootdir":  "../conf.d/project/htdocs",
  "roothttp": ".",
}
```

### FedID companion binding

FedID-binding provides the identity federation API. It is designed as a replaceable component, but remains mandatory. Current version should run within the same binder as oidc-sgate extension, this constrain should be remove on future versions of the extension.

FedID-binding is a native afb-V4 binding, it configuration only required the path to the fedid-sqllite.db file. When not provided default path is /var/tmp/fedid-sqllite.db

```json
"binding" : [
  {"uid": "fedid-api",
   "path": "/usr/local/fedid-binding/lib/fedid-binding.so",
   "config": {"dbpath":"/var/store/fedid-sqllite.db"}
   }
  ],
```

*Note*: 

* At init time, fedid check for sqllite.db file. If not present it creates an empty DB with corresponding fedid schema. As a result dyring develop phase developer may safely delete the sqllite.db to restart test from a fresh empty identity federation data store.

* FedID binding provides AFB-V4 type converters. Those converters are share in between oidc-sgate extension and FedID binding. They are implemented as an independent sharelib that is shipped with FedID but requirer by the oidc-sgate extension.


### oidc-sgate extension

oidc-sgate is not a binding, but a binder-v4 extension. As a result it has access to every internal API from the binder and is not bound to any security restriction as a normal binding. Technically the extension implement hook on defined API/URL and intercept the incoming request to check if authentication level is acceptable or not.

### Configuration is split into zones:

* **global**: defines  default URL and global session timeout
* **idps**: one configuration per IDP (authentication authority)
* **apis**: imported API exposure and access control for REST/WEBsocket
* **alias**: HTTP access control.

### Global zone
 Define when user is redirected when something prevent from accessing a protected resource. Note that when WebSocket is used the same information is provided as an event in place of a traditional HTTP redirect.

```json
"@extconfig": {
    "oidc-sgate": {
      "api": "sgate",
      "info": "oidc secure gateway demo config",
      "globals": {
          "info" : "some misc useful info",
          "login": "/sgate/common/login.html",
          "register": "/sgate/common/register.html",
          "federate": "/sgate/common/fedlink.html",
          "home": "/",
          "error": "/sgate/common/error.html",
          "timeout": 600,
          "cache": 5000,
      },
    }
}
```
* **api**: name of the oidc-sgate api as view from external application.
* **login**: redirect URL where application are redirected when an authentication is not strong enough. This page should present to end user and IDP selection list.
* **register**:  redirect URL when on first authentication of a given user from a given authority. This page should request some basic user attributes as pseudo and email.
* **fedlink**: redirect URL to link two external identities to a unique local identity.
* **timeout**: global default timeout session in seconds. Defined how often an authority authentication token should be rechecked (from last authentication time and not from HTTP/REST request).
* **cache**: default access control list cache in ms. Defined how often access control should be recheck for a given Alias/API.

### IDP zone
A json array defining each authentication authority. Default authority are oAith2/OpenID-connect compliant. Nevertheless is is possible to add custom local/remote authority (check pam plugin as sample)

```json
{
    "uid": "github",
    "info": "OpenIdC Social Authentication",
    "credentials": {
      "clientid": "7899e605a7c15ae42f07",
      "secret": "385bbb1d7633e300aea137cf612ecd8ebdc98970",
    },
    "wellknown": {
        "tokenid": "https://github.com/login/oauth/authorize",
        "authorize": "https://github.com/login/oauth/access_token",
        "userinfo": "https://api.github.com/user",
    },
    "statics": {
        "login": "/sgate/github/login",
        "logo": "/sgate/github/logo-64px.png",
        "timeout": 600
    },
    "profils": [
        {"uid":"basic", "loa":1, "scope":"user:email"},
        {"uid":"teams", "loa":2, "scope":"read:org", "label":"organizations_url"}
    ]
}
```
* **uid**: IDP unique label
* **info**: Misc text presented with IDP list page
* **credientials**: This information should be provided from your external authority. OpenID-Connect typically requirer a ClientID and a Secret, but depending on the IDP you may have other form of credential. You may check OpenID-Connect generic protocol [here](https://openid.net/connect)  and github specifics [here](https://docs.github.com/en/developers/apps/authorizing-oauth-apps)

* **Wellknown**: remote IDP authority URLs, typically one URL to request the initial authentication token, then an other one to request the access token and final as many as needed URL for identity services provided by the authority.

  * **tokenid**: HTTP page to redirect to when authentication is requirer. This authority URL should prompt the user for authentication only when needed, in all the other case it should automatically redirect back oidc-sgate in SSO(Single-Sign-On).

  * **authorize**: REST exchange authentication end-point. Provided an access-token from the authentication-token received from 'tokenid' SSO. The request to 'authorize' does not go through user browser, this avoid to expose IDP application secret to user browser.

  * **userinfo**: REST authority identity service. Provide identity attributes matching requesting scope. Note that some authority as Github has multiple identity end point depending requested attributes. 

* **statics**: define the REST/HTTP end point created on oid-sgate for IDPs protocol handshake.

  * **login**: this is where remote IDP should redirect user after a valid HTTP authentication. When this page is called without a valid code from the authority user HTML application is redirect back to corresponding authority.
  * **logo**: misc information provided to login page when list available IDPs.
  * **timeout**: default timeout for this specific IDPs. After this timeout IDP LOA is reset to zero which force a token renewal negotiation.

* **profil**: each authority may support multiple [scope](https://auth0.com/docs/scopes/openid-connect-scopes) of authentication. A given scope typically imply a different authentication method (e.g. single vs double factor) and provide access to different user identity attributes. Scopes depend on IDP, most of them propose a, 'email' scope that typically respond to a basic LOA=1 model.

  * **uid**: unique profile label
  * **loa**: level of assurance attached to this IDP profile
  * **scope**: scope request when requesting authentication 
  * **label**: custom and specific to IDP label. It is used to request further identity information from IDP services. In the case of github 'organizations_url' is the json key name within return user attributes to request the list of organizations the user belows to.

* **apis**: list of binding APIs that oidc-sgate should make visible to the external world as with '--ws-client' binder command line attribute. Note that WebSocket does not support redirect, when a request is refused the application only receive an "UNAUTHORIZED" error. User application should subscribe to oidc-sgate events to be notified of refusal/error messages.
  * **uid**: api name as exported on oidc-sgate external interface.
  * **info**: misc user info presented to application then an authentication is required.
  * **loa**: level of assurance requested to access this page. By depend any IDP with equal or greater LOA will let the request go thought. When LOA is negative then the IDP should exactly request LOA. This is a very simple model to force a specific IDP on a give set of resources.
  * **requirer**: a list of either/or security labels check again identity authority. This list vary from one IDP to an other. Warning: this list is a logical OR, one match is enough to pass the check.
  * **prio**: access control priority list. The highest number being check first. Priority key might be use to implement complex access control as local AND case for security attributes. 
  * **uri**: which API to import. The "@api_name is the preferred method to import API from bindings running on the same Linux instance, to import API from binding running on the remote Linux instance use 'tcp:hostname:port/api' as with the --ws-client afb-binding command line option.
  * **lazy**: when true oidc-sgate will start even if API to import is not present.

* **Alias**: the same model as for apis but to protect HTML resources. The main difference is that with HTML it is possible to use redirect to automatically move the application from requested page to the authentication, when API/Websocket does not offer an equivalent mechanism.

  * **uid**: alias name as exported on oidc-sgate external interface.
  * **info**: misc user info presented to application then an authentication is required.
  * **loa**: level of assurance requested to access this page. 
  * **prio**: access control priority list. 
