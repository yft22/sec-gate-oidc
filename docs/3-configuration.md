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
          "info" : "Rodrigo demo uses a 'one-page' app",
          "login": "/sgate/common/login.html",
          "register": "/sgate/common/register.html",
          "fedlink": "/sgate/common/fedlink.html",
          "error": "/sgate/common/error.html",
          "timeout": 600
      },
    }
}
```
* **api**: name of the oidc-sgate api as view from external application.
* **login**: redirect URL where application are redirected when an authentication is not strong enough. This page should present to end user and IDP selection list.
* **register**:  redirect URL when on first authentication of a given user from a given authority. This page should request some basic user attributes as pseudo and email.
* **fedlink**: redirect URL to link two external identities to a unique local identity.
* **timeout**: global default timeout session in seconds.

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
        "loginTokenUrl": "https://github.com/login/oauth/authorize",
        "accessTokenUrl": "https://github.com/login/oauth/access_token",
        "identityApiUrl": "https://api.github.com/user",
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
* **credientials**: openid clientid and secret. This information should be provided from your external authority. For github check https://docs.github.com/en/developers/apps/authorizing-oauth-apps
* **loginTokenUrl**: remote authority URL to redirect to when application should be redirected when an authentication is requirer.