# phantauth Quick start IDP configuration

phantauth is not a readl IDP, but more a tool for for openid-connect client test and certification. It almost does not require configuration and might be very convenient for your CI/QA testing environment.

Note that Phantauth provide a quite complete set od REST api to automate your CI testing scenario. Check API documentation [here](https://www.phantauth.net/api/)

![home-documentation](asset/phantauth/01-documentation-api.png)

## 1- request a developer account.

Phantauth is fully opensource, and no registration is requirer. This does not prevent your from doing a small donation to cover operation cost [pricing](https://www.phantauth.net/doc/#pricing)

## 2- get your application client-id

Phantauth allows you to use any random client-id. Simply generate a secret [here](https://phantauth.net/)

![register-clientid](asset/phantauth/02-get-clientid.png)

## 3- register your login url

No need to register your redirect_uri, any one will do the job. This being said, you still need a valid end point to accept redirect after a valid authentication.

```json
    "statics": {
        "login": "/sgate/phantauth/login",
        "logo": "/sgate/phantauth/logo-64px.png",
    }
```

## 4- Add users

No need to request a user. Phantauth provide a fake login with no password. At login time user may choose its own attributes.

![register-user](asset/phantauth/04-authenticate-user.png)


## 6- mapping role on sgate security attributes

Phantauth does not handle groups/roles as such. Nevertheless for testing purpose your may still use gender or order other attributes as a fake security attributes.

For this create a profile that request corresponding identity attributes. Available scope [here](https://www.phantauth.net/doc/integration#scope)

```json

    "profiles": [
        {"uid":"basic", "loa":1, "scope":"openid profile"},
        {"uid":"basic", "loa":2, "scope":"openid profile address"}
    ]

```

Then map one of the return key from JWT token_id as sgate security attribute.

```json
    "schema": {
        "attrs": "address",
    },
```

## 7 Minimalist phantauth config.

A minimalist configuration may look like following one. Check for config chapter for full config options.

```json
{
  "name": "afb-oidc",
  "rootdir":  "/my/sgate/rootdir",
  "https": true,
  "https-cert": "./project/ssl/devel-cert.pem",
  "https-key": "./project/ssl/devel-key.pem",
  "extension": "libafb-sgate-oidc-ext.so",
  "binding" : [{"uid": "fedid-api", "path": "fedid-binding.so"}],

  "@extconfig": {
    "sgate-oidc": {
        "api": "sgate",
        "globals": {
            "login": "/sgate/common/login.html",
            "register": "/sgate/common/register.html",
            "fedlink": "/sgate/common/fedlink.html",
            "error": "/sgate/common/error.html",
        },

        "idps": [{
        {
            "uid": "phantauth",
            "type": "oidc",
            "credentials": {
                "clientid": "sgate-oidc-iotbzh",
                "secret": "3ON5yAxX",
            },
            "wellknown": {
                "discovery": "https://phantauth.net/.well-known/openid-configuration",
            },
            "statics": {
                "login": "/sgate/phantauth/login",
                "logo": "/sgate/phantauth/logo-64px.png",
                "timeout": 600
            },
            "profiles": [
                {"uid":"basic", "loa":1, "scope":"openid profile"},
            ]
        }],

        "alias": [
            {"uid": "idp-phantauth" , "url":"/sgate/onlogin", "path":"idps/phantauth" },

            {"uid": "public" , "url":"/public", "path":"public" },
            {"uid": "private", "url":"/private",  "loa":1, "path":"private" },
            {"uid": "confidential", "url":"/confidential", "loa":2, "path":"confidential" },
        ]
    }
  }
}
```