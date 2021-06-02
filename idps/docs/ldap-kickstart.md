# ldap Quick start IDP configuration

LDAP is obviously not openid-connect compliant, also with local authentication sgate fakes a full IDP. With LDAP is uses an initial request to check login/password while retrieving user profile and a second request to retrieve groups user belows to.

Unfortunately LDAP does not support SSO(Sign Sign On) and each time a session timeouts, you will have to confirm your password.

## 1- request a developer account.

As LDAP or Active directory is usually handle by your company system administrator, either you already have an account, or you will probably never get one.

## 2- get your application client-id

LDAP does not use application client-id. You should check with your system administrator the schema in order to build authentication requests for:

* authenticate a user
* retrieve authenticate user profile
* retrieve groups authenticate user belows to.

Those information should go in the 'schema' section of your sgate config.json

```json
    "schema": {
        "uri": "ldap://ldap.ovh.iot",
        "login": "uid=%login%,ou=People,dc=vannes,dc=iot",
        "people": "ou=people,dc=vannes,dc=iot?uid,gecos,mail?sub?(cn=%login%)",
        "groups": "ou=groups,dc=vannes,dc=iot?dn?sub?(memberUid=%login%)",
    },
```
In every URL login is replaced by login name provided by user authentication.

* **uri:** your ldap hostname optionally your may force your port. *(note: ldap/ldaps is detected automatically()*.

* **login**: should match a user DN within your LDAP schema.
* **people**: schema dependent request to retrieve a given user profile
* **groups**: schema dependent request to retrieve groups a user belongs to.

Before creating your config.json we advice you to check your schema with curl or ldap search.

```bash
    # Replace %???% with values matching your LDAP company schema
    curl -u "%userdn% %ldapuri%/%groupdn%?dn?sub?%filter%"
```

optionally your may also add following arguments to schema config:
* **avatar**: default avatar for ldap users
* **gids**: max number of authorized group (default 32)
* **timeout**: max timeout in second (default 5)

## 3- register your login url

They is not need to register a login URL, default should work for most of developers. Furthermore it is recommended to use websocket over a get/post form to check a login/passwd. The logo is the logo that should be display to help user to select the right authentication authority.

```json
    "statics": {
        "login": "/sgate/ldap/login",
        "logo": "/sgate/ldap/logo-64px.png",
    }
```

## 4- retrieve application clientid/secret

There is no clientid/secret the credential section is unused. On the other hand as LDAP does not provide an authentication page, you should provide one and register it within the wellknown section.

```json
    "wellknown": {
        "tokenid": "/sgate/ldap/login.html"
    },
```

This page should request user login/password and either post it back to the same uri end point, or better as explained before use the websocket API to check login/password validity. Check sample ldap login page at $SOURCE/conf.d/project/htdocs/idps/ldap/login.html

![login-page](asset/ldap/04-ldap-login-form-sample.png)


## 5- Add users

Any user matching your schema filter rules should be able to login your application.

## 6- mapping role on sgate security attributes

Any groups retrieve with your group request filter are automatically treated as sgate security attributes.

## 7 Minimalist ldap config.

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

        "idps": {
           "uid": "ldap-iotbzh",
            "type": "ldap",
            "info": "Iot.bzh internal LDAP",
            "statics": {
                "login": "/sgate/ldap/login",
                "logo": "/sgate/ldap/logo-64px.png",
            },
            "schema": {
                "uri": "ldap://ldap.ovh.iot",
                "login": "uid=%login%,ou=People,dc=vannes,dc=iot",
                "groups": "ou=groups,dc=vannes,dc=iot?dn?sub?(memberUid=%login%)",
                "people": "ou=people,dc=vannes,dc=iot?uid,gecos,mail?sub?(cn=%login%)",
                "signed": true,
            },
            "wellknown": {
                "tokenid": "/sgate/ldap/login.html"
            },
            "profiles": [
                {"uid":"login", "loa":1, "scope":"login"}
            ]
        },

        "alias": [
            {"uid": "idp-ldap"  , "url":"/sgate/ldap","loa":0, "path":"idps/ldap" },
            {"uid": "public" , "url":"/public", "path":"public" },
            {"uid": "private", "url":"/private",  "loa":1, "path":"private" },
            {"uid": "confidential", "url":"/confidential", "loa":2, "path":"confidential" },
        ]
    }
  }
}
```