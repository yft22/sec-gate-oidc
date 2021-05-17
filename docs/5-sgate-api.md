# API sgate

## idp-query

Return the list of configured IDP matching requested LOA with all necessary information for presenting a login UI to the end-user.

```json
// request
0: ws:/sgate/idp-query-conf?query="{}"
```

The API retutn IDPs list as an array and the 
```json
// response
  "jtype": "afb-reply",
  "request": {
    "status": "success",
    "code": 0
  },
  "response": {
    "idps": [
      {
        "uid": "onelogin",
        "info": "OpenIdC free testing IDP (https://www.onelogin.com/developer-signup)",
        "logo": "/sgate/onelogin/logo-64px.png",
        "client-id": "1198ce80-9187-0139-6d83-06d14e293211189676",
        "login-url": "/sgate/onelogin/login",
        "profiles": [
          {
            "loa": 1,
            "uid": "basic",
            "scope": "openid profile"
          },
          {
            "loa": 2,
            "uid": "basic",
            "scope": "openid profile groups"
          }
        ]
      },
      {
        "uid": "phantauth",
        "info": "OpenIdC testing authority (https://phantauth.net/)",
        "logo": "/sgate/phantauth/logo-64px.png",
        "client-id": "sgate-oidc-iotbzh",
        "login-url": "/sgate/phantauth/login",
        "profiles": [
          {
            "loa": 1,
            "uid": "basic",
            "scope": "openid profile"
          }
        ]
      },
      {
        "uid": "github",
        "info": "Github Social Authentication",
        "logo": "/sgate/github/logo-64px.png",
        "client-id": "7899e605a7c15ae42f07",
        "login-url": "/sgate/github/login",
        "profiles": [
          {
            "loa": 1,
            "uid": "basic",
            "scope": "user:email"
          },
          {
            "loa": 2,
            "uid": "teams",
            "scope": "read:org"
          }
        ]
      }
    ],
    "alias": {
      "uid": "private",
      "info": "Required basic authentication",
      "url": "/private",
      "loa": 1
    }
  }
}
```
