# OpenID-Connect Secure-Gateway AFB-Extension

oidc-sgate is an openid-connect compliant extension to the application framework binder. It provides a secure filtering gateway for REST and websocket incoming request.

On the external Internet interface is leverage OpenID user profile services to map incoming browser to profile and roles as defined by the identity authority. On the backend level (micro-service APIs) it respond to Cynagora privilege request for lower micro-service API to accept or deny a given request.

oidc-sgate complies with any OpenID-connect identity public authority as github, google, microsoft, facebook, ... it also complies with internal authorities as Dex, Keycloak, Forgerock, ...

Dependences
	json-c
	libafb
	libcurl
    uthash

makedir build & cd build
cmake ..
make

![oidc-biding-html5](docs/assets/afb-oidc-ext-dirconf.jpg)

Generate keys