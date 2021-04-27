# Architecture presentation

afb-oidc-sgate is an afb-binder-v4 extension. It leverages binder hooking capabilities to enforce authentication from an external authority (IDP) to allow/deny HTTP/REST/WEBsocket requests.

 * hooked input request can be checked again:

    * LOA (Level Of Assurance) defines the level of trust you have in a given external authentication source. There is no standard to define LOA. Nevertheless most people loosely map it on NIST definition:
    
        * loa=0 public access
        * loa=1 basic authentication (just better than nothing)
        * loa=2 typical authentication (usually provided some trusted attributes as roles or groups.
        * loa=3 more trusted authentication (two factors ?)
        * loa=6 live critical authentication.

    * Security attributes, define a set of labels that should be provided by your IDP. Enterprise IDPs typically provide either groups or roles. An external authority as 'github' provides organizations, repositories, ... Each IDP has it own way to provide attributes.

    * Note: 

        * when requesting LOA=2 then any IDP with a higher LOA will be accepted. You should use LOA=-2 to enforce a specific level of LOA.

        * security attributes array are processed as logical OR. If one of the list is accepted then the request is valid.

## Documentation

* [Installation Guide](./2-installation_guide.html)
* [Configuration](./3-configuration.html)
* [Running and Testing](./4-running_and_testing.html)

## Support/sources

afb-oidc-sgate is part of redpesk-common and relies on [redpesk-core]({% chapter_link apis-services-doc.services-list %})

* Community support [#redpesk-core:matrix.org]( {% chapter_link community-doc.support %})
* source code: [github/redpesk-common](https://github.com/redpesk-common)

## HTML5 test page
![afb-oidc-sgate-html5](assets/afb-oidc-sgate-test.jpg)
