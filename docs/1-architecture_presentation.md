# Architecture presentation

afb-oidc-ext exposes through a standard set of REST/Websocket APIs a simple mechanism to launch within secure sandbox containers any Linux native commands or script: bash, python, nodejs, lua, tcl, ...

afb-oidc-ext can launch any Linux executable command that support a non-interactive mode. Its security model scales from basic Linux access control with setuid/gid to advanced Linux security model based on cgroups, capability, seccomp and namespaces. Output generated during children execution on stdout/srderr are send back to HTML5 client interface through standard websocket as any other AFB events.

afb-oidc-ext was initially designed to provide an HTML5 user interface to the 'redpesk' factory-reset service, this for end-user to easily restore their system when things get really bad (SOTA failure, hardware breakdown, ...). Nevertheless its implementation is very generic, and it may respond to many other scenarios requirements:
 * any operations where a controlled upscale of user privileges is required (enter sleep-mode, reboot, reformat a disk, on-demand service activation, ...),
 * expose any (bash, python, nodejs, ...) scripts as AFB standard microservices this with privileges upscale or not,
 * autostart operation before systemd is ready (see vpn-autostart sample)
 * out-of-the-box exposure through HTML5 websocket of any set of scripts/commands
 * ...

afb-oidc-ext only requires a custom config.json to expose a new set of scripts/commands under an HTML5 form. It is not needed to change/recompile the source code to create a specific API or tune the security model to match your requirements.

* Define a config.json with 'script' commands he wishes to expose
* User standard afb-devtools-ui or provide a custom HTML5 page.

*Notes:
* developers who never had the opportunity to dig seriously into Linux advanced security model (cgroups, capabilities, namespace, seccomp, ...) may find usefully to run basic Linux commands/scripts with different security scenarios to check the effective impact of container sandbox settings on their own applications.
* performance cost: isolating the amount of extra resources due to afb-oidc-ext sandbox containerization is not a simple task. Nevertheless previous experimentations IoT.bzh did showed that processing sandboxes configurations usually cost more than the effective launch of the container itself. In order to reduce config processing, afb-oidc-ext compiles configurations at startup time, as a result outside of dynamic argument processing the extra cost should remains around 10ms on a typical embedded board as Renesas-M3/H3 .*


## Documentation

* [Installation Guide](./2-installation_guide.html)
* [Configuration](./3-configuration.html)
* [Running and Testing](./4-running_and_testing.html)

## Support/sources

afb-oidc-ext is part of redpesk-common and relies on [redpesk-core]({% chapter_link apis-services-doc.services-list %})

* Community support [#redpesk-core:matrix.org]( {% chapter_link community-doc.support %})
* source code: [github/redpesk-common](https://github.com/redpesk-common)

## HTML5 test page
![afb-oidc-ext-html5](assets/afb-oidc-ext-exec.jpg)
