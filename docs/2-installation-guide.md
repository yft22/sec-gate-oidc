# Installation

## Redpesk

afb-sgate-oidc is part of redpesk-common and is available on any redpesk installation.

```bash
sudo dnf install afb-sgate-oidc afb-oidc-webui
```

## Other Linux Distributions

**Prerequisite**: should declare redpesk repository: [[instructions-here]]({% chapter_link host-configuration-doc.setup-your-build-host %})

```bash
# Fedora
sudo dnf install afb-sgate-oidc fedid-binding afb-oidc-webui

# OpenSuse
sudo zypper install afb-sgate-oidc fedid-binding afb-oidc-webui

# Ubuntu
sudo apt-get install afb-sgate-oidc-bin fedid-binding afb-oidc-webui
```

Note:

* afb-oidc-webui: is an optional angular/html5 frontend. If you do not use Angular, you rather check basic HTML/JS testing UI and write your own one.

* fedid-binding: is the companion binding that handle federation database.  It implements local an identity storage with an sqllite backend. Identity store is implemented as an external binding to allow developer to replace it with there preferred identity store model.

# Quick test

## start afb-sgate-oidc samples
Use one of the default config template to write your own one and start the binder with your own oidc-config.json

```
 # check with PAM login as fake IDP
 afb-binder --config=/my_config/oidc-local.json
```
**Note:** *any test with as external authority require a minimum level of remote configuration. Check specific IDPs requirement before trying oidc-oauth2.json samples.*

## Connect to HTML5 test page

Connect your browser to your sgate-oidc service with ```https://target:port``` to display corresponding HTML5 test page. When testing on your local machine redirect uri should look like https://localhost:1234 when running sgate on a target, then your should use https://target-ip-addr

* Note:

    * HTTPS require SSL certificates. Check $PROJECT/conf.d/project/ssl/gen-cert.sh to generated self signed SSL certificates. For development you may also choose remove SSL. To remove SSL simply set 'HTTPS':false within your oidc-config.json

    * Warning: most IDPs impose HTTPS connection when using anything different from localhost as redirect login URL.


## Rebuild 'afb-sgate-oidc' from sources

**Notice**: recompiling afb-sgate-oidc is not require to implement your own set rules. You should recompile 'afb-sgate-oidc' when:

* targeting a not supported environment/distribution.
* changing code to fix bug or propose improvement *(contributions are more than welcome)*
* adding custom/unsupported IDPs*

### Install building dependencies

#### Prerequisite

* declare redpesk repositories (see previous step).
* install typical Linux C/C++ development tool chain gcc+cmake+....

#### Install AFB binder and sgate-oidc dependencies

* application framework: 'afb-binding-devel', 'afb-binder-dev', 'afb-lib-afb-devel'
* cmake template 'afb-cmake-modules'

>Note: For Ubuntu/OpenSuse/Fedora specific instructions check [redpesk-developer-guide]({% chapter_link host-configuration-doc.setup-your-build-host#install-the-application-framework-1 %})

#### Install afb-sgate-oidc specific dependencies

* standard linux dependencies
    * libpam-devel
    * libcurl-devel
    * uthash

* Redpesk AFB application framework dependencies
    * afb-cmake-modules
    * afb-lib-afb-devel

>Note: all previous dependencies should be available out-of-the-box for major Linux distrutions (Fedora, OpenSuse, Ubuntu). Note that Debian/Ubuntu use '.dev' in place of '.devel'.

### Download source from git

```bash
    git clone https://github.com/redpesk-common/sgate-fedid-binding.git
    git clone https://github.com/redpesk-common/sgate-oidc-afbext.git
```

### Build your fedid binding and sgate binder extention

Build and install fedid-binding first, as the secure gateway extension depends on fedid types converters ship as part of fedid-binding.

Both should compile with standard AGL cmake template.

```bash
    mkdir build
    cd build
    cmake ..
    make
    make install
```

### Run a test from building tree

Create a custom config file from samples avaliable at '../conf.d/project/etc/oidc-*.json'. When config looks good try it with afb-binder --config. Note that it is a good 'best-practice' to check your json config with 'jq' on an equivalent tools before trying to use it.

```bash
    jq < ../conf.d/project/etc/my-oidc-config.json
    afb-binder --config=../conf.d/project/etc/my-oidc-config.json -v
```
