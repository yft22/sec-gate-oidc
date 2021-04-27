# Installation

## Redpesk

afb-oidc-sgate is part of redpesk-common and is available on any redpesk installation.

```bash
sudo dnf install afb-oidc-sgate afb-oidc-webui
```

## Other Linux Distributions

**Prerequisite**: should declare redpesk repository: [[instructions-here]]({% chapter_link host-configuration-doc.setup-your-build-host %})

```bash
# Fedora
sudo dnf install afb-oidc-sgate fedid-binding afb-oidc-webui 

# OpenSuse
sudo zypper install afb-oidc-sgate fedid-binding afb-oidc-webui 

# Ubuntu
sudo apt-get install afb-oidc-sgate-bin fedid-binding afb-oidc-webui  afb-oidc-webui
```

Note: 

* afb-oidc-webui: is an optional angular/html5 frontend. If you do not use Angular, you rather check basic HTML/JS testing UI and write your own one.

* fedid-binding: is the companion binding that handle federation database.  It implements local an identity storage with an sqllite backend. Identity store is implemented as an external binding to allow developer to replace it with there preferred identity store model.

# Quick test

## start afb-oidc-sgate samples
Use one of the default config template to write your own one and start the binder with your own oidc-config.json

```
 afb-binder --config=/my_config/oidc-config.json
```
## Connect to HTML5 test page

Copy `localhost:1234` or what ever is your target host:port in your browser address bar to connect to HTML5 test page. 

*Note: to use HTTPS check ../conf.d/project/ssl/gen-cert.sh to generated self signed SSL development SSL certificates. Then set 'HTTPS':true within your oidc-config.json.*

## Rebuild 'afb-oidc-sgate' from sources

**Notice**: recompiling afb-oidc-sgate is not requirer to implement your own set rules. You should recompile 'afb-oidc-sgate' when:

* targeting a not supported environment/distribution.
* changing code to fix bug or propose improvement *(contributions are more than welcome)*
* adding custom/unsupported IDPs*

### Install building dependencies

#### Prerequisite

* declare redpesk repositories (see previous step).
* install typical Linux C/C++ development tool chain gcc+cmake+....

#### Install AFB binder and oidc-sgate dependencies

* application framework: 'afb-binding-devel', 'afb-binder-dev', 'afb-lib-afb-devel'
* cmake template 'afb-cmake-modules'

>Note: For Ubuntu/OpenSuse/Fedora specific instructions check [redpesk-developer-guide]({% chapter_link host-configuration-doc.setup-your-build-host#install-the-application-framework-1 %})

#### Install afb-oidc-sgate specific dependencies

* libpam-devel
* libcurl-devel

>Note: all previous dependencies should be available out-of-the-box within any good Linux distribution. Note that Debian as Ubuntu base distro use '.dev' in place of '.devel' for package name.

### Download source from git

```bash
git clone https://github.com/redpesk-common/afb-oidc-sgate.git
```

### Build your binding

```bash
mkdir build
cd build
cmake ..
make
```

### Run a test from building tree


```bash
# Customize '../conf.d/project/etc/oidc-basic.json' to patch your environnement
 afb-binder --config=../conf.d/project/etc/my-oidc-config.json -vvv
```
