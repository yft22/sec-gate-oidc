# Installation

## Redpesk

afb-oidc-ext is part of redpesk-common and is available on any redpesk installation.

```bash
sudo dnf install afb-oidc-ext afb-ui-devtools
```

## Other Linux Distributions

**Prerequisite**: should declare redpesk repository: [[instructions-here]]({% chapter_link host-configuration-doc.setup-your-build-host %})

```bash
# Fedora
sudo dnf install afb-oidc-ext afb-ui-devtools bubblewrap libcap

# OpenSuse
sudo zypper install afb-oidc-ext bubblewrap libcap-progs afb-ui-devtools

# Ubuntu
sudo apt-get install afb-oidc-ext-bin afb-ui-devtools bubblewrap libcap2-bin
```

# Quick test

## start afb-oidc-ext samples
```
AFB_oidc_CONFIG=/var/local/lib/afm/applications/afb-oidc-ext/etc \
afb-binder --name=afb-oidc --binding=/var/local/lib/afm/applications/afb-oidc-ext/lib/afb-oidc.so --verbose
```
## Connect to HTML5 test page

Copy `localhost:1234/devtools/index.html`in your browser address bar to connect to HTML5 test page

*Optionally:*

* if you rather CLI interface to HTML5, feel free to replace 'afb-ui-devtools' with 'afb-client'.

## Rebuild 'afb-oidc-ext' from sources

**Notice**: recompiling afb-oidc-ext is not requirer to implement your own set of commands and/or sandbox containers. You should recompile 'afb-oidc-ext' only when:

* targeting a not supported environment/distribution.
* changing code to fix bug or propose improvement *(contributions are more than welcome)*
* adding custom output formatting encoders. *note: for custom formatting you technically only recompile your new "custom-encoder". Nevertheless tool chain dependencies remain equivalent.*

### Install building dependencies

#### Prerequisite

* declare redpesk repositories (see previous step).
* install typical Linux C/C++ development tool chain gcc+cmake+....

#### Install AFB controller dependencies

* application framework 'afb-binder' & 'afb-binding-devel'
* binding controller 'afb-libcontroller-devel'
* binding helpers 'afb-libhelpers-devel'
* cmake template 'afb-cmake-modules'
* ui-devel html5 'afb-ui-devtools'

>Note: For Ubuntu/OpenSuse/Fedora specific instructions check [redpesk-developer-guide]({% chapter_link host-configuration-doc.setup-your-build-host#install-the-application-framework-1 %})

#### Install afb-oidc-ext specific dependencies

* libcap-ng-devel
* libseccomp-devel
* liblua5.3-devel

>Note: all previous dependencies should be available out-of-the-box within any good Linux distribution. Note that Debian as Ubuntu base distro use '.dev' in place of '.devel' for package name.

### Download source from git

```bash
git clone https://github.com/redpesk-common/afb-oidc-ext.git
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
export AFB_oidc_CONFIG=../conf.d/project/etc/oidc-simple-config.json
afb-binder --name=afb-oidc --binding=./package/lib/afb-oidc.so -vvv
```
