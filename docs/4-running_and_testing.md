## Running/Testing

afb-oidc-ext implements *afb-libcontroller* and requires a valid afb-controller-config.json to operate. For testing purpose the simplest way
is to define `AFB_oidc_CONFIG` environment variable with a full or relative path to binder *rootdir*.

### Requirements

* you should have a valid afb-binder install.
* you should write or copy a sample oidc-config.json
* you should known the path to 'afb-oidc.so' binding
* you need a test client
  * afb-client for testing command line interface
  * afb-ui-devtools for html5 test with a web-browser (chromium, firefox, ...)

If you run redpesk simply install the package with `dnf install afb-oidc-ext` for other platform check redpesk [developer guide]({% chapter_link host-configuration-doc.setup-your-build-host %})



## Run afb-oidc-ext samples

``` bash
# move to default install directory
export AFB_oidc_INSTALL="/var/local/lib/afm/applications/afb-oidc-ext"

# running without privileged
AFB_oidc_CONFIG="$AFB_oidc_INSTALL/etc/oidc-nspace-config.json" afb-binder --name=afb-oidc --workdir=$AFB_oidc_INSTALL --binding=./lib/afb-oidc.so --verbose

# running with privileges
sudo AFB_oidc_CONFIG="$AFB_oidc_INSTALL/etc/oidc-nspace-config.json" afb-binder --name=afb-oidc --workdir=$AFB_oidc_INSTALL --binding=./lib/afb-oidc.so --verbose
```

>Note: --binding should point on where ever your *afb-oidc.so* is installed, and AFB_oidc_CONFIG should point on a valid json config

## Verify json config validity

``` bash
jq < /xxxx/yyy/my-oidc-config.json
```
>Note: JQ package should be available within your standard Linux repository


## HTML5 test

Open binding UI with browser at `[host]:[port]/devtools/index.html` in your browser address bar.
*For example: `localhost:1234/devtools/index.html` for a binding running on localhost, on port 1234.*

You should see a page as the one below fitting your configuration. To activate a command simply click, select a sample and sent.

![afb-ui-devtool](assets/afb-oidc-ext-exec.jpg)

## Command line test

### Connect *afb-client* to afb-oidc-ext service

``` bash
afb-client --human ws://localhost:1234/api
```

>Note: depending on afb-client version you may have no prompt. Use `simple ping` to assert oidc binding is alive !!!

### Test your API with afb-client

#### Basic commands

```bash
oidc admin/myid
oidc admin/env
oidc admin/cap
```

**oidc** is what ever *api name* your have chosen in your config.json. *Start* is the default action, also *oidc admin/myid* is equivalent to *oidc admin/myid {"action":"start"}*.

#### Passing arguments from query to cli

Api query takes args from the client as a json-object compose of {"name":"value"} tuples.

```bash
oidc admin/list {"args":{"dirname":"/etc"}}
oidc admin/list {"args":{"dirname":"/home"}}
oidc admin/display {"args":{"filename":"/etc/passwd"}}
```

Each argument passed into query *args* replaces corresponding %name% in binding config.json. In following example json query argument {"timeout": value} is passed to sleep command.

```json
config: "exec": {"cmdpath": "/bin/sleep", "args": ["%timeout%"]}
query:  {"action":"start","args":{"timeout":"180"}}
start:  sleep 180;

```

* mandatory argument: %argument% (abort the request when missing)
* optional argument: ?argument? (silently replaced by "" when missing)

## Advanced tests

Check for conf.d/project/etc for more advance samples.

Note: depending if you start afb-oidc-ext in a privilege mode or not, some behavior may change. For example "user/group" or "capacity" required to start the binder in admin mode with sudo.

```log
- NOTICE: [API oidc] sandboxParseAcls: [ignoring user/group acls] sandbox='sandbox-demo' no uid/gid privileges ignoring user='"daemon"' group='"dialout"' [/home/fulup/afb-oidc-ext/src/- oidc-sandbox.c:510,sandboxParseAcls]
- NOTICE: [API oidc] [capability ignored] sandbox='sandbox-demo' capability='KILL[set]' (sandboxParseOneCap)
- NOTICE: [API oidc] [cgroups ignored] sandbox=sandbox-demo user=1000 not privileged (sandboxLoadOne)
```

You may activate all config in one shot by using placing sample config name within AFB_oidc_CONFIG or by providing a suite of config.json filenames.

```bash
    oidc_SAMPLE_DIR=xxxxxx
    AFB_oidc_CONFIG=$oidc_SAMPLE_DIR  # will load every oidc-*.json config for given directory
    AFB_oidc_CONFIG=$oidc_SAMPLE_DIR/oidc-simple-config.json:$oidc_SAMPLE_DIR/oidc-minimal-config.json # load corresponding configs

    afb-binder --name=afb-oidc --binding=xxxxxx/afb-oidc.so
```

**Warning** if you load multiple file double-check that they register different APIs name. Your HTML5 interface should reflect
![oidc-biding-html5](assets/afb-oidc-ext-dualconf.jpg)

## Testing with GDB

When testing with GDB you should add *--trap-faults=no* in order to prevent afb-binder from trapping errors.
```bash
AFB_oidc_CONFIG=../conf.d/project/etc/oidc-simple-config.json gdb --args afb-binder --name=afb-oidc --binding=package/lib/afb-oidc.so -vvv --ws-server=unix:/run/user/$UID/simple --trap-faults=no
```

## Testing namespace

Namespace allows to create a *fake* root filesystem that only expose the minimal necessary resources. Unfortunately depending on your restriction the process may not even start, with no-log to help debugging the situation.

For a quick namespace test, start afb-oidc-ext with *oidc-sample-nspace.json*. Then use *oidc/admin list* api/verb to explore your namespace.

```bash
AFB_oidc_CONFIG=./conf.d/project/etc/oidc-sample-nspace.json afb-binder --name=afb-oidc --binding=./package/lib/afb-oidc.so
```

Namespace can a tricky to debug. In case of doubt add {"verbose":1} to query argument list, this will push within your command stderr the bwrap equivalent command. You may then copy/paste the command line and replace you command with "bash" to explore in interactive mode your namespace.

## Testing formatting

afb-oidc-ext support 3 builtin formatting options. Encoder formatting is enforced for each command within config.json. Default encoder is "DOCUMENT" and it cannot not be change at query time. Check *oidc-sample-encoders.json* for example. If you need the same command with multiple formatting, then your config should duplicate the entry with different uid.

## Exposing oidc API as AFB micro-service

In order to make afb-oidc-ext api accessible from other AFB micro-service you simply export the API with *--ws-server=unix:/path/apiname* as you would do for any other AFB micro-service. The exposed API may later be imported with *--ws-client==unix:/path/apiname* by any afb-binder that get corresponding privileges. *Note: when exposing an API locally it is a good practice to remove TCP/IP visibility with --no-httpd*

```bash
# note than --ws-server=unix exported API should match with selected config.json
AFB_oidc_CONFIG=$oidc_SAMPLE_DIR/oidc-simple-config.json afb-binder --no-httpd --ws-server=unix:/run/user/$UID/simple --name=afb-oidc --binding=package/lib/afb-oidc.so -vvv --ws-server=unix:/run/user/$UID/oidc
```

Direct unix socket API can be tested with *--direct* argument
``` bash
# note that when using direct api, apiname should not be added to the request
afb-client --direct unix:/run/user/$UID/simple
> ping
> admin/env
```

## Autoload/Autostart

afb-oidc-ext support an 'autoload', any action in this sections will be tried at binding starup time.
```json
  "onload": [
    {
      "uid": "vpn-autostart",
      "info": "create VPN interface (reference https://www.wireguard.com/quickstart)",
      "action": "api://autostart#vpn-start"
    }
  ],
```
*wireguard-autostart.json* provide a small example to start a wireguard VPN.

To run the test.

- Install 'wireguard-tools' to get 'wg-quick' helper.
- Start 'wireguard-autoconfig.sh' to create a test config into /etc/wireguard/afb-oidc-ext.conf
- Check with ```sudo wg-quick up afb-oidc-ext``` that your config works.
- Start 'afb-oidc-ext' in privileged mode with
```bash
sudo AFB_oidc_CONFIG=../conf.d/project/etc/wireguard-autostart.json afb-binder --name=afb-oidc --binding=package/lib/afb-oidc.so --verbose

```

## caching events

afb-oidc-ext is an [afb-controller](/docs/en/master/developer-guides/controllerConfig.html) and may on event reception execute internal/external API. For external action you should use *--ws-client=xxx* to import the api within afb-oidc-ext context. Note that to execute an external API you also need corresponding privileges.
```json
  "events": [
    {
      "uid": "monitor/disconnected",
      "info": "call log function on monitor/disconnect event detection",
      "action": "api://autostart#vpn-log"
    }
  ],
```