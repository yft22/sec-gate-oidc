# Configuration

## afb-oidc-ext AFB hierarchy config

afb-oidc-ext config depends on afb-controller and people used to redpesk or agl AFB controllers should feel home. For the other one config.json as described below remains pretty simple.

*It is nevertheless highly recommended to check your config.json with a json linter after any modification.*

```bash
# check config.json validity with JQ
jq < config.json
```

Config.json filename should be place into AFB_oidc_CONFIG before starting afb-binder. Config can either be a simple filename, a suite of filename separated by ':' or a directory, in which case afb-oidc-ext will take every oidc-*.json file from concerned directory.

### top hierarchy

* metadata: API name
* plugins: optional encoder plugin path and names
* sandbox: access control and command list

**Minimal configuration sample**

```json
{
  "metadata": {
    "uid": "oidc-svc",
    "api": "mini",
    "version": "1.0"
  },
  "sandboxes": {
      "uid": "sandbox-mini",
      "commands": [
        {
          "uid": "distro",
          "info" : "return server Linux version",
          "exec": {"cmdpath": "/usr/bin/lsb_release", "args": ["-a"]}
        }
      ]
    }
}

// resulting API
// ws://localhost:1234/api/minimal/distro?query={"action":"start"}
```

### sandbox definition

* **uid**: sandbox name, is used to build children taskid
* **info**: optional field describing sandbox
* **prefix**: is added to every command 'api/verb==api-name/prefix/cmd-uid'.  When prefix="" it is fully removed from commands API, providing a flat namespace to every commands independently of their umbrella sandbox.
Default when prefix is not defined. If config.json declare more than one 'sandbox' by default *prefix==sandbox->uid*, on the other hand if config.json declare only one sandbox (no json-array) then no-prefix is added and api/ver==api-name/cmd-uid.
* **verbose**: [0-9] value. Turn on/off some debug/log capabilities
* **privilege**: required corresponding sample privileges [here]({% chapter_link afb_binder.overview %}). For further explanation on AFB privileges check: [Cynagora](../../developer-guides/afb-overview.html). AFB/AGL privileges are based on Tizen privileges definitions [here](https://www.tizen.org/privilege)
```json
  "sandboxes": {
      "uid": "sandbox-demo",
      "info": "Shell admin commands",
      "prefix": "admin",
      "privilege": "urn:redpesk:permission:system:syscall:shell",
      "verbose":2
  }
```

* **envs**: environment variable inherited or not by child at fork/execv time
```json
  "envs" : [
      {"name": "SESSION_MANAGER", "mode":"unset"},
      {"name": "PATH", "value":"/bin"},
      {"name": "LD_LIBRAY_PATH", "value":"/usr/lib64"}
    ]
```

* **acl**: basic Linux [DAC](https://en.wikipedia.org/wiki/Discretionary_access_control)
* **caps**: Linux [capabilities](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html). Note:  to gain privileges binder should run in privileged mode.
* **cgroups**: create a cgroup-v2 in */sys/fs/cgroup/sandbox-uid* and attach every children oidc to the corresponding cgroup (binder need to be privileged to activate cgroups)
* **seccomp**: restrict kernel syscall with [SECure COMPuting with filters](https://www.kernel.org/doc/html/v4.16/userspace-api/seccomp_filter.html)
* **namespace**: create an unprivileged rootless container based on [unshare](https://www.kernel.org/doc/html/v4.16/userspace-api/unshare.html?highlight=unshare#benefits) kernel call.
* **commands**: the list of commands use wish to expose as HTML5 api/verb.

#### acls (basic access control)

```json
  "acls": {
        "umask": "027",
        "user": "daemon",
        "group":"dialout",
        "chdir": "/var/tmp"
      }
```

* **umask**: standard Linux umask, if not defined use system default.
* **user**:  either 'fullname' or 'uid'. **WARNING**: when running 'root' privileged mode, 'acl->user' must be defined. When 'root' is requirer, you have to enforce it and explicitly add 'user:root' in your acls config. Note than running 'root' is a bad behavior. As much as possible you should run with a less privilege user and add only minimum requirer capabilities to run your command.
* **group**: equivalent to user
* **chdir**: change dir before child fork/exec.
* **label**: set SeLinux/Smack security label for oidc children to either: LSM_LABEL_SBOX, LSM_LABEL_API, LSM_LABEL_CMD or LSM_LABEL_NO. Tagging children with a security label requirer either SMACK or SeLinux on the platform as well as running under privileged mode.
* **timeout**: default execution timeout for every sandbox command. Overload possible at cmd config level.

#### caps (linux capabilities)

```json
  "caps": [
      {"cap": "NET_BROADCAST", "mode": "unset"},
      {"cap": "KILL", "mode":"set"}
  ]
```

Linux [capabilities](https://www.openshift.com/blog/linux-capabilities-in-openshift) allow a process to gain a subset of traditional "super admin" privileges. For example it may give the "chown" or "kill" authorization without giving full "sudo" rights. . When running non-privileged afb-oidc-ext may only drop capabilities. If order to give extra capabilities to non-privileged user afb-oidc-ext must run in privileged mode.

#### groups (control groups-v2)

```json
  "cgroups": {
      "cset": "1-4",
      "mem": {"max": "512M", "hight": "256M", "min": "128K"},
      "cpu": {"weight":"100","max": "100000"}
  }
```

[Cgroups](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html) allow to control/limit resources as CPU,RAM,IO,... afb-oidc-ext enforces 'cgroup-v2' which is default for Redpesk or latest Fedora. Unfortunately cgroup V1-V2 have a incompatible APIs and even if some compatibility mode exist in practice it is better not to use them.  The good news is that any recent Linux distribution as Ubuntu-20.4 or OpenSuse-15.2, ... have a builtin option to run cgroups-v2, the bad news is that by default they still activate V1. On those distro user should edit corresponding boot flag to activate V2. See [activating cgroup-v2] at the end of this page.

* **cset**: provides CPU affinity. As example "3-5" will limit child process to CPU:3,4,5. [kernel-doc](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/cpusets.html?highlight=cset)
* **mem**: limit the amount of RAM support "max","hight","min" label. [kernel-doc](https://www.kernel.org/doc/html/v4.19/admin-guide/cgroup-v2.html#memory)
* **cpu**: restrict CPU usage support "weight" and "max" label. [kernel-doc](https://www.kernel.org/doc/html/v4.19/admin-guide/cgroup-v2.html#cpu)
* **io**: restrict per devices (major/minor) usage. [kernel-doc](https://www.kernel.org/doc/html/v4.19/admin-guide/cgroup-v2.html#io)

#### seccomp secure computing filters

```json
  "seccomp": {
      "default": "SCMP_ACT_ALLOW",
      "locked": false,
      "rules": [
          {"syscall": "kexec_file_load", "action": "SCMP_ACT_KILL"},
          {"syscall": "breakpoint", "action": "SCMP_ACT_KILL"}
      ]
  }
```

[Seccomp](https://www.kernel.org/doc/html/v4.16/userspace-api/seccomp_filter.html) allows to restrict the syscall a given may access. Seccomp rules may either be provided within a json_array or in a file of compiled BPF rules [BPF/XDP-doc](https://docs.cilium.io/en/v1.9/). While *seccomp* is a very powerful tool to secure a container writing a complex set of security rules is not a simple task. Redhat has nevertheless a good introduction paper that may help people to start writing there own rules [here](https://www.openshift.com/blog/seccomp-for-fun-and-profit and Yadutaf some nice basic sample on his blob [here](https://blog.yadutaf.fr/2014/05/29/introduction-to-seccomp-bpf-linux-syscall-filter/).

* **default**: defines default seccomp action for any non defined rules. Options are: SCMP_ACT_ALLOW, SCMP_ACT_KILL_PROCESS, SMP_ACT_KILL_THREAD, SCMP_ACT_KILL, SCMP_ACT_TRAP, SCMP_ACT_LOG, SCMP_ACT_ALLOW, SCMP_ACT_NOTIFY depending on your system some option as SCMP_ACT_NOTIFY might not be available. ***Warning**: setting default to SCMP_ACT_KILL will impose you to declare every 'syscall' you authorize.*
* **locked**: when true this flash will set two extra options:
  * PR_SET_NO_NEW_PRIVS prevent children to request or inherit from from file sticky bit or capabilities extra permissions
  * PR_SET_DUMPABLE prevent children from activating ptrace escape
* **rules**: a json array defining basic *seccomp* rules with the form   {"syscall": "syscall_name", "action": "SCMP_ACT_XXX"}
* **rulespath**: path top your BPF compiled rules. Note than when using a sandbox this file is apply only after unshare namespace are established, when previous rules applies before.

#### Namespace (unprivileged rootless container)

```json
  "namespace" : {
    "opts": {
      "autocreate": true
    },
    "shares": {
      "all": "default",
      "users":"disable",
      "net": "enable"
    },
    "mounts": [
      {"target": "/etc/passwd", "mode":"execfd", "source": "getent passwd $SBOXUSER 65534"},
      {"target": "/home", "source": "/var/tmp/$SANDBOX", "mode": "rw"},
      {"target": "/usr",  "source": "/usr", "mode": "ro"},
      {"target": "/sbin", "source": "/usr/sbin", "mode": "symlink"},
      {"target": "/tmp", "mode": "tmpfs"},
    ]
  }
```

Namespace allows to restrict children visibility to the filesystem by executing the process within a private namespace. Note than every children get a private namespace container at execution time, this even when they are configured under the same sandbox umbrella within config.json. Technically namespace relies on Linux kernel 'unshare'

* **opts** allows to defined generic namespace behavior.
  * **autocreate**: try to create source mount point when they does not exist. If mountpath does not exist and creation fail, afb-oidc-ext will refuse to start.
  * **hostname**: change namespace hostname when UTS is unshare
  * **bwrap**: specify a custom brwap file

* **shares**: defines what existing namespace you import from afb-oidc-ext to forked children.  Shares support 'default','disable','enable' tags. Default depend on the hosting environment but generally match with 'enable'.
  * **all**: set all following namespaces.
  * **users**: allow or not access to core userspace. When 'disable' children visible UID/GID do not match with hosting environment. *Note that in order to simplify developer live afb-oidc-ext will set a 'fake' uid/gid matching with the one define with namespace->acls.*
  * **cgroup**: when 'disable' children see a new empty cgroup. This even if previously defined cgroups still apply.
  * **net**: remove network visibility. When 'disable' the only remaining available network is 'localhost'. This mode allows the children to exchange with the hosting environment, while preventing them from accessing the Internet.
  * **ipc**: equivalent to 'net' restriction but for Linux 'ipc' mgsset/get system call.

* **mounts**: define mounted entry points to add into children containers. The goal is to provide the minimal set of resources necessary for the execution of a given children. ***Warning**: too many restrictions may prevent children from starting. This scenario might be harder than expected to debug.*

  * **target**: this label is mandatory it define the mount point inside your container namespace as view by children processes.
  * **source**: this is an optional entry point that defines the path within your hosting environment that you wish to import. When undefined source==target, which respond to the situation where you want the same path inside and outside of the container : /usr,/lib64,... When used source path is check at configuration time. If source does not exist and 'autocreate' is set, the afb-oidc-ext will try to create the mounting point on the hosting environment. When source does not exist or cannot be created afb-oidc-ext refuses to start.

  * **mode**: specify the type of mount to use:
    * **rw/ro** or 'read'/'write' is used to mount directory in either read-only or read-write.
    * **symlink** does not really mount a resource, but create a symbolic link within container after its creation. For example {"target": "/sbin", source "/usr/sbin", "mode": "symlink"} will create a legacy link for applications that require and access to /sbin.
    * **dir** create a directory on children namespace. Depending on where this directory is created, it may remain after children terminate, or be shared in between children.
    * **tmpfs** create a temporally filesystem visible only from within this children container. Note that 'tmpfs' entry point are not share in between children of a given sandbox.
    * **dev**: mount a empty '/dev' file system. When children have corresponding rights they may later mount specific devices.
    * **procfs**: idem 'dev' but for '/proc'
    * **mqueue**: idem 'dev' but for '/dev/mqueue'
    * **devfs** : idem 'dev' but for '/dev'

## Commands

```json
  commands": [
    {
      "uid": "dir",
      "info" : "list directory files",
      "usage": {"dirname": "...dirpath..."},
      "exec": {"cmdpath": "/bin/ls", "args": ["-l", "%dirname%"]},
      "encoder": {"output": "document", "opts": {"maxlen":1024}}
      "samples": [
        {"args": {"dirname": "/etc"}},
        {"args": {"dirname": "/etc/udev"}},
      ]
    }
```

This section exposes for a given sandbox children commands. Command only requires 'uid' and 'exec' label any other one are optionals.

* **uid** is required to build command API/verb under the form 'sandbox-prefix/cmd-uid. Note that if sandbox-prefix="" (not undefined) then cmd api use a flat namespace with API/verb compose only of commands uid independently of its umbrella sandbox. *Note: is is a good behavior to prefix command api/verb with a sandbox prefix/uid.*

* **exec**

  * **cmdpath**: full command file path to execute (no search path allowed). afb-oidc-ext check at startup time that exec file is executable by the hosting environnement. Nevertheless it cannot assert that it will still be executable after applying sandbox restrictions.
  * **args** : a unique or array of arguments. Arguments can be expandable either at config time with '$NAME' or at query time with '%pattern%'. ***Warning**: argument expansion at query time is case sensitive.*
    * **$NAME** : config time expansion. On top of traditional environment variables afb-oidc-ext support few extra builtin expansion: $SANDBOX, $COMMAND, $APINAME, $PID, $UID, $GID, $TODAY, $UUID.
    * **%name%***  those patterns are expanded at command launching time. By searching within query args json_object corresponding key. For example if your command line used '"exec": {"cmdpath": "/bin/sleep", "args": ["%timeout%"]}' then a query with '{"action":"start", "args": {"timeout": "180"}}' will fork/exec 'sleep 180'.

* **verbose**: overload sandbox verbosity level. ***Warning** verbosity [5-9] are reserve to internal code debugging. With verbosity=5, query arguments expansion happen in main process and not in child to help 'gdb' debugging, nevertheless in this case any expansion error may kill the server.*
* **timeout**: overload sandbox timeout. (note zero == no-timeout)
* **info**: describes command function. Is return as part of 'api/info' introspection.
* **usage**: is used to populate HTML5 help query area.
* **encoder**: specify with output encoder should be used. When not used default 'document' encoder is used. afb-oidc-ext provides 3 builtin encoders, nevertheless developer may add custom output formatting with encoder plugins. *Note: check plugin directory on github for a custom encoder sample.*

  * **text**: returns a json_array for both stdout/stderr at the end of command execution. Supports 'maxlen' & 'maxline' options.
  * **line**: returns a json_string even each time a new line appear on stdout. Stderr keeps 'document' behavior.
  * **json**: returns an event each time a new json blob is produce on stdout. Stderr keeps 'document' behavior.
  * **log**: push log in corresponding file default server side sdtdout/err. When output not defined default afb-binder stdout/err is used.
  * **xxxx**: where 'xxxx' is the 'uid' you gave to your plugin custom encoder options.

  * Example of encoders accepting*
```json
        "encoder": {"output": "json", "opts": {"maxlen":1024}},
        "encoder": {"output": "log", "opts":{"stdout":"/tmp/afb-$AFB_NAME-$SANDBOX_UID-$COMMAND_UID.out", "stderr":"/tmp/afb-$AFB_NAME-$SANDBOX_UID-$COMMAND_UID.err", "maxlen":1024}}.
```

* **samples**: this is an optional label used return when 'api/info' verb is called to automatically built HTML5 testing page. No check is done on 'sample' which allow to provision test that should fail.

```json
          "samples": [
            {"args": {"dirname": "/etc"}},
            {"args": {"dirname": "/etc/udev"}},
            {"args": {"dirname": "/var/cache/"}}
          ]
```

## API usage

each command create a standard api/verb that can be requested by all AFB transport by default: REST/WebSocket/UnixDomain

**Websocket Query**

```bash
ws://localhost:1234/api/simple/sandbox-simple/distro?query={"action":"start"}
```

**Event Response**

```json
{
  "jtype": "afb-event",
  "event": "simple/sandbox-simple/distro@12858",
  "data": {
    "cmd": "distro",
    "pid": 12858,
    "status": {
      "exit": 0
    },
    "stdout": [
      "LSB Version:\tn/a",
      "Distributor ID:\topenSUSE",
      "Description:\topenSUSE Leap 15.2",
      "Release:\t15.2",
      "Codename:\tn/a"
    ]
  }
}
```

### Two builtin api/verb

* api://oidc/ping // assert binder is alive
* api://oidc/info // return parsed config to automatically build HTML5 debug/test page [binder-devtool]({% chapter_link monitoring-doc.binder-devtool %})

*Note: In following samples 'oidc' should be replaced by what ever you chose as API name in your config.json.*

### One api/verb/privilege per command

Each command may define its own required privileges (Linux SeLinux/Smack & Cynara privileges). Optional arguments depend on chosen action.

* **action**:
```json
    query={"action":"start"}
```
  default (action: 'start')
  * **start**: create a new container for targeted command with arguments and security model.
  * **stop**: stop all or specified task previously started
  * **subscribe**: request subscription to the output of a given command. *Note: by default any client starting an action automatically subscribe the its output.*
  * **unsubscribe**: force unsubscribe to output events of a given command.

* **args**:
```json
    query={"args":{"filename":"/etc/passwd"}}
```

  Dynamic argument provided by the client to be used at children launching time. Args is a json-array that SHOULD match with config command exec/args definition. Each argument contain within this array is check again %pattern% used within command definition. If a label is missing then command is not started. 'verbose' is an extra builtin label that allows to over load command or sandbox verbosity level.

 ```json
 Example: {"args":{"filename":"/etc/passwd"}, "verbose":1}
 ```

### Api Response

afb-oidc-ext send an OK/FX response when launching the command *(equivalent to '&' background launch in bash)*. Response returns task pid and other misc information.

```json
{
  "jtype": "afb-reply",
  "request": {
    "status": "success"
  },
  "response": {
    "api": "oidc",
    "sandbox": "sandbox-simple",
    "command": "display",
    "pid": 22131
  }
}
```

Children oidc task output always come back as events. The model depend on chosen encoder. Default one returns stdout+stderr with closing status at the end of children execution.

```json
{
  "jtype": "afb-event",
  "event": "oidc/sandbox-simple/display@22131",
  "data": {
    "cmd": "display",
    "pid": 22131,
    "status": {
      "exit": 0
    },
    "stdout": [
      "avahi:x:468:472:User for Avahi:/run/avahi-daemon:/bin/false",
      "bin:x:1:1:bin:/bin:/sbin/nologin",
      "chrony:x:479:479:Chrony Daemon:/var/lib/chrony:/bin/false",
      "daemon:x:2:2:Daemon:/sbin:/sbin/nologin",
      "...",
      "fulup:x:1000:100:Fulup Ar Foll:/home/fulup:/bin/bash",
    ]
  }
}
}
```

## Activating cgroup-v2

While recent OpenSuse, Ubuntu or Debian support cgroups-v2 by default they only activate compatibility mode. In this mode cgroup controller use in V1 cannot be use in V2 and vice versa. As afb-oidc-ext request all controller in V2, compatibility mode is not really useful and you should move all control to V2. The good news is that when rebooting systemd, lxc, docker,... notice the change and commute automatically to full V2 mode. Except is you have custom applications that support only V1 mode the shift to V2 should be fully transparent.

### Fedora & Redpesk

Cgroup-v2 activated by default for all controllers.

### OpenSuse

* add to /etc/default/grub the two following parameters
```bash
  sudo vi /etc/default/grub
    - change => GRUB_CMDLINE_LINUX_DEFAULT="resume=/dev/disk/by-label/swap splash=silent quiet showopts"
    - to => GRUB_CMDLINE_LINUX_DEFAULT="resume=/dev/disk/by-label/swap splash=silent quiet showopts systemd.unified_cgroup_hierarchy=1 cgroup=no_v1=all"

  sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

### Ubuntu

* update grub & reboot
```bash
  sudo vi /etc/default/grub
    - change => GRUB_CMDLINE_LINUX_DEFAULT=""
    - to => GRUB_CMDLINE_LINUX_DEFAULT="systemd.unified_cgroup_hierarchy=1 cgroup=no_v1=all"

  sudo update-grub
```
