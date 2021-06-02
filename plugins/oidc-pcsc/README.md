# PCSC NFC Quick start IDP configuration

oidc-pcsc somehow fakes sgate openid-connect handshake. It relies on pcscd-client library and pcscd daemon to access nfc tokens/smartcards. 

Note: pcsc is implemented as an external plugin and released under MIT licence. Reference implementation relies on:

* Mifare-classic NFC scard and you probably should hack the code to interface any other token/scard.
* CCID ACR122U NFC reader. Chaging for an other CCID reader should hopefully only requirer configuration change. Changing for a non supported reader more or less impose to fully rewrite oidc-pcsc. 

## 1- provision your card

Except if you only use token/scard UUID within a slave profile you should provision your token/scard with adequate datas. If you need a provision tool check pscd-client (here)[/xxxxx]

## 2- configure your plugin

oidc-pscd is loaded at run time and you should provide plugin path+name in order sgate to find it. Note that if */etc/ld.so.conf.d/* or *LD_LIBRARY_PATH* are correctly configured you should not have to provide plugin fullpath within your config.

```json
    "uid": "nfc-scard",
    "type": "pcsc",
    "info": "NFC Mifare/Classic smartcard authentication (check ",
    "plugin": {
        "ldpath": "libidp-sgate-pcscd-auth.so",
        "config": {
        ....    
```

Complete your configuration:
* check pcsc-client configuration for NFC/scard command and key definition.
* other part of the config static,wellknown,profile... are common to any other idps.

## 3- mapping scard attributes as sgate security attributes

In order to map openid and security attributes to data store in token/scard with map pscsd command 'uid' onto scope or attributes security labels.

In following example 'fedid','pseudo',... should map on valid pcsc commands as describe into later full config sample.

```json
"profiles": [
    {"uid":"linked","loa":1, "scope":"fedid", "slave":true},
    {"uid":"admin", "loa":2, "scope":"fedid,pseudo,name,email,company", "attrs":"roles,apps"}
    ]
```

Note: 
* token/scard have multiple constrains and limitation. Mifare-classic usefull data within a sector is 48bytes which constrains attributes maximum length. 
* slave profile cannot register a new user. In previous 'linked' profile config sample, either token/scard UUID should be pre-provision or user should double authenticate and prove its identity with second authority, as it is typically the case with second factor authentication. 

## 4 Minimalist pcsc full config.

A minimalist configuration may look like following one. Check for config chapter for full config options.

```json
{
    "uid": "nfc-scard",
    "type": "pcsc",
    "info": "NFC Mifare/Classic smartcard authentication (check ",
    "plugin": {
        "ldpath": "libidp-sgate-pcscd-auth.so",
        "config":     {
            "info" : "Mifare/Classic command samples",
            "reader": "acr122",
            "keys": [
                {"uid":"key-a", "idx": 0, "value":["0x01","0x02","0x03","0x04","0x05","0x06"]},
                {"uid":"key-b", "idx": 1, "value":["0x0A","0x0B","0x0C","0x0D","0x0E","0x0F"]}      
            ],
            "cmds": [ 
                // card should be pre-provision with right keys/acls (pcsc-client --help)          
                {"uid":"fedid"   , "action":"uuid"},
                {"uid":"pseudo"  , "action":"read","sec": 1, "key":"key-a", "len":48},
                {"uid":"email"   , "action":"read","sec": 2, "key":"key-a", "len":48},
                {"uid":"name"    , "action":"read","sec": 3, "key":"key-a", "len":48},
                {"uid":"company" , "action":"read","sec": 4, "key":"key-a", "len":48},
                {"uid":"roles"   , "action":"read","sec": 5, "key":"key-a", "len":48},
                {"uid":"apps"    , "action":"read","sec": 6, "key":"key-a", "len":48}
            ]
        }
    },
    "statics": {
        "login": "/sgate/nfc-auth/login",
        "logo": "/sgate/nfc-auth/logo-64px.png",
        "timeout": 900
    },
    "wellknown": {
        "tokenid": "/sgate/nfc-auth/login.html"
    },
    "profiles": [
        {"uid":"linked","loa":1, "scope":"fedid", "slave":true},
        {"uid":"admin", "loa":2, "scope":"fedid,pseudo,name,email,company", "attrs":"roles,apps"}
    ]
}
```