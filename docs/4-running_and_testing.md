## Running/Testing

sec-gate-oidc is an afb-binder-v4 extension and cannot work work with afb-binder-v3. Check with 'afb-binder --version' that your version >= 4.0.0

### Requirements

* you should have a valid afb-binder install.
* you should write or copy a sample oidc-config.json
* you should known the path to:

  * 'sec-gate-oidc.extso' extention
  * 'fedid-binding.so' binding
  * 'libfedid-types.so' type converters

* you need a test client
  * oidc-sgate basic HTML/JS testing pages.
  * afb-oidc-webui for one-page HTML Angular 

If you run redpesk simply install the package with `dnf install sec-gate-oidc` for other platform check redpesk [developer guide]({% chapter_link host-configuration-doc.setup-your-build-host %})



## Run sec-gate-oidc samples

Fulup TBD (depend on default binary package installation path)