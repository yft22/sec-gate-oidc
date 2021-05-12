## Running/Testing

afb-oidc-sgate is an afb-binder-v4 extension and cannot work work with afb-binder-v3. Check with 'afb-binder --version' that your version >= 4.0.0

### Requirements

* you should have a valid afb-binder install.
* you should write or copy a sample oidc-config.json
* you should known the path to:

  * 'afb-oidc-sgate.extso' extention
  * 'fedid-binding.so' binding
  * 'libfedid-types.so' type converters

* you need a test client
  * oidc-sgate basic HTML/JS testing pages.
  * afb-oidc-webui for one-page HTML Angular

If you run redpesk simply install the package with `dnf install afb-oidc-sgate` for other platform check redpesk [developer guide]({% chapter_link host-configuration-doc.setup-your-build-host %})



## Run afb-oidc-sgate samples

Fulup TBD (depend on default binary package installation path)

## testing JWT signature

### raw form (url64 encoded)

* header: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkpSY080bnhzNWpnYzhZZE43STJoTE80Vl9xbDFiZG9pTVhtY1lnSG00SHMifQ

* body: eyJzdWIiOiIxMzMzODI4NzciLCJlbWFpbCI6ImZ1bHVwQGlvdC5iemgiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJmdWx1cEBpb3QuYnpoIiwibmFtZSI6IkZ1bHVwIEFyIEZvbGwiLCJ1cGRhdGVkX2F0IjoxNjIwODE0NjkzLCJnaXZlbl9uYW1lIjoiRnVsdXAiLCJmYW1pbHlfbmFtZSI6IkFyIEZvbGwiLCJub25jZSI6IjBhMWEyMjllLTIyMmMtNDdiYi1iMTJmLTUzYmE2M2Q4MjI5ZiIsImF0X2hhc2giOiJkbzhUTmY2Q1JiWVA0RTZaTzV6YVB3Iiwic2lkIjoiYjkwYWMxMDctMGM5OC00MzliLWI5MTUtNmI2YTI2MTBjZTkyIiwiYXVkIjoiMTE5OGNlODAtOTE4Ny0wMTM5LTZkODMtMDZkMTRlMjkzMjExMTg5Njc2IiwiZXhwIjoxNjIwODIyNjk3LCJpYXQiOjE2MjA4MTU0OTcsImlzcyI6Imh0dHBzOi8vaW90LWJ6aC1kZXYub25lbG9naW4uY29tL29pZGMvMiJ9

* sign: HYdCZ4LLj_B2oUbtRngrO_b88pta6DPlHqATkMLScpO6W5wHeB8CDP8XfG5qhrK2Gm_3IyPoxzanshif5ruypkwHjHknG0tY-NgvVv_bovC0VSpT_pmhtBP6_2mLwjpKEpFBXrXK1263eYL7eURfBrFXgDRENlYGSahWwGl508Szfh1Y0XNcU6CXcnF-lvXi1N1-ZzVesxD7rw-LB9ghjm8lmAiQD7baOzmJzJAR21Ttw3B0qGln9z4LdomocOKlK7grEFGrBbVJ2SxLmt2EdS-Q2BsmojaC6ukqesP_spxHXdmH4Rcw-h1ORaU9Y1PQ5ShnleebbcIAzW2Wnb_i4A


### url64 decode

* header: {"alg":"RS256","typ":"JWT","kid":"JRcO4nxs5jgc8YdN7I2hLO4V_ql1bdoiMXmcYgHm4Hs"}

* body: {"sub":"133382877","email":"fulup@iot.bzh","preferred_username":"fulup@iot.bzh","name":"Fulup Ar Foll","updated_at":1620814693,"given_name":"Fulup","family_name":"Ar Foll","nonce":"0a1a229e-222c-47bb-b12f-53ba63d8229f","at_hash":"do8TNf6CRbYP4E6ZO5zaPw","sid":"b90ac107-0c98-439b-b915-6b6a2610ce92","aud":"1198ce80-9187-0139-6d83-06d14e293211189676","exp":1620822697,"iat":1620815497,"iss":"https://iot-bzh-dev.onelogin.com/oidc/2"}

*sign: