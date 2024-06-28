# EUDIW Issuer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)


### Overview

The EUDIW Issuer is an implementation of  the PID and (Q)EAA Provider service, supporting the OpenId4VCI (draft 13) protocol.

The service provides, by default, support for `mso_mdoc` and `SD-JWT-VC`formats, for the following credentials:


| Credential/Attestation | Format    |
|------------------------|-----------|
| PID                    | mso_mdoc  |
| PID                    | SD-JWT-VC |
| mDL                    | mso_mdoc  | 
| mDL                    | SD-JWT-VC  | 
| (Q)EAA age-over-18 pseudonym | mso_mdoc |
| (Q)EAA loyalty card | mso_mdoc |

For authenticating the user, it requires the use of eIDAS node, OAUTH2 server or a simple form (for testing purposes).


### OpenId4VCI coverage

This version of the EUDIW Issuer supports the [OpenId for Verifiable Credential Issuance (draft 13)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) protocol with the following coverage:


| Feature                                                   | Coverage                                                        |
|-------------------------------------------------------------------|-----------------------------------------------------------------|
| [Authorization Code flow](api_docs/authorization.md)              | ✅ Support for PAR, PKCE, credential configuration id, scope    |
| [Pre-authorized code flow](api_docs/pre-authorized.md)            | ✅                                                              |
| Dynamic Credential Request                                        | ✅                                                              |
| mso_mdoc format                                                   | ✅                                                              |
| SD-JWT-VC format                                                  | ✅                                                              |
| W3C VC DM                                                         | ❌                                                              |
| [Token Endpoint](api_docs/token.md)                               | ✅                                                              |
| [Credential Offer](api_docs/credential_offer.md)                  | ✅ `authorization_code` , ✅ `pre-authorized_code`              |
| [Credential Endpoint](api_docs/credential.md)                     | ✅ Including proofs and repeatable invocations                  |
| Credential Issuer MetaData                                        | ✅                                                              | 
| [Batch Endpoint](api_docs/batch_credential.md)                     | ✅                                                              | 
| [Deferred Endpoint](api_docs/deferred.md)                         | ✅                                                              |
| Proof                                                             | ✅ JWT, ✅ CWT                                                  |
| [Notification Endpoint](api_docs/notification.md)                 | ✅                                                              |


You can use the EUDIW Issuer at https://issuer.eudiw.dev/, or install it locally.

## 1. Installation

Pre-requisites:

+ Python v. 3.10 or higher
+ Flask v. 2.3 or higher

Click [here](install.md) for detailed installation instructions.


## 2. Run

Click [here](install.md) for detailed instructions.


## How to add a new credential to the issuer ?

Please see detailed instructions in [api_docs/add_credential.md](api_docs/add_credential.md) 

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
