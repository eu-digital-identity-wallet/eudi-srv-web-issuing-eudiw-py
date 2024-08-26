
----

# NOTICE

:heavy_exclamation_mark: This is a development version provided for the POTENTIAL LSP hackathon in Dresden.

Changes in the configuration process:

+ You must copy your IACA trusted certificate(s) (in PEM format) to the trusted_CAs_path folder - you can use the [example test IACA certificate for country Utopia (UT)](api_docs/test_tokens/IACA-token/PIDIssuerCAUThackathon.cacert.pem) -.

+ You can use the [example test private DS keys and certificates, for country Utopia (UT)](api_docs/test_tokens/DS-token/PID-DS-hackathon.zip) - the password of the example test private DS keys is b"123456".

----

# EUDIW Issuer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)


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


## :heavy_exclamation_mark: Disclaimer

The released software is a initial development release version:

-   The initial development release is an early endeavor reflecting the efforts of a short timeboxed
    period, and by no means can be considered as the final product.
-   The initial development release may be changed substantially over time, might introduce new
    features but also may change or remove existing ones, potentially breaking compatibility with your
    existing code.
-   The initial development release is limited in functional scope.
-   The initial development release may contain errors or design flaws and other problems that could
    cause system or other failures and data loss.
-   The initial development release has reduced security, privacy, availability, and reliability
    standards relative to future releases. This could make the software slower, less reliable, or more
    vulnerable to attacks than mature software.
-   The initial development release is not yet comprehensively documented.
-   Users of the software must perform sufficient engineering and additional testing in order to
    properly evaluate their application and determine whether any of the open-sourced components is
    suitable for use in that application.
-   We strongly recommend not putting this version of the software into production use.
-   Only the latest version of the software will be supported


## 1. Installation

Pre-requisites:

+ Python v. 3.9 or 3.10
+ Flask v. 2.3 or higher

Click [here](install.md) for detailed installation instructions.


## 2. Run

Click [here](install.md) for detailed instructions.

## 3. Frequently Asked Questions

### A. How to make your local EUDIW Issuer available on the Internet?

Please see detailed instructions in [install.md](install.md#4-make-your-local-eudiw-issuer-available-on-the-internet-optional).

### B. How to add a new credential to the issuer ?

Please see detailed instructions in [api_docs/add_credential.md](api_docs/add_credential.md).

### C. Can I use my IACA certificate with the EUDIW Issuer?

Yes. You must copy your IACA trusted certificate(s) (in PEM format) to the `trusted_CAs_path` folder. If you don't have an IACA certificate, we provide an example test IACA certificate for the country Utopia (UT).

See more information in [api_docs/configuration.md](api_docs/configuration.md#1-service-configuration).

### D. Can I use my Document Signer private key and certificate with the EUDIW Issuer?

Yes. Please follow the instructions in [api_docs/configuration.md](api_docs/configuration.md#2-configuration-of-countries). If you don't have Document Signer private key and certificate, we provide  test private DS keys and certificates, for country Utopia (UT).

### E. How can I create a credential offer to issue a credential?

Please see detailed instructions in [api_docs/credential_offer.md](api_docs/credential_offer.md).

### F. Can I test the pre-authorized flow?

Yes. Please see how in [api_docs/pre-authorized.md](api_docs/pre-authorized.md).

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
