# EUDIW issuer

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)


The EUDIW issuer implements the PID and mDL provider backend (as defined in the issuing-mdl and issuing-pid repositories) and includes the functionalities of the following components:


| Component |    API  Documentation      |
|----------|-------------|
| PID/mDL OID4VCI with dynamic registration | [API](api_docs/pid_oidc_auth.md) |
| PID/mDL OID4VCI without dynamic registration | [API](api_docs/pid_oidc_no_auth.md) |
| CBOR Formatter | [API](api_docs/cbor_formatter.md)  |
| SD-JWT VC Formatter |  |
| Document Signer |  |


## 1. Installation

Pre-requisites:

+ Python v. 3.10 or higher
+ Flask v. 2.3 or higher

Click [here](install.md) for detailed installation instructions.


## 2. Run

After installation, on the root directory of the clone repository, insert the following command line to run the eudiw-issuer application.
Examples:

+ Linux/macOS/Windows (on <http://127.0.0.1:5000>)

    ```
    flask --app app run
    ```

+ Linux/macOS/Windows (on <http://127.0.0.1:5000> with flag debug)

    ```
    flask --app app run --debug
    ```

+ Linux/macOS/Windows (on <http://127.0.0.1:4430> with flag debug, using ssl and defining the port)

    ```
    flask --app app run --debug --cert=app/certs/certHttps.pem --key=app/certs/key.pem --host=127.0.0.1 --port=4430
    ```


-----

## Disclaimer

The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported


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
