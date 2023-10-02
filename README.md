# EUDIW issuer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

The EUDIW issuer implements the PID and mDL provider backend and includes the functionalities of the following components:


| Component |    API  Documentation      |
|----------|-------------|
| PID issuer | [API](api_docs/pid_issuer.md) |
| mDL issuer |  |
| CBOR Formatter | [API](api_docs/cbor_formatter.md)  |
| SD-JWT VC Formatter |  |


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
