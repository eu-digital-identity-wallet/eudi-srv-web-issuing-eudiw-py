# Installation

## 1. Python

The eudiw-issuer application was tested with

+ Python version 3.10.8

and should only be used with Python 3.10 or higher.

If you don't have it installed, please downlod it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. Flask

The eudiw-issuer application was tested with

+ Flask v. 2.3

and should only be used with Flask v. 2.3 or higher.

To install [Flask](https://flask.palletsprojects.com/en/2.3.x/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/2.3.x/installation/).

## 3. eudiw-issuer application

To run the eudiw-issuer application, follow these simple steps (some of which may have already been completed when installing Flask) for Linux/macOS or Windows.


1. Clone the eudiw-issuer repository:

    ```shell
    git clone <repository>
    ```

2. Create a `.venv` folder within the cloned repository:

    ```shell
    cd eudiw-issuer
    python3 -m venv .venv
    ```

3. Activate the environment:

   Linux/macOS

    ```shell
    . .venv/bin/activate
    ```

    Windows

    ```shell
    . .venv\Scripts\Activate
    ```


1. Install or upgrade _pip_

    ```shell
    python -m pip install --upgrade pip
    ```


5. Install Flask in virtual environment

    ```shell
    pip install Flask-Cors requests jwt cbor2 pytz flask pyignite tinyec pycryptodome  config flask_api cbor_diag validators Flask-Session jsonschema
    ```

6. Install other dependencies

    ```shell
    pip install git+https://github.com/devisefutures/pyMDOC-CBOR.git@cert_arg
    pip install git+https://github.com/openwallet-foundation-labs/sd-jwt-python.git
    ```

7. Run the eudiw-issuer application (on <http://127.0.0.1:5000>)

    ```shell
    flask --app app run
    ```
