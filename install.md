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


5. Install Flask, gunicorn and other dependencies in virtual environment

    ```shell
    pip install -r app/requirements.txt
    ```

    Note: The original pyMDOC-CBOR library will be forked into the eu-digital-identity-wallet repo (and the modifications will be applied), when it is made public, since a public repo cannot be forket into a private repo.

6. Setup secrets
   
   -  Copy ```/app/app_config/__config_secrets.py``` to ```/app/app_config/config_secrets.py``` and modify secrets.

8. Run the eudiw-issuer application (on <http://127.0.0.1:5000>)

    ```shell
    flask --app app run
    ```
