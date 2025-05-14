# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
The PID Issuer Web service is a component of the PID Provider backend. 
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This __init__.py serves double duty: it will contain the application factory, and it tells Python that the flask directory should be treated as a package.
"""

import copy
import json
import os
import sys

sys.path.append(os.path.dirname(__file__))

from flask import Flask, render_template, request, send_from_directory
from flask_session import Session
from flask_cors import CORS
from werkzeug.debug import *
from werkzeug.exceptions import HTTPException
from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server import Server
from urllib.parse import urlparse
from pycose.keys import EC2Key

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from app_config.config_service import ConfService as cfgserv


# Log
from .app_config.config_service import ConfService as log


oidc_metadata = {}
oidc_metadata_clean = {}
openid_metadata = {}
oauth_metadata = {}
trusted_CAs = {}


def remove_keys(obj, keys_to_remove):
    if isinstance(obj, dict):
        new_obj = {
            k: remove_keys(v, keys_to_remove)
            for k, v in obj.items()
            if k not in keys_to_remove
        }
        return new_obj if new_obj else None
    elif isinstance(obj, list):
        new_list = [remove_keys(item, keys_to_remove) for item in obj]
        new_list = [item for item in new_list if item is not None]
        return new_list if new_list else None
    else:
        return obj
    
def setup_metadata():
    global oidc_metadata
    global oidc_metadata_clean
    global openid_metadata
    global oauth_metadata

    try:
        credentials_supported = {}
        dir_path = os.path.dirname(os.path.realpath(__file__))

        with open(
            dir_path + "/metadata_config/openid-configuration.json"
        ) as openid_metadata:
            openid_metadata = json.load(openid_metadata)

        with open(
            dir_path + "/metadata_config/oauth-authorization-server.json"
        ) as oauth_metadata:
            oauth_metadata = json.load(oauth_metadata)

        with open(dir_path + "/metadata_config/metadata_config.json") as metadata:
            oidc_metadata = json.load(metadata)
            oidc_metadata_clean = copy.deepcopy(oidc_metadata)

        for file in os.listdir(dir_path + "/metadata_config/credentials_supported/"):
            if file.endswith("json"):
                json_path = os.path.join(
                    dir_path + "/metadata_config/credentials_supported/", file
                )
                with open(json_path, encoding="utf-8") as json_file:
                    credential = json.load(json_file)
                    credentials_supported.update(credential)

    except FileNotFoundError as e:
        cfgserv.app_logger.exception(f"Metadata Error: file not found. \n{e}")
    except json.JSONDecodeError as e:
        cfgserv.app_logger.exception(
            f"Metadata Error: Metadata Unable to decode JSON. \n{e}"
        )
    except Exception as e:
        cfgserv.app_logger.exception(
            f"Metadata Error: An unexpected error occurred. \n{e}"
        )

    oidc_metadata["credential_configurations_supported"] = credentials_supported

    
    oidc_metadata_clean["credential_configurations_supported"] = remove_keys(copy.deepcopy(credentials_supported),{"issuer_conditions", "issuer_config", "overall_issuer_conditions"})


setup_metadata()

def setup_trusted_CAs():
    global trusted_CAs

    try:
        ec_keys = {}
        for file in os.listdir(cfgserv.trusted_CAs_path):
            if file.endswith("pem"):
                CA_path = os.path.join(cfgserv.trusted_CAs_path, file)

                with open(CA_path) as pem_file:

                    pem_data = pem_file.read()

                    pem_data = pem_data.encode()

                    certificate = x509.load_pem_x509_certificate(
                        pem_data, default_backend()
                    )

                    public_key = certificate.public_key()

                    issuer = certificate.issuer

                    not_valid_before = certificate.not_valid_before

                    not_valid_after = certificate.not_valid_after

                    x = public_key.public_numbers().x.to_bytes(
                        (public_key.public_numbers().x.bit_length() + 7)
                        // 8,  # Number of bytes needed
                        "big",  # Byte order
                    )

                    y = public_key.public_numbers().y.to_bytes(
                        (public_key.public_numbers().y.bit_length() + 7)
                        // 8,  # Number of bytes needed
                        "big",  # Byte order
                    )

                    ec_key = EC2Key(
                        x=x, y=y, crv=1
                    )  # SECP256R1 curve is equivalent to P-256

                    ec_keys.update(
                        {
                            issuer: {
                                "certificate": certificate,
                                "public_key": public_key,
                                "not_valid_before": not_valid_before,
                                "not_valid_after": not_valid_after,
                                "ec_key": ec_key,
                            }
                        }
                    )

    except FileNotFoundError as e:
        cfgserv.app_logger.exception(f"TrustedCA Error: file not found.\n {e}")
    except json.JSONDecodeError as e:
        cfgserv.app_logger.exception(
            f"TrustedCA Error: Metadata Unable to decode JSON.\n {e}"
        )
    except Exception as e:
        cfgserv.app_logger.exception(
            f"TrustedCA Error: An unexpected error occurred.\n {e}"
        )

    trusted_CAs = ec_keys


setup_trusted_CAs()


def handle_exception(e):
    # pass through HTTP errors
    if isinstance(e, HTTPException):
        return e
    cfgserv.app_logger.exception("- WARN - Error 500")
    # now you're handling non-HTTP exceptions only
    return (
        render_template(
            "misc/500.html",
            error="Sorry, an internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            error_code="Internal Server Error",
        ),
        500,
    )


def page_not_found(e):
    cfgserv.app_logger.exception("- WARN - Error 404")
    return (
        render_template(
            "misc/500.html",
            error_code="Page not found",
            error="Page not found.We're sorry, we couldn't find the page you requested.",
        ),
        404,
    )


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    @app.route("/", methods=["GET"])
    def initial_page():
        return render_template(
            "misc/initial_page.html", oidc=cfgserv.oidc, service_url=cfgserv.service_url
        )

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory("static/images", "favicon.ico")

    @app.route("/ic-logo.png")
    def logo():
        return send_from_directory("static/images", "ic-logo.png")

    app.config.from_mapping(SECRET_KEY="dev")

    if test_config is None:
        # load the instance config (in instance directory), if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    # @app.route('/hello')
    # def hello():
    #    return 'Hello, World!'

    # register blueprint for the /pid route
    from . import (
        route_eidasnode,
        route_formatter,
        route_oidc,
        route_dynamic,
        route_oid4vp,
        preauthorization,
        revocation
    )

    app.register_blueprint(route_eidasnode.eidasnode)
    app.register_blueprint(route_formatter.formatter)
    app.register_blueprint(route_oidc.oidc)
    app.register_blueprint(revocation.revocation)
    app.register_blueprint(route_oid4vp.oid4vp)
    app.register_blueprint(route_dynamic.dynamic)
    app.register_blueprint(preauthorization.preauth)

    # config session
    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # CORS is a mechanism implemented by browsers to block requests from domains other than the server's one.
    CORS(app, supports_credentials=True)

    cfgserv.app_logger.info(" - DEBUG - FLASK started")

    dir_path = os.path.dirname(os.path.realpath(__file__))

    config = create_from_config_file(
        Configuration,
        entity_conf=[
            {"class": OPConfiguration, "attr": "op", "path": ["op", "server_info"]}
        ],
        filename=dir_path + "/app_config/oid_config.py",
        base_path=dir_path,
    )

    app.srv_config = config.op

    server = Server(config.op, cwd=dir_path)

    for endp in server.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split("/")
        if _vpath[0] == "":
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    app.server = server

    return app


#
# Usage examples:
# flask --app app run --debug
# flask --app app run --debug --cert=app/certs/certHttps.pem --key=app/certs/key.pem --host=127.0.0.1 --port=4430
#
