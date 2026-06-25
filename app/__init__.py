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
import logging

from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

import yaml
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_from_directory, session, jsonify
from flask_cors import CORS
from flask_session import Session
from werkzeug.exceptions import HTTPException

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from pycose.keys.ec2 import EC2Key

from app.session_manager import SessionManager
from app.redirect_func import post_redirect_with_payload
from app.app_config.logging_config import configure_logging



# Load environment variables
load_dotenv()

# Allow local imports
sys.path.append(os.path.dirname(__file__))

def _load_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

def _process_config(config: dict) -> dict:
    # --- Frontend keys ---
    for frontend in config["frontend"]["frontends_config"].values():
        frontend["metadata_signing_key"] = _load_file(frontend["metadata_signing_key_path"])
        frontend["metadata_access_certificate"] = _load_file(frontend["metadata_access_certificate_path"])

    # --- Global keys ---
    keys = config["keys"]
    keys["nonce_key"] = _load_file(keys["nonce_path"])
    keys["credential_encryption_key"] = _load_file(keys["credential_request_path"])

    # --- Country keys ---
    for country in config["countries"].values():
        for entry_name, entry in country["keys"].items():
            # entry_name is either "_default" or a frontend UUID
            entry["private_key"] = _load_file(entry["private_key_path"])
            entry["certificate"] = _load_file(entry["certificate_path"])

    return config

def _load_config() -> dict:
    config_path = os.environ.get("ISSUER_CONFIG_PATH", "/etc/issuer_config/config_issuer_backend.yaml")
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        if not config:
            raise RuntimeError(f"Config file is empty: {config_path}")
    except FileNotFoundError:
        raise RuntimeError(f"Config file not found: {config_path}")
    except yaml.YAMLError as e:
        raise RuntimeError(f"Invalid YAML in config: {e}")

    return _process_config(config)

if os.getenv("MOCK_CONFIGURATION"):
    CONFIGURATION = {
        "expiry": {
            "session": 30
        }
    }
else:
    CONFIGURATION = _load_config()

logger = logging.getLogger(__name__)

oidc_metadata: Dict[str, Any] = {}
oidc_metadata_clean: Dict[str, Any] = {}
openid_metadata: Dict[str, Any] = {}
oauth_metadata: Dict[str, Any] = {}
trusted_CAs: Dict[str, Any] = {}

IS_TEST_ENV = (
    "pytest" in sys.modules
    or any("pytest" in arg for arg in sys.argv)
    or os.getenv("CI") == "true"
    or os.getenv("SONARCLOUD") == "true"
)

session_manager = SessionManager(default_expiry_minutes=CONFIGURATION["expiry"]["session"])

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

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

    configure_logging(app, CONFIGURATION["logging"])
    
    app.logger.info("Running initialization setups...")
    setup_metadata()
    if not IS_TEST_ENV:
        setup_trusted_cas()

    app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    @app.route("/", methods=["GET"])
    def health_check():
        return "OK", 200

    from . import (
        route_formatter,
        route_oidc,
        route_dynamic,
        route_oid4vp,
        preauthorization,
        revocation,
        signed_metadata,
    )

    app.register_blueprint(route_formatter.formatter)
    app.register_blueprint(route_oidc.oidc)
    app.register_blueprint(revocation.revocation)
    app.register_blueprint(route_oid4vp.oid4vp)
    app.register_blueprint(route_dynamic.dynamic)
    app.register_blueprint(preauthorization.preauth)
    app.register_blueprint(signed_metadata.metadata)

    # config session
    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # CORS is a mechanism implemented by browsers to block requests from domains other than the server's one.
    CORS(app, supports_credentials=True)

    app.logger.info(" - DEBUG - FLASK started")

    return app



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


def replace_domain(
    obj: Union[Dict[str, Any], List[Any], str, Any], old: str, new: str
) -> Union[Dict[str, Any], List[Any], str, Any]:
    if isinstance(obj, dict):
        return {k: replace_domain(v, old, new) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_domain(i, old, new) for i in obj]
    elif isinstance(obj, str):
        return obj.replace(old, new)
    else:
        return obj


def fix_key_attestations(data):
    """
    Recursively traverse the data structure and replace
    key_attestations_required: null with key_attestations_required: {}
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "key_attestations_required" and value is None:
                data[key] = {}
            else:
                fix_key_attestations(value)
    elif isinstance(data, list):
        for item in data:
            fix_key_attestations(item)

    return data

import base64
import hashlib
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def _build_credential_encryption_metadata(key_bytes: bytes) -> dict:
    """
    Build the credential_request_encryption block from a PEM-encoded
    EC private key. Only the public coordinates are exposed in the JWK.
    The kid is the RFC 7638 JWK Thumbprint (SHA-256).
    """
    private_key = load_pem_private_key(key_bytes, password=None)

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("credential_encryption_key must be a P-256 EC private key")

    nums = private_key.public_key().public_numbers()
    key_size = (private_key.key_size + 7) // 8

    def _b64url(n: int) -> str:
        return (
            base64.urlsafe_b64encode(n.to_bytes(key_size, "big"))
            .rstrip(b"=")
            .decode()
        )

    x_b64 = _b64url(nums.x)
    y_b64 = _b64url(nums.y)

    thumbprint_json = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": x_b64, "y": y_b64},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    kid = (
        base64.urlsafe_b64encode(hashlib.sha256(thumbprint_json).digest())
        .rstrip(b"=")
        .decode()
    )

    logger.info("credential_request_encryption metadata built successfully (kid=%s, crv=P-256)", kid)

    return {
        "jwks": {
            "keys": [
                {
                    "kty": "EC",
                    "use": "enc",
                    "alg": "ECDH-ES",
                    "crv": "P-256",
                    "x": x_b64,
                    "y": y_b64,
                    "kid": kid,
                }
            ]
        },
        "enc_values_supported": [
            "A128GCM",
            "A256GCM",
            "A128CBC-HS256",
            "A256CBC-HS512",
            "ECDH-ES",
        ],
        "encryption_required": False,
    }

def setup_metadata():
    global oidc_metadata
    global oidc_metadata_clean
    global openid_metadata
    global oauth_metadata

    credentials_supported: Dict[str, Any] = {}

    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))

        with open(dir_path + "/metadata_config/openid-configuration.json") as f:
            openid_metadata = json.load(f)

        with open(dir_path + "/metadata_config/oauth-authorization-server.json") as f:
            oauth_metadata = json.load(f)

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
        logger.exception(f"Metadata Error: file not found. \n{e}")
        raise
    except json.JSONDecodeError as e:
        logger.exception(
            f"Metadata Error: Metadata Unable to decode JSON. \n{e}"
        )
        raise
    except Exception as e:
        logger.exception(
            f"Metadata Error: An unexpected error occurred. \n{e}"
        )
        raise

    oidc_metadata["credential_configurations_supported"] = credentials_supported

    oidc_metadata_clean["credential_configurations_supported"] = remove_keys(
        copy.deepcopy(credentials_supported),
        {
            "issuer_conditions",
            "issuer_config",
            "overall_issuer_conditions",
            "source",
            "selective_disclosure",
        },
    )

    oidc_metadata_clean["credential_configurations_supported"] = fix_key_attestations(
        oidc_metadata_clean["credential_configurations_supported"]
    )

    old_domain = oidc_metadata["credential_issuer"]

    new_domain = CONFIGURATION["service_url"]

    openid_metadata = cast(
        Dict[str, Any], replace_domain(openid_metadata, old_domain, new_domain)
    )
    oauth_metadata = cast(
        Dict[str, Any], replace_domain(oauth_metadata, old_domain, new_domain)
    )
    oidc_metadata_clean = cast(
        Dict[str, Any], replace_domain(oidc_metadata_clean, old_domain, new_domain)
    )
    oidc_metadata = cast(
        Dict[str, Any], replace_domain(oidc_metadata, old_domain, new_domain)
    )

    logger.info("Setting up credential_request_encryption in oidc_metadata_clean")
    try:
        oidc_metadata_clean["credential_request_encryption"] = _build_credential_encryption_metadata(
            CONFIGURATION["keys"]["credential_encryption_key"]
        )
        logger.info("credential_request_encryption: %s", json.dumps(oidc_metadata_clean["credential_request_encryption"], indent=2))
    except Exception as e:
        logger.exception("Failed to build credential_request_encryption metadata: %s", e)
        raise


def setup_trusted_cas():
    global trusted_CAs
    try:
        ec_keys = {}
        for file in os.listdir(CONFIGURATION["trusted_CAs_path"]):
            if file.endswith("pem"):
                ca_path = os.path.join(CONFIGURATION["trusted_CAs_path"], file)

                with open(ca_path) as pem_file:

                    pem_data = pem_file.read()

                    pem_data = pem_data.encode()

                    certificate = x509.load_pem_x509_certificate(
                        pem_data, default_backend()
                    )

                    public_key = certificate.public_key()

                    issuer = certificate.issuer

                    not_valid_before = certificate.not_valid_before

                    not_valid_after = certificate.not_valid_after

                    if isinstance(public_key, ec.EllipticCurvePublicKey):
                        public_numbers = public_key.public_numbers()
                        x = public_numbers.x.to_bytes(
                            (public_numbers.x.bit_length() + 7) // 8,
                            "big",
                        )
                        y = public_numbers.y.to_bytes(
                            (public_numbers.y.bit_length() + 7) // 8,
                            "big",
                        )

                    else:
                        raise ValueError(
                            "Only elliptic curve keys supported for EC2Key"
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
        logger.exception(f"TrustedCA Error: file not found.\n {e}")
        raise
    except json.JSONDecodeError as e:
        logger.exception(
            f"TrustedCA Error: Metadata Unable to decode JSON.\n {e}"
        )
        raise
    except Exception as e:
        logger.exception(
            f"TrustedCA Error: An unexpected error occurred.\n {e}"
        )
        raise

    trusted_CAs = ec_keys



def handle_exception(e):
    if isinstance(e, HTTPException):
        return e

    logger.exception("Unhandled exception")

    return jsonify({
        "error": "Internal Server Error",
        "error_code": 500,
        "message": "An internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
    }), 500


def page_not_found(e):
    logger.warning("404 Not Found: %s", request.path)

    return jsonify({
        "error": "Not Found",
        "error_code": 404,
        "message": f"The requested path '{request.path}' could not be found.",
    }), 404