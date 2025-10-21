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
Its main goal is to issue the PID and MDL in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This route_oidc.py file is the blueprint for the route /oidc of the PID Issuer Web service.
"""
import base64
import io
import re
import time
import uuid
import urllib.parse
from app.misc import (
    authentication_error_redirect,
    generate_unique_id,
    post_redirect_with_payload,
    scope2details,
    vct2id,
    verify_jwt_with_x5c,
)
import segno

from flask import (
    Blueprint,
    Response,
    jsonify,
    request,
    session,
    current_app,
    redirect,
    render_template,
    url_for,
)
from flask.helpers import make_response
from jwcrypto import jwk, jwe
from flask_cors import CORS
import json
import sys

import werkzeug


from datetime import datetime, timedelta

#!/usr/bin/env python3
import requests

from .app_config.config_service import ConfService as cfgservice
from .app_config.config_countries import ConfFrontend
from . import oidc_metadata, openid_metadata, oidc_metadata_clean

oidc = Blueprint("oidc", __name__, url_prefix="/")
CORS(oidc)  # enable CORS on the blue print

# variable for PAR requests
from app.data_management import (
    credential_offer_references,
)


@oidc.route("/.well-known/oauth-authorization-server/oidc")
def well_known2():
    info = {
        "response": openid_metadata,
        "http_headers": [
            ("Content-type", "application/json"),
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-store"),
        ],
    }

    _http_response_code = info.get("response_code", 200)
    resp = make_response(info["response"], _http_response_code)

    for key, value in info["http_headers"]:
        resp.headers[key] = value

    return resp


@oidc.route("/.well-known/oauth-authorization-server/frontend")
def well_known3():
    url = "https://dev.issuer.eudiw.dev/frontend/.well-known/oauth-authorization-server"
    r = requests.get(url)

    return Response(
        r.content, status=r.status_code, content_type=r.headers.get("Content-Type")
    )


@oidc.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-credential-issuer":
        info = {
            "response": oidc_metadata_clean,
            "http_headers": [
                ("Content-type", "application/json"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp
    if service == "openid-credential-issuer2":
        info = {
            "response": oidc_metadata,
            "http_headers": [
                ("Content-type", "application/json"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp
    elif service == "oauth-authorization-server":
        info = {
            "response": openid_metadata,
            "http_headers": [
                ("Content-type", "application/json"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    elif service == "openid-configuration":
        # _endpoint = current_app.server.get_endpoint("provider_config")
        info = {
            "response": openid_metadata,
            "http_headers": [
                ("Content-type", "application/json"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    else:
        return make_response("Not supported", 400)


@oidc.route("/auth_choice", methods=["GET"])
def auth_choice():

    print("\nauth_choice: ", request.args)

    token = request.args.get("token")
    print("\nauth_choice 1")
    session_id = request.args.get("session_id")
    print("\nauth_choice 2")
    scope = request.args.get("scope")
    print("\nauth_choice 3")
    authorization_details_str = request.args.get("authorization_details")
    print("\nauth_choice 4")
    frontend_id = request.args.get("frontend_id")

    print("\nauth_choice 5")

    if not frontend_id:
        frontend_id = "5d725b3c-6d42-448e-8bfd-1eff1fcf152d"

    print("\nauth_choice 6")
    session["session_id"] = session_id

    print("\nauth_choice 7")

    supported_credencials = cfgservice.auth_method_supported_credencials

    print("\nauth_choice 8")

    pid_auth = True
    country_selection = True

    authorization_details = []

    if authorization_details_str:
        print("\nauth_choice 9")
        try:
            decoded_string = urllib.parse.unquote(authorization_details_str)

            authorization_details = json.loads(json.loads(decoded_string))
        except json.JSONDecodeError as e:
            print(f"Error parsing authorization_details JSON: {e}")
            return jsonify({"error": "Invalid authorization_details parameter"}), 400

    print("\nauth_choice 10")
    credential_configuration_id = None
    if scope:  # "scope" in authorization_params:
        print("\nauth_choice 11")
        scope_elements = scope.split()
        authorization_details.extend(
            scope2details(scope_elements)
        )  # authorization_params["scope"]

        credential_configuration_id = scope.replace("openid", "").strip()

    print("\nauth_choice 12")
    if not authorization_details:
        print("\nauth_choice 3")
        return authentication_error_redirect(
            jws_token=token,  # authorization_params["token"],
            error="invalid authentication",
            error_description="No authorization details or scope found in dynamic route.",
        )

    print("\nauth_choice 14")
    credentials_requested = []

    print("\nauth_choice 15")
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])

        elif "vct" in cred:
            if cred["vct"] not in credentials_requested:
                credentials_requested.append(vct2id(cred["vct"]))

    print("\nauth_choice 16: ", credentials_requested)

    session_manager.add_session(
        session_id=session_id,
        jws_token=token,
        scope=credential_configuration_id,
        authorization_details=authorization_details,
        credentials_requested=credentials_requested,
        frontend_id=frontend_id,
    )

    print("\nauth_choice 16")

    for cred in credentials_requested:
        if (
            cred in supported_credencials["PID_login"]
            and cred not in supported_credencials["country_selection"]
        ):
            country_selection = False

        elif (
            cred not in supported_credencials["PID_login"]
            and cred in supported_credencials["country_selection"]
        ):
            pid_auth = False

        elif (
            cred not in supported_credencials["PID_login"]
            and cred not in supported_credencials["country_selection"]
        ):
            country_selection = False
            pid_auth = False

    print("\nauth_choice 18")
    if country_selection == False and pid_auth == True:
        print("\nauth_choice 19")
        return redirect(cfgservice.service_url + "oid4vp")
    elif country_selection == True and pid_auth == False:
        print("\nauth_choice 20")
        return redirect(cfgservice.service_url + "dynamic/")

    print("\nauth_choice 21")
    error = ""
    if pid_auth == False and country_selection == False:
        error = "Combination of requested credentials is not valid!"

    print("\npid_auth: ", pid_auth)
    print("\ncountry_selection: ", country_selection)

    print("\nauth_choice 22")
    target_url = ConfFrontend.registered_frontends[frontend_id]["url"]

    print("\nauth_choice 23: ", pid_auth, "\n", country_selection)
    return post_redirect_with_payload(
        target_url=f"{target_url}/display_auth_method",
        data_payload={
            "pid_auth": pid_auth,
            "country_selection": country_selection,
            "redirect_url": cfgservice.service_url,
            "session_id": session_id,
        },
    )

    """ return render_template(
        "misc/auth_method.html",
        pid_auth=pid_auth,
        country_selection=country_selection,
        error=error,
        redirect_url=cfgservice.service_url,
    ) """

    # return render_template("misc/auth_method.html")


@oidc.route("/pid_authorization")
def pid_authorization_get():

    presentation_id = request.args.get("presentation_id")

    if not presentation_id:
        raise ValueError("Presentation id is required")

    if not re.match(r"^[A-Za-z0-9_-]+$", presentation_id):
        raise ValueError("Invalid Presentation id format")

    url = (
        cfgservice.dynamic_presentation_url
        + presentation_id
        + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
    )
    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg = str(response.status_code)
        return jsonify({"error": error_msg}), 500
    else:
        data = {"message": "Sucess"}
        return jsonify({"message": data}), 200


def verify_introspection(bearer_token):
    introspection_url = "http://127.0.0.1:6005/introspection"

    payload = f"token={bearer_token}"

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.request(
            "POST", introspection_url, headers=headers, data=payload
        )
        response.raise_for_status()  # Raises an HTTPError for 4xx/5xx status codes

        introspection_data = response.json()

    except requests.exceptions.RequestException as e:
        # Error 4: Network or HTTP-level error during introspection call
        print(f"An error occurred during introspection request: {e}")
        return (
            jsonify({"error": "Failed to validate token with the issuer."}),
            502,
        )  # 502 Bad Gateway is appropriate here
    except json.JSONDecodeError:
        # Error 5: Malformed JSON from the introspection endpoint
        print("Failed to decode JSON from introspection response.")
        return (
            jsonify({"error": "Invalid response from the introspection endpoint."}),
            502,
        )

    # --- 3. Verify Introspection Data ---
    is_active = introspection_data.get("active", False)
    username = introspection_data.get("username")

    if not is_active:
        # Error 6: Inactive token
        print("Token is inactive.")
        return jsonify({"error": "Provided token is inactive."}), 401

    if not username:
        # Error 7: Missing username in introspection response
        print("Token is active but missing username.")
        return (
            jsonify(
                {"error": "Token is active but does not contain a username claim."}
            ),
            401,
        )

    return username


from app import session_manager


def verify_credential_request(credential_request):

    if "credential_indentifier" in credential_request:
        return jsonify({"error": "credential_identifier currently not supported."}), 401

    if (
        "credential_identifier" not in credential_request
        and "credential_configuration_id" not in credential_request
    ):
        return (
            jsonify(
                {
                    "error": "Missing credential_identifier or credential_configuration_id"
                }
            ),
            401,
        )

    if "proof" not in credential_request and "proofs" not in credential_request:
        return jsonify({"error": "Credential Issuer requires key proof."}), 401

    elif "proof" in credential_request:
        if "proof_type" not in credential_request["proof"]:
            return jsonify({"error": "Credential Issuer requires key proof."}), 401

        elif (
            credential_request["proof"]["proof_type"] == "attestation"
            and "attestation" not in credential_request["proof"]
        ):
            return jsonify({"error": "Missing jwt field."}), 401

        elif (
            credential_request["proof"]["proof_type"] == "jwt"
            and "jwt" not in credential_request["proof"]
        ):
            return jsonify({"error": "Missing attestation field."}), 401

    return credential_request


import jwt

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


# gets the public key from a JWK
def pKfromJWT(jwt_encoded):
    jwt_decoded = jwt.get_unverified_header(jwt_encoded)
    jwk = jwt_decoded["jwk"]

    return pKfromJWK(jwk)


def pKfromJWK(jwk):
    if "crv" not in jwk or jwk["crv"] != "P-256":
        _resp = {
            "error": "invalid_proof",
            "error_description": "Credential Issuer only supports P-256 curves",
        }
        return _resp  # {"response_args": _resp, "client_id": client_id}

    x = jwk["x"]
    y = jwk["y"]

    # Convert string coordinates to bytes
    x_bytes = base64.urlsafe_b64decode(x + "=" * (4 - len(x) % 4))
    y_bytes = base64.urlsafe_b64decode(y + "=" * (4 - len(y) % 4))

    # Create a public key from the bytes
    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x_bytes, "big"),
        y=int.from_bytes(y_bytes, "big"),
        curve=ec.SECP256R1(),
    )

    public_key = public_numbers.public_key()

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Encode the public key in base64url format

    device_key = base64.urlsafe_b64encode(public_key_pem).decode("utf-8")

    return device_key


from authlib.jose import JsonWebEncryption
from authlib.jose import JsonWebKey


def decode_verify_attestation(jwt_raw):
    claims = verify_jwt_with_x5c(jwt_raw=jwt_raw)

    print("\nclaims: ", claims)
    return claims


def generate_credentials(credential_request, session_id):
    formatter_request = {}

    formatter_request.update(
        {
            "credential_configuration_id": credential_request[
                "credential_configuration_id"
            ]
        }
    )

    pubKeys = []

    if (
        "proof" in credential_request
        and credential_request["proof"]["proof_type"] == "jwt"
    ):
        try:
            jwt_encoded = credential_request["proof"]["jwt"]
            device_key = pKfromJWT(jwt_encoded)
            formatter_request.update({"proofs": [{"jwt": device_key}]})

        except Exception as e:
            return ""

    elif "proofs" in credential_request:
        for alg, key_list in credential_request["proofs"].items():
            if alg != "jwt":
                return {"error": "proof currently not supported"}
            else:
                for jwt_ in key_list:
                    try:
                        device_key = pKfromJWT(jwt_)
                        pubKeys.append({alg: device_key})
                    except Exception as e:
                        _resp = {
                            "error": "invalid_proof",
                            "error_description": str(e),
                        }
                        return _resp

                session_manager.update_is_batch_credential(
                    session_id=session_id, is_batch_credential=True
                )

        formatter_request.update({"proofs": pubKeys})

    elif (
        "proof" in credential_request
        and credential_request["proof"]["proof_type"] == "attestation"
    ):
        claims = decode_verify_attestation(credential_request["proof"]["attestation"])
        for _jwk in claims["attested_keys"]:
            device_key = pKfromJWK(_jwk)
            pubKeys.append({"attestation": device_key})

        formatter_request.update({"proofs": pubKeys})

    redirect_uri = cfgservice.service_url + "dynamic/dynamic_R2"

    data = {
        "credential_requests": formatter_request,
        "user_id": session_id,
    }

    json_data = json.dumps(data)
    headers = {"Content-Type": "application/json"}
    _msg = requests.post(redirect_uri, data=json_data, headers=headers).json()

    return _msg


def encrypt_response(credential_request, credential_response):
    print("\n--------------------Starting Encryption")
    encryption_config = credential_request.get("credential_response_encryption", {})
    print("\nencryption_config: ", encryption_config)

    if not encryption_config or not all(k in encryption_config for k in ["jwk", "enc"]):
        print("\nMissing required fields in credential_response_encryption.")
        return make_response(
            jsonify(
                {
                    "error": "invalid_credential_response_encryption",
                    "error_description": "Missing required fields in credential_response_encryption.",
                }
            ),
            400,
        )

    if "alg" not in encryption_config["jwk"]:
        if "alg" not in encryption_config:
            return make_response(
                jsonify(
                    {
                        "error": "invalid_credential_response_encryption",
                        "error_description": "Missing alg field in credential_response_encryption.",
                    }
                ),
                400,
            )

    if "alg" in encryption_config:
        _alg = encryption_config["alg"]

    else:
        _alg = encryption_config["jwk"]["alg"]

    protected_header = {
        "alg": _alg,
        "enc": encryption_config["enc"],
    }

    print("\nprotected_header:", protected_header)

    try:
        public_key = JsonWebKey.import_key(encryption_config["jwk"])
        print("\npublic_key:", public_key)
        jwe = JsonWebEncryption()
        jwe_token = jwe.serialize_compact(
            protected_header, json.dumps(credential_response), public_key
        )
        print("\njwe_token:", jwe_token)
    except:
        return make_response(
            jsonify(
                {
                    "error": "invalid_credential_response_encryption",
                    "error_description": "Failed to encrypt with the provided key.",
                }
            ),
            400,
        )

    _response = make_response(jwe_token)

    _response.headers["Content-Type"] = "application/jwt"

    return _response


def decrypt_jwe_credential_request(jwt_token):
    """
    Decrypt JWE credential request using the PEM private key.
    Returns the decrypted credential request as a dictionary.
    """
    if jwt_token.count(".") != 4:
        raise ValueError("Invalid JWE format - expected 5 parts")

    try:
        with open(cfgservice.credential_request_priv_key, "r") as key_file:
            pem_private_key = key_file.read()

        private_key = jwk.JWK.from_pem(pem_private_key.encode("utf-8"))

        jwe_token = jwe.JWE()
        jwe_token.deserialize(jwt_token)
        jwe_token.decrypt(private_key)

        payload = jwe_token.payload.decode("utf-8")

        cfgservice.app_logger.info(f"Successfully decrypted JWE payload")

        credential_request = json.loads(payload)
        return credential_request

    except FileNotFoundError:
        cfgservice.app_logger.error(
            f"Private key file not found: {cfgservice.credential_request_priv_key}"
        )
        raise ValueError(f"Private key file not found")
    except json.JSONDecodeError as e:
        cfgservice.app_logger.error(
            f"Failed to parse decrypted payload as JSON: {str(e)}"
        )
        raise ValueError(f"Decrypted payload is not valid JSON: {str(e)}")
    except Exception as e:
        cfgservice.app_logger.error(f"Failed to decrypt JWE: {str(e)}")
        raise ValueError(f"Failed to decrypt JWE: {str(e)}")


@oidc.route("/credential", methods=["POST"])
def credential():

    content_type = request.content_type

    if content_type == "application/jwt":
        jwt_token = request.get_data(as_text=True)

        cfgservice.app_logger.info(
            f", Started Credential Request (JWT), Token: {jwt_token}"
        )

        try:
            credential_request = decrypt_jwe_credential_request(jwt_token)
        except (jwt.InvalidTokenError, jwt.ExpiredSignatureError, Exception) as e:
            cfgservice.app_logger.error(f"Failed to decrypt/verify JWT: {str(e)}")
            return make_response(
                jsonify({"error": "Invalid JWT credential request"}), 400
            )
    else:
        # Original JSON handling
        credential_request = request.get_json()

    cfgservice.app_logger.info(
        f", Started Credential Request, Payload: {credential_request}"
    )

    # Get the Authorization header from the request
    auth_header = request.headers.get("Authorization")

    bearer_token = None

    if not auth_header:
        return make_response(jsonify({"error": "Authorization header is missing"}), 401)

    if not (
        auth_header.lower().startswith("bearer ")
        or auth_header.lower().startswith("dpop ")
    ):
        return make_response(
            jsonify({"error": "Authorization header must be a Bearer or DPoP token"}),
            401,
        )

    try:
        bearer_token = auth_header.split(" ")[1]
    except IndexError:
        return make_response(
            jsonify({"error": "Invalid Authorization header format"}), 401
        )

    verification_result_introspection = verify_introspection(bearer_token=bearer_token)

    # Check if the result is an error response (a tuple)
    if isinstance(verification_result_introspection, tuple):
        # If it's a tuple, it's a Flask error response. Return it immediately.
        return verification_result_introspection

    # If the result is not a tuple, it's the username string
    session_id = verification_result_introspection

    verification_result_request = verify_credential_request(credential_request)

    if isinstance(verification_result_request, tuple):
        # If it's a tuple, it's an error response. Return it immediately.
        return verification_result_request

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Credential Request, Payload: {verification_result_request}"
    )

    # If the check passes, the result is the validated request dictionary.
    validated_credential_request = verification_result_request

    current_session = session_manager.get_session(session_id=session_id)

    _response = generate_credentials(
        credential_request=validated_credential_request, session_id=session_id
    )

    # add notification_id
    notification_id = str(uuid.uuid4())
    session_manager.store_notification_id(
        session_id=session_id, notification_id=notification_id
    )
    _response["notification_id"] = notification_id

    # Deferred case. Issuer doesnt have the data yet

    is_deferred = False

    if ("error" in _response and _response["error"] == "Pending") or (
        "credential_configuration_id" in validated_credential_request
        and validated_credential_request["credential_configuration_id"]
        == "eu.europa.ec.eudi.pseudonym_over18_mdoc_deferred_endpoint"
    ):
        _transaction_id = str(uuid.uuid4())
        session_manager.add_transaction_id(
            session_id=session_id,
            transaction_id=_transaction_id,
            credential_request=validated_credential_request,
        )
        _response = {"transaction_id": _transaction_id, "interval": 30}
        is_deferred = True

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Credential response, Payload: {_response}"
    )

    if "credential_response_encryption" in validated_credential_request:
        _response = encrypt_response(
            credential_request=validated_credential_request,
            credential_response=_response,
        )

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Credential encrypted response, Payload: {_response}"
        )

        """ cfgservice.app_logger.info(
            f", Session ID: {session_id}, Credential encrypted response, Payload: {_response.data.decode('utf-8')}"
        ) """

        print("\nfinal_response_1: ", type(_response))
        print("\nfinal_response_1.1: ", _response.data.decode("utf-8"))
        
        if _response.status_code != 200:
            return _response
        
        if is_deferred:
            print("\nfinal_response_2: ", _response)
            return _response, 202
        return _response, 200

    print("\nfinal_response_3: ", _response)
    
    if is_deferred:
        return _response, 202
    return _response, 200


@oidc.route("/notification", methods=["POST"])
def notification():
    notification_request = request.get_json()

    cfgservice.app_logger.info(
        f", Started Notification Request, Payload: {notification_request}"
    )

    # Get the Authorization header from the request
    auth_header = request.headers.get("Authorization")

    bearer_token = None

    if not auth_header:
        return jsonify({"error": "Authorization header is missing"}), 401

    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header must be a Bearer token"}), 401

    try:
        bearer_token = auth_header.split(" ")[1]
    except IndexError:
        return jsonify({"error": "Invalid Authorization header format"}), 401

    verification_result_introspection = verify_introspection(bearer_token=bearer_token)

    # Check if the result is an error response (a tuple)
    if isinstance(verification_result_introspection, tuple):
        # If it's a tuple, it's a Flask error response. Return it immediately.
        return verification_result_introspection

    # If the result is not a tuple, it's the username string
    session_id = verification_result_introspection

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Notification Request, Payload: {notification_request}"
    )

    return make_response("", 204)


@oidc.route("/nonce", methods=["POST"])
def nonce():
    protected = {"type": "cnonce+jwt", "alg": "RSA-OAEP", "enc": "A256GCM"}
    with open(cfgservice.nonce_key, "rb") as f:
        key = f.read()

    current_time = int(time.time())

    payload = {
        "iss": cfgservice.service_url[:-1],
        "iat": current_time,
        "exp": current_time + 3600,
        "source_endpoint": cfgservice.service_url + "nonce",
        "aud": [cfgservice.service_url + "credential"],
    }

    jwe = JsonWebEncryption()

    payload_json = json.dumps(payload)

    encrypted_jwt = jwe.serialize_compact(protected, payload_json, key)

    data = jwe.deserialize_compact(encrypted_jwt, key)
    jwe_payload = data["payload"]

    encrypted_jwt_str = encrypted_jwt.decode("utf-8")

    response_data = {"c_nonce": encrypted_jwt_str}

    response = jsonify(response_data)

    response.headers["Cache-Control"] = "no-store"

    response.headers["DPoP-Nonce"] = encrypted_jwt_str

    return response, 200


@oidc.route("/deferred_credential", methods=["POST"])
def deferred_credential():
    deferred_request = request.get_json()

    if "transaction_id" not in deferred_request:
        return jsonify({"error": "invalid_transaction_id"}), 401

    deferred_transaction_id = deferred_request["transaction_id"]

    try:
        uuid.UUID(deferred_transaction_id, version=4)
    except (ValueError, AttributeError):
        return jsonify({"error": "invalid_transaction_id_format"}), 401

    cfgservice.app_logger.info(
        f", Started Deferred Request, Transaction ID: {deferred_transaction_id}"
    )

    # Get the Authorization header from the request
    auth_header = request.headers.get("Authorization")

    bearer_token = None

    if not auth_header:
        return jsonify({"error": "Authorization header is missing"}), 401

    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header must be a Bearer token"}), 401

    try:
        bearer_token = auth_header.split(" ")[1]
    except IndexError:
        return jsonify({"error": "Invalid Authorization header format"}), 401

    verification_result_introspection = verify_introspection(bearer_token=bearer_token)

    # Check if the result is an error response (a tuple)
    if isinstance(verification_result_introspection, tuple):
        # If it's a tuple, it's a Flask error response. Return it immediately.
        return verification_result_introspection

    # If the result is not a tuple, it's the username string
    session_id = verification_result_introspection

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Deferred Request, Payload: {deferred_request}"
    )

    current_session = session_manager.get_session(session_id=session_id)

    if deferred_transaction_id not in current_session.transaction_id:
        # Return a 400 Bad Request to indicate a client-side error
        return (
            jsonify(
                {
                    "error": f"Transaction ID '{deferred_transaction_id}' is not associated with this session."
                }
            ),
            400,
        )

    credential_request = current_session.transaction_id[deferred_transaction_id]

    verification_result_request = verify_credential_request(credential_request)

    if isinstance(verification_result_request, tuple):
        # If it's a tuple, it's an error response. Return it immediately.
        return verification_result_request

    # If the check passes, the result is the validated request dictionary.
    validated_credential_request = verification_result_request

    current_session = session_manager.get_session(session_id=session_id)

    _response = generate_credentials(
        credential_request=validated_credential_request, session_id=session_id
    )

    # add notification_id
    notification_id = str(uuid.uuid4())
    session_manager.store_notification_id(
        session_id=session_id, notification_id=notification_id
    )
    _response["notification_id"] = notification_id

    # Deferred case. Issuer doesnt have the data yet

    is_deferred = False
    if "error" in _response and _response["error"] == "Pending":
        _response = {"transaction_id": deferred_transaction_id, "interval": 30}
        is_deferred = True

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Deferred credential response, Payload: {_response}"
    )

    if "credential_response_encryption" in deferred_request:
        validated_credential_request["validated_credential_request"] = deferred_request[
            "credential_response_encryption"
        ]
        _response = encrypt_response(
            credential_request=validated_credential_request,
            credential_response=_response,
        )

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Deferred credential encrypted response, Payload: {_response.data.decode('utf-8')}"
        )

        if is_deferred:
            return _response, 202
        return _response, 200

    if is_deferred:
        return _response, 202
    return _response, 200


@oidc.route("credential_offer_choice", methods=["GET"])
def credential_offer():
    # Page for selecting credentials

    # Loads credentials supported by EUDIW Issuer

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}

    for cred in credentialsSupported:
        credential = credentialsSupported[cred]

        if credential["format"] == "dc+sd-jwt":
            # if credential["scope"] == "eu.europa.ec.eudiw.pid.1":
            if (
                cred in cfgservice.auth_method_supported_credencials["PID_login"]
                or cred
                in cfgservice.auth_method_supported_credencials["country_selection"]
            ):
                credentials["sd-jwt vc format"].update(
                    # {"Personal Identification Data": cred}
                    {cred: credential["credential_metadata"]["display"][0]["name"]}
                )

        if credential["format"] == "mso_mdoc":
            if (
                cred in cfgservice.auth_method_supported_credencials["PID_login"]
                or cred
                in cfgservice.auth_method_supported_credencials["country_selection"]
            ):
                credentials["mdoc format"].update(
                    {cred: credential["credential_metadata"]["display"][0]["name"]}
                )

    return render_template(
        "openid/credential_offer.html",
        cred=credentials,
        redirect_url=cfgservice.service_url,
        credential_offer_URI="openid-credential-offer://",
    )


""" @oidc.route("/test_dump", methods=["GET", "POST"])
def dump_test():
    _store = current_app.server.context.dump()
    
    print("\n------Store-----\n", _store)
    print("\n------Store type-----\n", type(_store))
    
    json_string = json.dumps(_store, indent=4)
    
    with open("data.json", "w") as json_file:
        json_file.write(json_string)
    return "dump"

@oidc.route("/test_load", methods=["GET", "POST"])
def load_test():
    print("load_test\n")
    with open("data.json", "r") as json_file:
    # Load the JSON data from the file
        data = json.loads(json_file.read())
        print("\n-----Data-----\n",data)
        current_app.server.context.load(data)

    return "load" """


@oidc.route("/logs", methods=["GET"])
def get_logs_by_session():
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "Missing required parameter: session_id"}), 400

    LOG_FILES = ["/tmp/oidc_log_dev/logs.log", "/tmp/log_dev/logs.log"]
    matches = []

    for log_file in LOG_FILES:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    if f"Session ID: {session_id}" in line:
                        matches.append(line.strip())
        except FileNotFoundError:
            # Just skip missing files silently
            continue

    return jsonify({"session_id": session_id, "count": len(matches), "logs": matches})


@oidc.route("/credential_offer2", methods=["GET", "POST"])
def credentialOffer2():
    session_id = generate_unique_id()
    print("\nCredential_offer2 session_id:", session_id)

    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": ["eu.europa.ec.eudi.pid_mdoc"],
        "grants": {"authorization_code": {"issuer_state": session_id}},
    }

    json_string = json.dumps(credential_offer)

    uri = f"openid-credential-offer://credential_offer?credential_offer={urllib.parse.quote(json_string, safe=':/')}"

    qrcode = segno.make(uri)
    out = io.BytesIO()
    qrcode.save(out, kind="png", scale=3)

    qr_img_base64 = base64.b64encode(out.getvalue()).decode("utf-8")

    return jsonify({"base64_img": qr_img_base64, "session_id": session_id})


@oidc.route("/credential_offer", methods=["GET", "POST"])
def credentialOffer():

    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    auth_choice = request.form.get("Authorization Code Grant")
    form_keys = request.form.keys()
    credential_offer_URI = request.form.get("credential_offer_URI")

    if "proceed" in form_keys:
        form = list(form_keys)
        form.remove("proceed")
        form.remove("credential_offer_URI")
        form.remove("Authorization Code Grant")
        all_exist = all(credential in credentialsSupported for credential in form)

        if all_exist:
            credentials_id = form
            session["credentials_id"] = credentials_id
            credentials_id_list = json.dumps(form)
            if auth_choice == "pre_auth_code":
                session["credential_offer_URI"] = credential_offer_URI
                return redirect(
                    url_for("preauth.preauthRed", credentials_id=credentials_id_list)
                )

            else:

                session_id = generate_unique_id()

                credential_offer = {
                    "credential_issuer": cfgservice.service_url[:-1],
                    "credential_configuration_ids": credentials_id,
                    "grants": {"authorization_code": {"issuer_state": session_id}},
                }

                reference_id = str(uuid.uuid4())
                credential_offer_references.update(
                    {
                        reference_id: {
                            "credential_offer": credential_offer,
                            "expires": datetime.now()
                            + timedelta(minutes=cfgservice.form_expiry),
                        }
                    }
                )

                # create URI
                json_string = json.dumps(credential_offer)

                uri = (
                    f"{credential_offer_URI}credential_offer?credential_offer="
                    + urllib.parse.quote(json_string, safe=":/")
                )

                # Generate QR code
                # img = qrcode.make("uri")
                # QRCode.print_ascii()

                qrcode = segno.make(uri)
                out = io.BytesIO()
                qrcode.save(out, kind="png", scale=3)

                # qrcode.to_artistic(
                #    background=cfgtest.qr_png,
                #    target=out,
                #    kind="png",
                #    scale=4,
                # )
                # qrcode.terminal()
                # qr_img_base64 = qrcode.png_data_uri(scale=4)

                qr_img_base64 = "data:image/png;base64," + base64.b64encode(
                    out.getvalue()
                ).decode("utf-8")

                wallet_url = cfgservice.wallet_test_url + "credential_offer"

                return render_template(
                    "openid/credential_offer_qr_code.html",
                    wallet_dev=wallet_url
                    + "?credential_offer="
                    + json.dumps(credential_offer),
                    url_data=uri,
                    qrcode=qr_img_base64,
                )

    else:
        return redirect(cfgservice.service_url + "credential_offer_choice")


@oidc.route("/credential-offer-reference/<string:reference_id>", methods=["GET"])
def offer_reference(reference_id):
    return credential_offer_references[reference_id]["credential_offer"]


""" @oidc.route("/testgetauth", methods=["GET"])
def testget():
    if "error" in request.args:
        response = (
            request.args.get("error") + "\n" + request.args.get("error_description")
        )
        return response
    else:
        return request.args.get("code") """


IGNORE = ["cookie", "user-agent"]


@oidc.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return "bad request!", 400
