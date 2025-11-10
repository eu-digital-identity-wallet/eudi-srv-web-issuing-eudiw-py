# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
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

import base64
import io
import json
import re
from urllib.parse import urlparse
import uuid
import cbor2
from flask import (
    Blueprint,
    abort,
    jsonify,
    request,
    session,
)
from typing import Tuple, Union
from urllib.parse import quote_plus
import requests
import segno
from .app_config.config_service import ConfService as cfgservice
from app.data_management import revocation_requests
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from . import oidc_metadata
from misc import generate_unique_id
from datetime import datetime, timedelta
import cbor2

""" from app.data_management import (
    oid4vp_requests,
) """
from sd_jwt.holder import SDJWTHolder
import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from app_config.config_countries import ConfFrontend
from app.redirect_func import post_redirect_with_payload

revocation = Blueprint("revocation", __name__, url_prefix="/revocation")


# TODO finish revocation pages.
@revocation.route("revocation_choice", methods=["GET"])
def revocation_choice():
    """Page for selecting credentials

    Loads credentials supported by EUDIW Issuer"""

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}

    for cred in credentialsSupported:
        credential = credentialsSupported[cred]

        if credential["format"] == "dc+sd-jwt":
            credentials["sd-jwt vc format"].update(
                {cred: credential["credential_metadata"]["display"][0]["name"]}
            )

        if credential["format"] == "mso_mdoc":
            credentials["mdoc format"].update(
                {cred: credential["credential_metadata"]["display"][0]["name"]}
            )

    target_url = ConfFrontend.registered_frontends[cfgservice.default_frontend]["url"]

    return post_redirect_with_payload(
        target_url=f"{target_url}/display_revocation_choice",
        data_payload={
            "cred": credentials,
            "redirect_url": f"{cfgservice.service_url}revocation/oid4vp_call",
        },
    )


@revocation.route("oid4vp_call", methods=["GET", "POST"])
def oid4vp_call():
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    form_keys = request.form.keys()
    form = list(form_keys)
    form.remove("proceed")
    session_id = str(uuid.uuid4())

    print("\nform: ", form)

    input_descriptors = []

    # print("\nrequested: ", credentials_requested)

    dcql_credentials = []
    query_id_counter = 0

    for credential_requested in form:
        credential_config = credentialsSupported[credential_requested]
        credential_metadata = credential_config["credential_metadata"]
        credential_format = credential_config["format"]

        query_id = f"query_{query_id_counter}"
        dcql_credential = {"id": query_id, "format": credential_format, "claims": []}

        # Add the meta object based on the format
        if credential_format == "dc+sd-jwt":
            dcql_credential["meta"] = {"vct_values": [credential_config["vct"]]}
        elif credential_format == "mso_mdoc":
            dcql_credential["meta"] = {"doctype_value": credential_config["doctype"]}

        for claim in credential_metadata["claims"]:
            dcql_credential["claims"].append(
                {"path": claim["path"], "intent_to_retain": False}
            )

        dcql_credentials.append(dcql_credential)

        query_id_counter += 1

    # Final DCQL query
    dcql_query = {"credentials": dcql_credentials}

    url = cfgservice.dynamic_presentation_url
    payload_cross_device = json.dumps(
        {
            "type": "vp_token",
            "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
            "dcql_query": dcql_query,
            "request_uri_method": "post",
        }
    )

    payload_same_device = json.dumps(
        {
            "type": "vp_token",
            "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
            "request_uri_method": "post",
            "dcql_query": dcql_query,
            "wallet_response_redirect_uri_template": cfgservice.service_url
            + "getpidoid4vp?response_code={RESPONSE_CODE}&session_id="
            + session_id,
        }
    )

    headers = {
        "Content-Type": "application/json",
    }

    print("\npayload: ", payload_cross_device)

    response_cross = requests.request(
        "POST", url[:-1], headers=headers, data=payload_cross_device
    ).json()

    response_same = requests.request(
        "POST", url[:-1], headers=headers, data=payload_same_device
    ).json()

    """ oid4vp_requests.update(
        {
            session_id: {
                "response": response_same,
                "expires": datetime.now()
                + timedelta(minutes=cfgservice.deffered_expiry),
            }
        }
    ) """

    domain = urlparse(url).netloc

    deeplink_url = (
        "eudi-openid4vp://"
        + domain
        + "?client_id="
        + response_same["client_id"]
        + "&request_uri="
        + response_same["request_uri"]
    )

    qr_code_url = (
        "eudi-openid4vp://"
        + domain
        + "?client_id="
        + response_cross["client_id"]
        + "&request_uri="
        + response_cross["request_uri"]
    )

    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(qr_code_url)
    out = io.BytesIO()
    qrcode.save(out, kind="png", scale=3)

    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    target_url = ConfFrontend.registered_frontends[cfgservice.default_frontend]["url"]

    return post_redirect_with_payload(
        target_url=f"{target_url}/display_revocation_authorization",
        data_payload={
            "url_data": deeplink_url,
            "redirect_url": cfgservice.service_url,
            "qrcode": qr_img_base64,
            "presentation_id": response_cross["transaction_id"],
        },
    )


def b64url_decode(data):
    if not re.fullmatch(r"[A-Za-z0-9\-_]*", data):
        raise ValueError("Invalid base64url characters in input")

    padding = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except Exception as e:
        raise ValueError(f"Invalid base64 data: {e}")


def extract_public_key_from_x5c(
    jwt_raw: str,
) -> Tuple[CertificatePublicKeyTypes, str]:
    """
    Extract the public key and algorithm from the x5c header in a JWT.

    This function does NOT trust the JWT; it only extracts the public key
    to be used later for signature verification.

    Args:
        jwt_raw (str): The raw JWT as a string.

    Raises:
        ValueError: If the x5c header is missing or the key type is unsupported.

    Returns:
        Tuple[CertificatePublicKeyTypes, str]: A tuple containing the public key
        extracted from the x5c certificate and the algorithm from the JWT header.
    """
    unverified_header = jwt.get_unverified_header(jwt_raw)

    x5c_chain = unverified_header.get("x5c")
    if not x5c_chain:
        raise ValueError("x5c header not found in JWT")

    x5c_cert_der = b64url_decode(x5c_chain[0])
    x509_cert = x509.load_der_x509_certificate(x5c_cert_der, default_backend())
    return x509_cert.public_key(), unverified_header["alg"]


def verify_and_decode_sdjwt(sd_jwt: str) -> dict:
    """
    Verify the signature of a base64url-encoded SD-JWT using its embedded x5c certificate
    and decode its payload.

    Args:
        sd_jwt (str): The SD-JWT encoded with base64url.

    Raises:
        ValueError: If the x5c certificate is missing or malformed, the public key type is unsupported,
                    or the JWT signature verification fails.

    Returns:
        dict: The decoded payload of the SD-JWT as a dictionary.
    """
    sdjwt_holder = SDJWTHolder(
        sd_jwt,
    )

    public_key, alg = extract_public_key_from_x5c(sdjwt_holder._unverified_input_sd_jwt)

    # Check if the key type is supported by PyJWT
    if isinstance(
        public_key,
        (
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
        ),
    ):
        decoded_jwt = jwt.decode(
            sdjwt_holder._unverified_input_sd_jwt,
            key=public_key,
            algorithms=[alg],
        )
    else:
        raise ValueError(f"Unsupported key type: {type(public_key)}")

    return decoded_jwt


def get_status_sdjwt(sd_jwt: str) -> dict:
    """
    Verifies a base64url-encoded SD-JWT and extracts the 'status' claim.

    Args:
        sd_jwt (str): A base64url-encoded SD-JWT in compact serialization format.

    Raises:
        ValueError: If the JWT is invalid, the x5c certificate is missing or malformed,
                    or the public key type is unsupported.

    Returns:
        dict: The value of the 'status' claim from the decoded JWT payload.
    """

    decoded = verify_and_decode_sdjwt(sd_jwt)

    return decoded["status"]


def get_status_mdoc(mdoc_credential: str) -> Union[list, dict]:
    """
    Decodes a base64url-encoded mdoc credential and extracts the status information.

    Args:
        mdoc_credential (str): A base64url-encoded mdoc credential string.

    Returns:
        Union[list, dict]: The 'status' field(s) extracted from the document(s).
            Returns a dict if only one document is present,
            or a list of dicts if multiple documents are present.
    """

    mdoc_bytes = b64url_decode(mdoc_credential)

    mdoc = cbor2.loads(mdoc_bytes)

    print("\nlen documents: ", len(mdoc["documents"]))

    if len(mdoc["documents"]) == 1:
        status = cbor2.loads(
            cbor2.loads(mdoc["documents"][0]["issuerSigned"]["issuerAuth"][2]).value
        )["status"]

        print("\nstatus: ", status)
        print("\nstatus type: ", type(status))
        return status

    else:
        statuses = []
        for document in mdoc["documents"]:
            statuses.append(
                cbor2.loads(
                    cbor2.loads(document["issuerSigned"]["issuerAuth"][2]).value
                )["status"]
            )

        print("\nstatuses: ", statuses)
        print("\nstatuses type: ", type(statuses))
        return statuses


@revocation.route("getoid4vp", methods=["GET", "POST"])
def oid4vp_get():

    if "response_code" in request.args and "session_id" in request.args:
        cfgservice.app_logger.info(
            ", Session ID: " + session["session_id"] + ", " + "oid4vp flow: same_device"
        )

        response_code = request.args.get("response_code")
        """ presentation_id = oid4vp_requests[request.args.get("session_id")]["response"][
            "transaction_id"
        ] """

        # Validate presentation_id: allow only base64url characters (alphanumeric, '-', '_')
        """ if not re.fullmatch(r"[A-Za-z0-9\-_]+", presentation_id):
            raise ValueError("Invalid presentation_id")

        url = (
            cfgservice.dynamic_presentation_url
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
            + "&response_code="
            + response_code
        ) """

    elif "presentation_id" in request.args:
        presentation_id = request.args["presentation_id"]
        print("\npresentation_id", presentation_id)

        # Validate presentation_id: allow only base64url characters (alphanumeric, '-', '_')
        if not re.fullmatch(r"[A-Za-z0-9\-_]+", presentation_id):
            raise ValueError("Invalid presentation_id")

        url = (
            cfgservice.dynamic_presentation_url
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
        )

    else:
        return jsonify({"error": "Missing required parameters"}), 400

    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg = str(response.status_code)
        return jsonify({"error": error_msg}), 400

    response_json = response.json()

    print("\nresponse: ", response_json)

    credentials = {"dc+sd-jwt": [], "mso_mdoc": []}

    resp = {"dc+sd-jwt": [], "mso_mdoc": []}

    if len(response_json["vp_token"]) == 1:

        format = response_json["presentation_submission"]["descriptor_map"][0]["format"]

        if format == "mso_mdoc":
            credentials["mso_mdoc"].append(response_json["vp_token"][0])
        elif format == "dc+sd-jwt":
            credentials["dc+sd-jwt"].append(response_json["vp_token"][0])

    else:
        for descriptor_map in response_json["presentation_submission"][
            "descriptor_map"
        ]:
            format = descriptor_map["format"]
            path = descriptor_map["path"]

            # get array index from json path
            index = int(path[path.find("[") + 1 : path.find("]")])

            # print("\nformat", format)
            # print("\nindex", index)
            # print("\ncredential", response_json["vp_token"][index])

            if format == "mso_mdoc":
                credentials["mso_mdoc"].append(response_json["vp_token"][index])
            elif format == "dc+sd-jwt":
                credentials["dc+sd-jwt"].append(response_json["vp_token"][index])
            if format == "mso_mdoc":
                credentials["mso_mdoc"].append(response_json["vp_token"][index])
            elif format == "dc+sd-jwt":
                credentials["dc+sd-jwt"].append(response_json["vp_token"][index])

    print("\ncredentials: ", credentials)
    print("\nmso_mdoc len: ", len(credentials["mso_mdoc"]))

    for credential in credentials["mso_mdoc"]:

        statuses = get_status_mdoc(credential)
        if isinstance(statuses, list):
            resp["mso_mdoc"].extend(statuses)
        else:
            resp["mso_mdoc"].append(statuses)

    for credential in credentials["dc+sd-jwt"]:
        resp["dc+sd-jwt"].append(get_status_sdjwt(credential))

    display_list = {"dc+sd-jwt": [], "mso_mdoc": []}

    for _format in resp:
        for _status in resp[_format]:
            if "status_list" in _status:
                parsed_url = urlparse(_status["status_list"]["uri"])
                path = parsed_url.path
                path_parts = path.strip("/").split("/")
                doctype = path_parts[2]
                status_list_identifier = path_parts[3]
                display_list[_format].append(
                    {
                        "doctype": doctype,
                        "status_list_identifier": status_list_identifier,
                    }
                )

    print(display_list)

    revocation_id = generate_unique_id()

    revocation_requests.update(
        {
            revocation_id: {
                "status_lists": resp,
                "expires": datetime.now()
                + timedelta(minutes=cfgservice.revocation_code_expiry),
            }
        }
    )

    target_url = ConfFrontend.registered_frontends[cfgservice.default_frontend]["url"]

    return post_redirect_with_payload(
        target_url=f"{target_url}/display_revocation_authorization",
        data_payload={
            "display_list": display_list,
            "redirect_url": f"{cfgservice.service_url}revocation/revoke",
            "revocation_identifier": revocation_id,
            "revocation_choice_url": f"{cfgservice.service_url}revocation/revocation_choice",
        },
    )


@revocation.route("revoke", methods=["GET", "POST"])
def revoke():

    revocation_identifier = request.form.get("revocation_identifier")

    if not revocation_identifier:
        abort(400, description="Missing revocation identifier")

    if revocation_identifier not in revocation_requests:
        abort(404, description="Invalid or expired revocation identifier")

    status_lists = revocation_requests[revocation_identifier]["status_lists"]

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Api-Key": cfgservice.revocation_api_key,
    }

    print("\nresp: ", status_lists)
    for _format in status_lists:
        for _status in status_lists[_format]:
            if "identifier_list" in _status:
                id = _status["identifier_list"]["id"]
                uri = _status["identifier_list"]["uri"]

                payload = f"uri={quote_plus(uri)}&id={id}&status=1"

                try:
                    response = requests.post(
                        cfgservice.revoke_service_url, headers=headers, data=payload
                    )
                    if response.status_code == 200:
                        print(f"[OK] {uri} id={id}")
                    else:
                        print(
                            f"[FAIL] {uri} id={id} -> {response.status_code} {response.text}"
                        )

                except Exception as e:
                    print(f"[ERROR] {uri} id={id} -> {e}")

            if "status_list" in _status:
                idx = _status["status_list"]["idx"]
                uri = _status["status_list"]["uri"]

                payload = f"uri={quote_plus(uri)}&idx={idx}&status=1"

                try:
                    response = requests.post(
                        cfgservice.revoke_service_url, headers=headers, data=payload
                    )
                    if response.status_code == 200:
                        print(f"[OK] {uri} idx={idx}")
                    else:
                        print(
                            f"[FAIL] {uri} idx={idx} -> {response.status_code} {response.text}"
                        )

                except Exception as e:
                    print(f"[ERROR] {uri} idx={idx} -> {e}")

    revocation_requests.pop(revocation_identifier)

    target_url = ConfFrontend.registered_frontends[cfgservice.default_frontend]["url"]

    return post_redirect_with_payload(
        target_url=f"{target_url}/display_revocation_success",
        data_payload={
            "redirect_url": cfgservice.service_url,
        },
    )
