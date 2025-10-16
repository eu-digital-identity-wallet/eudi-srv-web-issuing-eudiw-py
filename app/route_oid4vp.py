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
The oid4vp route implements the communication with an openid4vp backend service.

It has support for both same device and cross device oid4vp
"""

import base64
from datetime import date, timedelta, datetime
import io
import json
import re
from urllib.parse import urlparse
from uuid import uuid4
from flask import Blueprint, Flask, jsonify, render_template, request, session
from flask_cors import CORS
import requests
import segno
from misc import (
    generate_unique_id,
    authentication_error_redirect,
    getAttributesForm,
    getAttributesForm2,
    scope2details,
)
from formatter_func import cbor2elems

from app.validate_vp_token import validate_vp_token
from .app_config.config_service import ConfService as cfgservice
from . import session_manager
from . import oidc_metadata

oid4vp = Blueprint("oid4vp", __name__, url_prefix="/")
CORS(oid4vp)  # enable CORS on the blue print


@oid4vp.route("/oid4vp", methods=["GET"])
def openid4vp():

    session_id = session["session_id"]

    current_request = session_manager.get_session(session_id=session_id)

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Authorization selection, Type: "
        + "oid4vp"
    )

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    dcql_credentials = []
    query_id_counter = 0

    for credential_requested in current_request.credentials_requested:
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

    print("\npayload_cross_device", payload_cross_device)

    headers = {
        "Content-Type": "application/json",
    }

    response_cross = requests.request(
        "POST", url[:-1], headers=headers, data=payload_cross_device
    ).json()

    response_same = requests.request(
        "POST", url[:-1], headers=headers, data=payload_same_device
    ).json()

    print("\nresponse_cross: ", response_cross)
    print("\nresponse_same: ", response_same)

    session_manager.update_oid4vp_transaction_id(
        session_id=session_id, oid4vp_transaction_id=response_same["transaction_id"]
    )

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

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=4,
    ) """
    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "openid/pid_login_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response_cross["transaction_id"],
        redirect_url=cfgservice.service_url,
    )


@oid4vp.route("/getpidoid4vp", methods=["GET"])
def getpidoid4vp():

    if "response_code" in request.args and "session_id" in request.args:
        cfgservice.app_logger.info(
            ", Session ID: " + session["session_id"] + ", " + "oid4vp flow: same_device"
        )

        current_session = session_manager.get_session(session_id=session["session_id"])

        response_code = request.args.get("response_code")

        presentation_id = current_session.oid4vp_transaction_id

        url = f"{cfgservice.dynamic_presentation_url}{presentation_id}?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=&response_code={response_code}"

    elif "presentation_id" in request.args:
        cfgservice.app_logger.info(
            f", Session ID: {session['session_id']}, oid4vp flow: cross_device"
        )

        presentation_id = request.args.get("presentation_id")

        if not presentation_id:
            raise ValueError("Presentation id is required")

        if not re.match(r"^[A-Za-z0-9_-]+$", presentation_id):
            raise ValueError("Invalid Presentation id format")

        url = f"{cfgservice.dynamic_presentation_url}{presentation_id}?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="

    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg = str(response.status_code)
        return jsonify({"error": error_msg}), 400

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)
    error, error_msg = validate_vp_token(
        response.json(), current_session.credentials_requested
    )

    if error == True:
        cfgservice.app_logger.error(
            ", Session ID: " + session_id + ", " + "OID4VP error: " + error_msg
        )
        return authentication_error_redirect(
            jws_token=current_session.jws_token,
            error="invalid_request",
            error_description=error_msg,
        )

    mdoc_json = cbor2elems(response.json()["vp_token"]["query_0"][0] + "==")
    is_ageOver18 = False
    attributesForm = {}

    if current_session.authorization_details:

        for credential_id in current_session.authorization_details:
            if isinstance(credential_id, dict):
                if "credential_configuration_id" in credential_id:
                    if (
                        credential_id["credential_configuration_id"]
                        == "eu.europa.ec.eudi.pseudonym_over18_mdoc"
                        or credential_id["credential_configuration_id"]
                        == "eu.europa.ec.eudi.pseudonym_over18_mdoc_deferred_endpoint"
                    ):
                        is_ageOver18 = True
                        attributesForm.update({"user_pseudonym": str(uuid4())})
                elif "vct" in credential_id:
                    if (
                        credential_id["vct"]
                        == "urn:eu.europa.ec.eudi:pseudonym_age_over_18:1"
                    ):
                        attributesForm.update({"user_pseudonym": str(uuid4())})

    elif current_session.scope:
        cred_scopes = current_session.scope
        if (
            "eu.europa.ec.eudi.pseudonym.age_over_18.1" in cred_scopes
            or "eu.europa.ec.eudi.pseudonym.age_over_18.deferred_endpoint"
            in cred_scopes
        ):
            is_ageOver18 = True
            attributesForm.update({"user_pseudonym": str(uuid4())})

    if is_ageOver18 == True:
        for doctype in mdoc_json:
            for attribute, value in mdoc_json[doctype]:
                if attribute == "age_over_18":
                    attributesForm.update({attribute: value})

        doctype_config = cfgservice.config_doctype[
            "eu.europa.ec.eudi.pseudonym.age_over_18.1"
        ]

        attributesForm.update({"issuing_country": "FC"})
        attributesForm.update(
            {"issuing_authority": doctype_config["issuing_authority"]}
        )
        if "credential_type" in doctype_config:
            attributesForm.update(
                {"credential_type": doctype_config["credential_type"]}
            )

        """ user_id = generate_unique_id()
        form_dynamic_data[user_id] = attributesForm.copy()

        form_dynamic_data[user_id].update(
            {"expires": datetime.now() + timedelta(minutes=cfgservice.form_expiry)}
        ) """

        session_manager.update_user_data(
            session_id=session_id, user_data=attributesForm
        )
        session_manager.update_country(session_id=session_id, country="FC")

        presentation_data = {}

        presentation_data["Age over 18 Pseudonym"] = attributesForm.copy()

        today = date.today()
        expiry = today + timedelta(days=doctype_config["validity"])

        presentation_data["Age over 18 Pseudonym"].update(
            {"estimated_issuance_date": today.strftime("%Y-%m-%d")}
        )
        presentation_data["Age over 18 Pseudonym"].update(
            {"estimated_expiry_date": expiry.strftime("%Y-%m-%d")}
        )

        return render_template(
            "dynamic/form_authorize.html",
            presentation_data=presentation_data,
            user_id=session_id,
            redirect_url=cfgservice.service_url + "dynamic/redirect_wallet",
        )
    else:

        attributesForm = getAttributesForm(current_session.credentials_requested)
        if "user_pseudonym" in attributesForm:
            attributesForm.update(
                {"user_pseudonym": {"type": "string", "filled_value": str(uuid4())}}
            )

        attributesForm2 = getAttributesForm2(current_session.credentials_requested)

        for doctype in mdoc_json:
            for attribute, value in mdoc_json[doctype]:
                if attribute in attributesForm:
                    attributesForm[attribute]["filled_value"] = value
                elif attribute in attributesForm2:
                    attributesForm2[attribute]["filled_value"] = value

        session_manager.update_country(session_id=session_id, country="FC")

        return render_template(
            "dynamic/dynamic-form.html",
            mandatory_attributes=attributesForm,
            optional_attributes=attributesForm2,
            redirect_url=cfgservice.service_url + "dynamic/form",
        )
