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
The Dynamic Issuer Web service is a component of the Dynamic Provider backend.
Its main goal is to issue the credentials in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This route_dynamic.py file is the blueprint for the route /dynamic of the PID Issuer Web service.
"""
from datetime import datetime, timezone
from datetime import date
from datetime import timedelta
import io
import json
import base64
import re
import secrets
from formatter_func import cbor2elems
import threading
import schedule
import time
from urllib.parse import urlencode
from uuid import uuid4
from PIL import Image
from flask import (
    Blueprint,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    session,
    jsonify,
    url_for,
)
from flask_api import status
from flask_cors import CORS
import requests
from app.lighttoken import handle_response
from app.validate_vp_token import validate_vp_token

from boot_validate import (
    validate_mandatory_args,
)

from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries
from redirect_func import url_get
from misc import (
    authentication_error_redirect,
    convert_png_to_jpeg,
    credential_error_resp,
    generate_unique_id,
    getAttributesForm,
    getAttributesForm2,
    scope2details,
    calculate_age,
    validate_image,
    vct2doctype,
    vct2id,
    vct2scope,
)
from dynamic_func import dynamic_formatter
from . import oidc_metadata
from . import session_manager

# /pid blueprint
dynamic = Blueprint("dynamic", __name__, url_prefix="/dynamic")
CORS(dynamic)  # enable CORS on the blue print

# secrets
from app_config.config_secrets import flask_secret_key

# app.config["SECRET_KEY"] = flask_secret_key
# app.config["dynamic"] = {}

from app.data_management import form_dynamic_data


@dynamic.route("/", methods=["GET", "POST"])
def Supported_Countries():
    """Initial PID page.
    Loads country config information and renders pid_index.html so that the user can select the PID issuer country.
    """

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template(
            "misc/auth_method.html", redirect_url=cfgserv.service_url
        )

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)
    # session["credentials_requested"] = credentials_requested

    display_countries = {}
    for country in cfgcountries.supported_countries:
        res = all(
            ele in cfgcountries.supported_countries[country]["supported_credentials"]
            for ele in current_session.credentials_requested
        )
        if res:
            display_countries.update(
                {str(country): str(cfgcountries.supported_countries[country]["name"])}
            )

    if len(display_countries) == 1:
        country = next(iter(display_countries))

        # session["returnURL"] = cfgserv.OpenID_first_endpoint
        # session["country"] = country

        cfgserv.app_logger.info(
            ", Session ID: "
            + session["session_id"]
            + ", "
            + "Authorization selection, Type: "
            + country
        )
        return dynamic_R1(country)

    # render page where user can select pid_countries

    # session["authorization_params"] = {"token": token}

    # print("\nsession token: ", session)

    # session["jws_token"] = token  # authorization_params["token"]

    return render_template(
        "dynamic/dynamic-countries.html",
        countries=display_countries,
        authorization_details=json.dumps(current_session.authorization_details),
        redirect_url=cfgserv.service_url,
    )


@dynamic.route("/country_selected", methods=["GET", "POST"])
def country_selected():
    # form_keys = request.form.keys()
    form_country = request.form.get("country")

    # session["returnURL"] = cfgserv.OpenID_first_endpoint
    # session["country"] = form_country

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template(
            "misc/auth_method.html", redirect_url=cfgserv.service_url
        )

    cfgserv.app_logger.info(
        ", Session ID: "
        + session["session_id"]
        + ", "
        + "Authorization selection, Type: "
        + form_country
    )

    return dynamic_R1(form_country)


def dynamic_R1(country):
    """
    Function to create url to redirect to the selected credential issuer country

    Keyword arguments:
    country -- Country selected by user
    """

    session_id = session["session_id"]
    session_manager.update_country(session_id=session_id, country=country)

    current_session = session_manager.get_session(session_id=session_id)

    credentials_requested = current_session.credentials_requested
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    """ log.logger_info.info(
        " - INFO -  Version:"
        + cfgserv.current_version
        + " -  URL_R1 for Country: "
        + country
        + " has been created"
    ) """

    if country == "FC":

        mandatory_attributes = getAttributesForm(current_session.credentials_requested)
        if "user_pseudonym" in mandatory_attributes:
            mandatory_attributes.update(
                {"user_pseudonym": {"type": "string", "filled_value": str(uuid4())}}
            )

        optional_attributes_raw = getAttributesForm2(
            current_session.credentials_requested
        )

        print("\nMandatory: ", mandatory_attributes)
        print("\nOptional: ", optional_attributes_raw)

        optional_attributes_filtered = {
            key: value
            for key, value in optional_attributes_raw.items()
            if key not in mandatory_attributes
        }

        return render_template(
            "dynamic/dynamic-form.html",
            mandatory_attributes=mandatory_attributes,
            optional_attributes=optional_attributes_filtered,
            redirect_url=cfgserv.service_url + "dynamic/form",
        )

    elif country == "sample":

        session_manager.update_user_data(
            session_id=session_id, user_data=cfgserv.sample_data.copy()
        )

        """ form_dynamic_data[user_id] = cfgserv.sample_data.copy()
        form_dynamic_data[user_id].update(
            {"expires": datetime.now() + timedelta(minutes=cfgserv.form_expiry)}
        ) """

        # session["returnURL"] = cfgserv.OpenID_first_endpoint

        return redirect(
            url_get(
                cfgserv.OpenID_first_endpoint,
                {
                    "token": current_session.jws_token,
                    "username": session_id,
                },
            )
        )

    elif cfgcountries.supported_countries[country]["connection_type"] == "eidasnode":
        return redirect(
            generate_connector_authorization_url(
                country=country, credentials_requested=credentials_requested
            )
        )
        # return redirect(cfgcountries.supported_countries[country]["pid_url_oidc"])

    elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
        oauth_data = cfgcountries.supported_countries[country]["oauth_auth"]

        return redirect(
            generate_connector_authorization_url(
                oauth_data=oauth_data,
                country=country,
                credentials_requested=credentials_requested,
            )
        )

        return redirect(url)

    elif cfgcountries.supported_countries[country]["connection_type"] == "openid":

        country_data = cfgcountries.supported_countries[country]["oidc_auth"]

        metadata_url = country_data["base_url"] + "/.well-known/openid-configuration"
        metadata_json = requests.get(metadata_url).json()

        authorization_endpoint = metadata_json["authorization_endpoint"]

        url = authorization_endpoint + "?redirect_uri=" + country_data["redirect_uri"]

        if country == "EE":
            country_data["state"] = country + "." + current_session.jws_token

        for url_part in country_data:
            if (
                url_part == "url"
                or url_part == "redirect_uri"
                or url_part == "base_url"
            ):
                pass
            else:
                url = url + "&" + url_part + "=" + country_data[url_part]

        return redirect(url)


@dynamic.route("/redirect", methods=["GET", "POST"])
def red():
    """Receives token from different IDPs

    GET parameters:
    + code (mandatory) - Token code to retrieve the shared attributes consented by the user.
    + scope (mandatory) - scope of the request.
    + state (mandatory) - state of the request.

    Return: Redirect answer to returnURL.
    """
    # session["route"] = "/dynamic/redirect"

    session_id = session["session_id"]
    print("\nsession_id ", session_id)
    current_session = session_manager.get_session(session_id=session_id)

    """ if current_session.country == "PT":

        if not request.args:  # if args is empty
            return render_template("/dynamic/pt_url.html")

        (v, l) = validate_mandatory_args(request.args, ["access_token"])
        if not v:  # if not all arguments are available
            return authentication_error_redirect(
                jws_token=current_session.jws_token,
                error="Missing mandatory args-PT",
                error_description="Missing mandatory PT-IdP fields",
            )

        token = request.args.get("access_token")

        if not token:
            raise ValueError("Access token is required")

        if not re.match(r"^[A-Za-z0-9_-]+$", token):
            raise ValueError("Invalid token format")

        r1 = requests.post(
            "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager",
            json={"token": token},
        )

        cfgserv.app_logger.info(
            " - INFO - "
            + "dynamic/redirect"
            + " - Version:"
            + cfgserv.current_version
            + " - Country: "
            + current_session.country
            + " -  entered the route"
        )

        data = dynamic_R2_data_collect(
            country=current_session.country,
            user_id=token
            + "&authenticationContextId="
            + r1.json()["authenticationContextId"],
        )

        if "error" in data and data["error"] == "Pending" and "response" in data:
            data = data["response"]

        # i = 0
        #while "error" in data and data["error"] == "Pending" and i < 20:
        #    time.sleep(2)
        #    data = dynamic_R2_data_collect(
        #    country=session["country"], user_id= token + "&authenticationContextId=" + r1.json()["authenticationContextId"]
        #    )
        #    i =+ 2

        portuguese_fields = dict()
        form_data = {}

        credential_requested = current_session.credentials_requested
        credentialsSupported = oidc_metadata["credential_configurations_supported"]

        for id in credential_requested:
            format = credentialsSupported[id]["format"]
            if format == "mso_mdoc":
                doctype = credentialsSupported[id]["doctype"]
            elif format == "dc+sd-jwt":
                doctype = credentialsSupported[id]["issuer_config"]["doctype"]

            portuguese_fields.update(
                {
                    doctype: {
                        "config": cfgcountries.supported_countries["PT"]["oidc_auth"][
                            "scope"
                        ][doctype],
                        "format": format,
                    }
                }
            )

        for doctype in portuguese_fields:
            for fields in portuguese_fields[doctype]["config"]:
                for item in data:
                    if item["name"] == portuguese_fields[doctype]["config"][fields]:
                        if item["state"] == "Pending":
                            value = "Pending"
                        else:
                            value = item["value"]

                        if doctype not in form_data:
                            form_data.update({doctype: {fields: value}})
                        else:
                            form_data[doctype].update({fields: value})
                        # form_data[doctype][fields] = item["value"]
                        break

        for doctype in portuguese_fields:
            if (
                "birth_date" in form_data[doctype]
                and form_data[doctype]["birth_date"] != "Pending"
            ):
                form_data[doctype]["birth_date"] = datetime.strptime(
                    form_data[doctype]["birth_date"], "%d-%m-%Y"
                ).strftime("%Y-%m-%d")

            if (
                "driving_privileges" in form_data[doctype]
                and form_data[doctype]["driving_privileges"] != "Pending"
            ):
                json_priv = json.loads(form_data[doctype]["driving_privileges"])
                form_data[doctype].update({"driving_privileges": json_priv})

            if (
                "driving_privileges" in form_data[doctype]
                and form_data[doctype]["driving_privileges"] == "Pending"
            ):
                json_priv = [
                    {
                        "Type": "Pending",
                        "IssueDate": "Pending",
                        "ExpiryDate": "Pending",
                        "Restriction": [],
                    }
                ]
                form_data[doctype].update({"driving_privileges": json_priv})

            doctype_config = cfgserv.config_doctype[doctype]

            today = date.today()
            expiry = today + timedelta(days=doctype_config["validity"])

            #if form_data[doctype]["birth_date"] != "Pending":
            #    form_data[doctype].update({"age_over_18": True if calculate_age(form_data[doctype]["birth_date"]) >= 18 else False})
            #else:
            #    form_data[doctype].update({"age_over_18":"Pending"})

            form_data[doctype].update(
                {"estimated_issuance_date": today.strftime("%Y-%m-%d")}
            )
            form_data[doctype].update(
                {"estimated_expiry_date": expiry.strftime("%Y-%m-%d")}
            )
            form_data[doctype].update({"issuing_country": current_session.country})
            form_data[doctype].update(
                {"issuing_authority": doctype_config["issuing_authority"]}
            )
            if "credential_type" in doctype_config:
                form_data[doctype].update(
                    {"credential_type": doctype_config["credential_type"]}
                )

            if portuguese_fields[doctype]["format"] == "mso_mdoc":
                form_data[doctype]["nationality"] = ["PT"]
                form_data[doctype]["birth_place"] = "Lisboa"
            elif portuguese_fields[doctype]["format"] == "dc+sd-jwt":
                form_data[doctype]["place_of_birth"] = [{"locality": "Lisboa"}]
                form_data[doctype]["nationalities"] = ["PT"]

        user_id = (
            current_session.country
            + "."
            + token
            + "&authenticationContextId="
            + r1.json()["authenticationContextId"]
        )

        return render_template(
            "dynamic/form_authorize.html",
            presentation_data=form_data,
            user_id=user_id,
            redirect_url=cfgserv.service_url + "dynamic/redirect_wallet",
        )

    elif current_session.country is None:

        country, jws_token = request.args.get("state").split(".")

        session_manager.update_country(session_id=session_id, country=country)

        session_manager.update_jws_token(session_id=session_id, jws_token=jws_token)
        # session["jws_token"] = jws_token
        # session["country"] = country """

    (v, l) = validate_mandatory_args(request.args, ["code"])
    if not v:  # if not all arguments are available
        return authentication_error_redirect(
            jws_token=current_session.jws_token,
            error="Missing fields",
            error_description="Missing mandatory IdP fields",
        )

    auth_code = request.args.get("code")

    country_config = cfgcountries.supported_countries[current_session.country]

    metadata_url = (
        country_config["oauth_auth"]["base_url"]
        + "/.well-known/oauth-authorization-server"
    )

    metadata_json = requests.get(metadata_url).json()

    token_endpoint = metadata_json["token_endpoint"]

    token_endpoint_headers = {}
    if (
        "token_endpoint" in country_config["oauth_auth"]
        and "header" in country_config["oauth_auth"]["token_endpoint"]
    ):
        token_endpoint_headers = country_config["oauth_auth"]["token_endpoint"][
            "headers"
        ]

    if (
        "oauth_auth" in country_config
        and "client_id" in country_config["oauth_auth"]
        and "client_secret" in country_config["oauth_auth"]
    ):
        auth_string = f"{country_config['oauth_auth']['client_id']}:{country_config['oauth_auth']['client_secret']}"
        encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")

        token_endpoint_headers["Authorization"] = f"Basic {encoded_auth}"

    data = f"code={request.args.get('code')}"

    params = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": country_config["oauth_auth"]["redirect_uri"],
    }

    try:
        response = requests.post(
            token_endpoint,
            data=params,
            headers=token_endpoint_headers,
        )

        response.raise_for_status()
        token_data = response.json()
        print("Access Token:", token_data.get("access_token"))

        access_token = token_data.get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

    session["access_token"] = access_token

    cfgserv.app_logger.info(
        f" - INFO - /dynamic/redicret - Version:{cfgserv.current_version} - Country: {current_session.country} - Code: {request.args.get('code')} - entered the route"
    )

    data = dynamic_R2_data_collect(
        country=current_session.country, session_id=session_id, access_token=access_token
    )

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    presentation_data = dict()

    for credential_requested in current_session.credentials_requested:

        scope = credentialsSupported[credential_requested]["scope"]

        """ if scope in cfgserv.common_name:
            credential=cfgserv.common_name[scope]

        else:
            credential = scope  """

        credential = credentialsSupported[credential_requested]["credential_metadata"][
            "display"
        ][0]["name"]

        presentation_data.update({credential: {}})

        credential_atributes_form = list()
        credential_atributes_form.append(credential_requested)
        attributesForm = getAttributesForm(credential_atributes_form).keys()

        for attribute in data.keys():
            if attribute in attributesForm:
                presentation_data[credential][attribute] = data[attribute]

        doctype_config = credentialsSupported[credential_requested]["issuer_config"]

        today = date.today()
        expiry = today + timedelta(days=doctype_config["validity"])

        presentation_data[credential].update(
            {"estimated_issuance_date": today.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"estimated_expiry_date": expiry.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"issuing_country": current_session.country}
        ),

        if credential_requested == "eu.europa.ec.eudi.ehic_sd_jwt_vc":
            presentation_data[credential].update(
                {
                    "issuing_authority": {
                        "id": doctype_config["issuing_authority_id"],
                        "name": doctype_config["issuing_authority"],
                    }
                }
            )
        else:
            presentation_data[credential].update(
                {"issuing_authority": doctype_config["issuing_authority"]}
            )

        if "credential_type" in doctype_config:
            presentation_data[doctype].update(
                {"credential_type": doctype_config["credential_type"]}
            )

        if "birth_date" in presentation_data[credential]:
            presentation_data[credential].update(
                {
                    "age_over_18": (
                        True
                        if calculate_age(presentation_data[credential]["birth_date"])
                        >= 18
                        else False
                    )
                }
            )

        if "driving_privileges" in presentation_data[credential] and isinstance(
            presentation_data[credential]["driving_privileges"], str
        ):
            json_priv = json.loads(presentation_data[credential]["driving_privileges"])
            presentation_data[credential].update({"driving_privileges": json_priv})

        fields_to_decode = [
            "portrait",
            "image",
            "signature_usual_mark",
        ]  # Add any other fields here

        for field in fields_to_decode:
            if field in presentation_data[credential]:
                presentation_data[credential].update(
                    {
                        field: base64.b64encode(
                            base64.urlsafe_b64decode(
                                presentation_data[credential][field]
                            )
                        ).decode("utf-8")
                    }
                )

        if "NumberCategories" in presentation_data[credential]:
            for i in range(int(presentation_data[credential]["NumberCategories"])):
                f = str(i + 1)
                presentation_data[credential].pop("IssueDate" + f)
                presentation_data[credential].pop("ExpiryDate" + f)
            presentation_data[credential].pop("NumberCategories")

    user_id = current_session.country + "." + session["access_token"]

    print("\npresentation_data: ", presentation_data)
    return render_template(
        "dynamic/form_authorize.html",
        presentation_data=presentation_data,
        user_id=user_id,
        redirect_url=cfgserv.service_url + "dynamic/redirect_wallet",
    )


@dynamic.route("/dynamic_R2", methods=["GET", "POST"])
def dynamic_R2():
    """Route acessed by OpenID to get PID attributes from country FC

    Get query parameters:
    + user_id - token to obtain PID attributes

    Return:PID in sd-jwt and mdoc formats

    """

    json_request = request.json

    (v, l) = validate_mandatory_args(json_request, ["user_id", "credential_requests"])

    if not v:
        return {
            "error": "invalid_credential_request",
            "error_description": "missing fields in json",
        }

    user_id = json_request["user_id"]

    current_session = session_manager.get_session(session_id=user_id)

    country = current_session.country

    credential_request = json_request["credential_requests"]

    # session["country"] = country
    # session["version"] = cfgserv.current_version
    # session["route"] = "/dynamic/form_R2"

    data = current_session.user_data #dynamic_R2_data_collect(country=country, user_id=user_id)

    print("\ndynamic_r2 data: ", data)
    """ if "error" in data:
        return data """

    # log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")

    credential_response = credentialCreation(
        credential_request=credential_request,
        data=data,
        country=country,
        session_id=user_id,
    )

    return credential_response


def dynamic_R2_data_collect(country, session_id, access_token):
    """
    Funtion to get attributes from selected credential issuer country

    Keyword arguments:"
    user_id -- user identifier needed to get respective attributes
    country -- credential issuing country that user selected
    """

    if country == "FC":

        current_session = session_manager.get_session(session_id=session_id)

        data = (
            current_session.user_data
        )  # form_dynamic_data.get(user_id, "Data not found")

        if data == "Data not found":
            return {"error": "error", "error_description": "Data not found"}

        # session["version"] = cfgserv.current_version
        # session["country"] = data["issuing_country"]

        print("\ndynamic_R2_data_collect user_data: ", data)
        return data

    if country == "sample":
        # data = form_dynamic_data.get(user_id, "Data not found")

        """if data == "Data not found":
        return {"error": "error", "error_description": "Data not found"}"""

        # session["version"] = cfgserv.current_version
        # session["country"] = data["issuing_country"]

        current_session = session_manager.get_session(session_id=session_id)

        data = current_session.user_data

        return data

    elif cfgcountries.supported_countries[country]["connection_type"] == "eidasnode":
        (b, data) = handle_response(user_id)

        if "custom_modifiers" in cfgcountries.supported_countries[country]:
            custom_modifiers = cfgcountries.supported_countries[country][
                "custom_modifiers"
            ]
            for modifier in custom_modifiers:
                if custom_modifiers[modifier] in data:
                    data[modifier] = data[custom_modifiers[modifier]]
                    data.pop(custom_modifiers[modifier])

        data["nationality"] = [country]
        data["nationalities"] = [country]

        birth_places = {
            "EU": "Brussels",
            "EE": "Tallinn",
            "CZ": "Prague",
            "NL": "Amsterdam",
            "LU": "Luxembourg",
        }

        if country in birth_places:
            data["birth_place"] = birth_places[country]
            data["place_of_birth"] = [{"locality": birth_places[country]}]

        return data

    elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":

        """attribute_request = cfgcountries.supported_countries[country][
            "attribute_request"
        ]
        url = attribute_request["url"] + user_id
        # headers = attribute_request["header"]
        try:
            r2 = requests.get(url)
            print("\nr2", r2)
            print("\nr2", r2.text)
            json_response = r2.json()
            print("\njson_response", json_response)
            for attribute in json_response:
                if attribute["state"] == "Pending":
                    return {"error": "Pending", "response": json_response}

            data = json_response

            return data
        except:
            credential_error_resp(
                "invalid_credential_request", "openid connection failed"
            )"""

        metadata_url = (
            cfgcountries.supported_countries[country]["oauth_auth"]["base_url"]
            + "/.well-known/oauth-authorization-server"
        )

        metadata_json = requests.get(metadata_url).json()

        user_info_endpoint = metadata_json["userinfo_endpoint"]

        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(user_info_endpoint, headers=headers)

            response.raise_for_status()

            user_data = response.json()

            print("\nbefore_user_data: ", user_data)

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fetching user data: {e}")
            if response:
                print("Response Body:", response.text)

        if "custom_modifiers" in cfgcountries.supported_countries[country]:
            custom_modifiers = cfgcountries.supported_countries[country][
                "custom_modifiers"
            ]

            for modifier in custom_modifiers:
                if custom_modifiers[modifier] in user_data:
                    user_data[modifier] = user_data[custom_modifiers[modifier]]
                    user_data.pop(custom_modifiers[modifier])

        print("\nafter_user_data: ", user_data)

        print("\nsession_id", session_id)

        user_data["nationality"] = [country]
        user_data["nationalities"] = [country]

        birth_places = {
            "EU": "Brussels",
            "EE": "Tallinn",
            "CZ": "Prague",
            "NL": "Amsterdam",
            "LU": "Luxembourg",
        }

        if country in birth_places:
            user_data["birth_place"] = birth_places[country]
            user_data["place_of_birth"] = [{"locality": birth_places[country]}]

        session_manager.update_user_data(session_id=session_id, user_data=user_data)

        return user_data

    elif cfgcountries.supported_countries[country]["connection_type"] == "openid":

        attribute_request = cfgcountries.supported_countries[country][
            "attribute_request"
        ]

        metadata_url = (
            cfgcountries.supported_countries[session["country"]]["oidc_auth"][
                "base_url"
            ]
            + "/.well-known/openid-configuration"
        )
        metadata_json = requests.get(metadata_url).json()

        userinfo_endpoint = metadata_json["userinfo_endpoint"]

        if country == "EE":
            url = userinfo_endpoint + "?access_token=" + access_token

            headers = attribute_request["header"]
        else:
            url = userinfo_endpoint
            headers = attribute_request["header"]
            headers["Authorization"] = f"Bearer {access_token}"

        try:
            r2 = requests.get(url, headers=headers)
            json_response = json.loads(r2.text)
            data = json_response
            if (
                "custom_modifiers"
                in cfgcountries.supported_countries[country]["attribute_request"]
            ):
                custom_modifiers = cfgcountries.supported_countries[country][
                    "attribute_request"
                ]["custom_modifiers"]
                for modifier in custom_modifiers:
                    if custom_modifiers[modifier] in data:
                        data[modifier] = data[custom_modifiers[modifier]]
                        data.pop(custom_modifiers[modifier])

            data["nationality"] = [country]
            data["nationalities"] = [country]

            birth_places = {
                "EE": "Tallinn",
                "CZ": "Prague",
                "NL": "Amsterdam",
                "LU": "Luxembourg",
            }

            if country in birth_places:
                data["birth_place"] = birth_places[country]
                data["place_of_birth"] = [{"locality": birth_places[country]}]

            return data
        except:
            credential_error_resp(
                "invalid_credential_request", "openid connection failed"
            )
    else:
        credential_error_resp("invalid_credential_request", "Not supported")


def credentialCreation(credential_request, data, country, session_id):
    """
    Function to create credentials requested by user

    Keyword arguments:"
    credential_request -- dictionary with credentials requested
    data -- attributes from user
    country -- credential issuing country


    """

    credentials_supported = oidc_metadata["credential_configurations_supported"]
    document_mappings = cfgserv.document_mappings

    credential_response = {"credentials": []}

    for proof in credential_request["proofs"]:

        if "credential_identifier" in credential_request:
            doctype = credentials_supported[
                credential_request["credential_identifier"]
            ]["scope"]
            format = credentials_supported[credential_request["credential_identifier"]][
                "format"
            ]

        elif "credential_configuration_id" in credential_request:

            if (
                "vct"
                in credentials_supported[
                    credential_request["credential_configuration_id"]
                ]
            ):
                doctype = vct2doctype(
                    credentials_supported[
                        credential_request["credential_configuration_id"]
                    ]["vct"]
                )
            else:
                doctype = credentials_supported[
                    credential_request["credential_configuration_id"]
                ]["doctype"]

            format = credentials_supported[
                credential_request["credential_configuration_id"]
            ]["format"]

        else:
            return {
                "error": "invalid_credential_request",
                "error_description": "invalid request",
            }

        """ elif "vct" in credential and "format" in credential:
            doctype = vct2scope(credential["vct"])
            format = credential["format"]

        elif "format" in credential and "doctype" in credential:
            format = credential["format"]
            doctype = credential["doctype"] """

        if "jwt" in proof:
            device_publickey = proof["jwt"]

        # device_publickey = credential["device_publickey"]

        # formatting_functions = document_mappings[doctype]["formatting_functions"]

        form_data = {}
        if country == "FC":
            form_data = data

        elif country == "sample":
            form_data = data

        elif (
            cfgcountries.supported_countries[country]["connection_type"] == "eidasnode"
        ):
            form_data = data

        elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
            if country == "PT":

                portuguese_fields = cfgcountries.supported_countries[country][
                    "oidc_auth"
                ]["scope"][doctype]

                for fields_pt in portuguese_fields:
                    for item in data:
                        if item["name"] == portuguese_fields[fields_pt]:
                            form_data[fields_pt] = item["value"]
                            break

                if "birth_date" in form_data:
                    form_data["birth_date"] = datetime.strptime(
                        form_data["birth_date"], "%d-%m-%Y"
                    ).strftime("%Y-%m-%d")

                if "portrait" in form_data:
                    form_data["portrait"] = base64.urlsafe_b64encode(
                        convert_png_to_jpeg(base64.b64decode(form_data["portrait"]))
                    ).decode("utf-8")

                form_data["nationality"] = ["PT"]
                form_data["nationalities"] = ["PT"]

                form_data["birth_place"] = "Lisboa"
                form_data["place_of_birth"] = [{"locality": "Lisboa"}]

            else:

                for attribute in data:
                    form_data[attribute] = data[attribute]

        elif cfgcountries.supported_countries[country]["connection_type"] == "openid":
            if country == "PT":
                portuguese_fields = cfgcountries.supported_countries[country]["oidc"][
                    "scope"
                ][doctype]

                for fields_pt in portuguese_fields:
                    for item in data:
                        if item["name"] == portuguese_fields[fields_pt]:
                            form_data[fields_pt] = item["value"]
                            break

                form_data["birth_date"] = datetime.strptime(
                    form_data["birth_date"], "%d-%m-%Y"
                ).strftime("%Y-%m-%d")

                form_data["portrait"] = base64.urlsafe_b64encode(
                    convert_png_to_jpeg(base64.b64decode(form_data["Portrait"]))
                ).decode("utf-8")

            else:

                for attribute in data:
                    form_data[attribute] = data[attribute]

        else:
            return {
                "error": "invalid_credential_request",
                "error_description": "invalid request",
            }

        form_data.update(
            {
                "issuing_country": country,
            }
        )

        pdata = dynamic_formatter(
            format, doctype, form_data, device_publickey, session_id
        )

        credential_response["credentials"].append({"credential": pdata})

        """ formatting_function_data = formatting_functions.get(format)

        if formatting_function_data:
            formatting_function = formatting_function_data["formatting_function"]
            f = globals().get(formatting_function)

            pdata = f(form_data, device_publickey)
            # credential_response.update({f"{doctype}_{format}": pdata})

            credential_response["credential_responses"].append(
                {"credential": pdata}
            ) """

    return credential_response


@dynamic.route("/auth_method", methods=["GET", "POST"])
def auth():

    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return authentication_error_redirect(
            jws_token=current_session.jws_token,
            error="Process Canceled",
            error_description="User canceled authentication",
        )
    choice = request.form.get("optionsRadios")

    choice = request.form.get("optionsRadios")
    if choice == "link1":
        return redirect(cfgserv.service_url + "oid4vp")
    elif choice == "link2":
        return redirect(cfgserv.service_url + "dynamic/")


def form_formatter(form_data: dict) -> dict:
    cleaned_data = {}

    # Handle date formatting first, as it's a simple key-value replacement
    if "effective_from_date" in form_data:
        date_part = form_data["effective_from_date"].split("T")[0]
        dt = datetime.strptime(date_part, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        rfc3339_string = dt.isoformat().replace("+00:00", "Z")
        form_data.update({"effective_from_date": rfc3339_string})

    # Regex to parse keys like 'capacities[0][codes][1][code]' into a list of parts
    key_pattern = re.compile(r"([^\[\]]+)")

    # Sort keys to ensure parent structures (e.g., capacities[0]) are processed before children (e.g., capacities[0][codes][0])
    for key in sorted(form_data.keys()):
        value = form_data[key]

        # Skip empty values and form control buttons
        if not value or key in ["proceed", "Cancelled", "NumberCategories"]:
            continue
        if "option" in key and "on" in value:
            continue

        parts = key_pattern.findall(key)

        current_level = cleaned_data
        for i, part in enumerate(parts[:-1]):
            is_numeric_index = part.isdigit()

            if is_numeric_index:
                idx = int(part)
                # Ensure the list is long enough to accommodate the index
                while len(current_level) <= idx:
                    current_level.append({})
                current_level = current_level[idx]
            else:  # It's a dictionary key (e.g., 'capacities', 'codes')
                is_next_part_index = (i + 1 < len(parts)) and parts[i + 1].isdigit()

                if is_next_part_index:
                    # If the next part is an index, this key must point to a list
                    current_level = current_level.setdefault(part, [])
                else:
                    # Otherwise, it points to a dictionary
                    current_level = current_level.setdefault(part, {})

        # Set the final value at the correct location
        final_key = parts[-1]
        if final_key.isdigit() and isinstance(current_level, list):
            idx = int(final_key)
            while len(current_level) <= idx:
                current_level.append(None)
            current_level[idx] = value
        else:
            current_level[final_key] = value

    # Fixing places of work data send after restructuring project for nested issues
    if 'places_of_work' in cleaned_data and isinstance(cleaned_data.get('places_of_work'), list):
        aggregated_data = {}
        # Loop through the list generated by the parser (e.g., [{'no_fixed_place': [...]}, {'no_fixed_place': [...]}])
        for item in cleaned_data['places_of_work']:
            if isinstance(item, dict):
                # An item is like {'no_fixed_place': [{'country_code': 't1'}]}
                for key, value_list in item.items():
                    # Initialize the key in our aggregator if it's not there
                    if key not in aggregated_data:
                        aggregated_data[key] = []
                    # Add the items from the current list to the aggregator's list
                    if isinstance(value_list, list):
                        aggregated_data[key].extend(value_list)
        
        # If we successfully aggregated data, replace the original list
        if aggregated_data:
            cleaned_data['places_of_work'] = [aggregated_data]

    # Final transformation for nationalities
    for key in ["nationality", "nationalities"]:
        if key in cleaned_data and isinstance(cleaned_data[key], list):
            # Check if the list contains dictionaries (it should from the form)
            if cleaned_data[key] and isinstance(cleaned_data[key][0], dict):
                # Use a list comprehension to extract the 'country_code' from each dictionary.
                cleaned_data[key] = [item.get('country_code') for item in cleaned_data[key] if 'country_code' in item]

    # Perform any final data transformations if necessary
    if "portrait" in cleaned_data:
        if cleaned_data["portrait"] == "Port1":
            cleaned_data["portrait"] = cfgserv.portrait1
        elif cleaned_data["portrait"] == "Port2":
            cleaned_data["portrait"] = cfgserv.portrait2
        # Note: File upload logic for Port3 remains in the main route function

    if "image" in cleaned_data:
        if cleaned_data["image"] == "Port1":
            cleaned_data["image"] = cfgserv.portrait1
        elif cleaned_data["image"] == "Port2":
            cleaned_data["image"] = cfgserv.portrait2

    if "signature_usual_mark" in cleaned_data:
        if cleaned_data["signature_usual_mark"] == "Sig1":
            cleaned_data["signature_usual_mark"] = (
                cfgserv.signature_usual_mark_issuing_officer
            )

    if "signature_usual_mark_issuing_officer" in cleaned_data:
        if cleaned_data["signature_usual_mark_issuing_officer"] == "Sig1":
            cleaned_data["signature_usual_mark_issuing_officer"] = (
                cfgserv.signature_usual_mark_issuing_officer
            )

    # Add issuer-filled data
    cleaned_data.update(
        {
            "issuing_country": session_manager.get_session(
                session["session_id"]
            ).country,
            "issuing_authority": cfgserv.mdl_issuing_authority,
        }
    )

    final_data = {}
    for item, value in cleaned_data.items():
        if item in [
            "portrait",
            "image",
            "picture",
            "signature_usual_mark",
            "signature_usual_mark_issuing_officer",
        ]:
            if value == "Port1":
                final_data[item] = cfgserv.portrait1
            elif value == "Port2":
                final_data[item] = cfgserv.portrait2
            else:
                # If it's not Port1 or Port2, it's the base64url string from the route handler.
                final_data[item] = value
        else:
            final_data[item] = value

    # Add issuer-filled data
    final_data.update(
        {
            "issuing_country": session_manager.get_session(
                session["session_id"]
            ).country,
            "issuing_authority": cfgserv.mdl_issuing_authority,
        }
    )

    return final_data


def presentation_formatter(cleaned_data: dict) -> dict:

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    presentation_data = dict()

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)
    credentials_requested = current_session.credentials_requested

    for credential_requested in credentials_requested:

        scope = credentialsSupported[credential_requested]["scope"]
        """ if scope in cfgserv.common_name:
            credential=cfgserv.common_name[scope]

        else:
            credential = scope """

        credential = credentialsSupported[credential_requested]["credential_metadata"][
            "display"
        ][0]["name"]

        presentation_data.update({credential: {}})

        credential_atributes_form = list()
        credential_atributes_form.append(credential_requested)
        attributesForm = getAttributesForm(credential_atributes_form).keys()
        attributesForm2 = getAttributesForm2(credential_atributes_form).keys()

        for attribute in cleaned_data.keys():

            if attribute in attributesForm:
                presentation_data[credential][attribute] = cleaned_data[attribute]

            if attribute in attributesForm2:
                presentation_data[credential][attribute] = cleaned_data[attribute]

        if "issuer_config" in credentialsSupported[credential_requested]:
            doctype_config = credentialsSupported[credential_requested]["issuer_config"]

        today = date.today()
        expiry = today + timedelta(days=doctype_config["validity"])

        presentation_data[credential].update(
            {"estimated_issuance_date": today.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"estimated_expiry_date": expiry.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"issuing_country": current_session.country}
        ),

        if credential_requested == "eu.europa.ec.eudi.seafarer_mdoc":
            presentation_data[credential].update(
                {
                    "issuing_authority_logo": base64.b64encode(
                        base64.urlsafe_b64decode(cfgserv.issuing_authority_logo)
                    ).decode("utf-8")
                }
            )

        if credential_requested == "eu.europa.ec.eudi.ehic_sd_jwt_vc":
            presentation_data[credential].update(
                {
                    "issuing_authority": {
                        "id": doctype_config["issuing_authority_id"],
                        "name": doctype_config["issuing_authority"],
                    }
                }
            )
        else:
            presentation_data[credential].update(
                {"issuing_authority": doctype_config["issuing_authority"]}
            )

        if "credential_type" in doctype_config:
            presentation_data[credential].update(
                {"credential_type": doctype_config["credential_type"]}
            )

        if (
            "birth_date" in presentation_data[credential]
            and "age_over_18" in presentation_data[credential]
        ):
            presentation_data[credential].update(
                {
                    "age_over_18": (
                        True
                        if calculate_age(presentation_data[credential]["birth_date"])
                        >= 18
                        else False
                    )
                }
            )

        if scope == "org.iso.18013.5.1.mDL":
            if "birth_date" in presentation_data[credential]:
                presentation_data[credential].update(
                    {
                        "age_over_18": (
                            True
                            if calculate_age(
                                presentation_data[credential]["birth_date"]
                            )
                            >= 18
                            else False
                        )
                    }
                )

        if "driving_privileges" in presentation_data[credential] and isinstance(
            presentation_data[credential]["driving_privileges"], str
        ):
            json_priv = json.loads(presentation_data[credential]["driving_privileges"])
            presentation_data[credential].update({"driving_privileges": json_priv})

        fields_to_decode = [
            "portrait",
            "image",
            "signature_usual_mark",
            "signature_usual_mark_issuing_officer",
            "picture",
        ]

        for field in fields_to_decode:
            if field in presentation_data[credential]:
                presentation_data[credential].update(
                    {
                        field: base64.b64encode(
                            base64.urlsafe_b64decode(
                                presentation_data[credential][field]
                            )
                        ).decode("utf-8")
                    }
                )

        if "NumberCategories" in presentation_data[credential]:
            for i in range(int(presentation_data[credential]["NumberCategories"])):
                f = str(i + 1)
                presentation_data[credential].pop("IssueDate" + f)
                presentation_data[credential].pop("ExpiryDate" + f)
            presentation_data[credential].pop("NumberCategories")

    return presentation_data


@dynamic.route("/form", methods=["GET", "POST"])
def Dynamic_form():
    """Form PID page.
    Form page where the user can enter its PID data.
    """
    # session["route"] = "/dynamic/form"
    # session["country"] = "FC"

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)

    # if GET
    if request.method == "GET":
        if (
            session.get("country") is None or session.get("returnURL") is None
        ):  # someone is trying to connect directly to this endpoint
            return (
                "Error 101: " + cfgserv.error_list["101"] + "\n",
                status.HTTP_400_BAD_REQUEST,
            )

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template("misc/auth_method.html")

    # if submitted form is valid
    """  v = validate_params_getpid_or_mdl(
        request.form,
        ["version", "country", "certificate", "returnURL", "device_publickey"],
    )
    if not isinstance(v, bool):  # getpid params were not correctly validated
        return v """

    user_id = session_id

    form_data = request.form.to_dict()

    form_data.pop("proceed")

    print("\nform_data: ", form_data)

    cleaned_data = form_formatter(form_data)
    print("\nCleaned Data: ", cleaned_data)

    session_manager.update_user_data(session_id=session_id, user_data=cleaned_data)

    form_dynamic_data[user_id] = cleaned_data.copy()

    form_dynamic_data[user_id].update(
        {"expires": datetime.now() + timedelta(minutes=cfgserv.form_expiry)}
    )

    print("\nform_dynamic_data: ", form_dynamic_data[user_id])

    presentation_data = presentation_formatter(cleaned_data=cleaned_data)

    print("\nPresentation Data: ", presentation_data)

    return render_template(
        "dynamic/form_authorize.html",
        presentation_data=presentation_data,
        user_id=user_id,
        redirect_url=cfgserv.service_url + "dynamic/redirect_wallet",
    )


@dynamic.route("/redirect_wallet", methods=["GET", "POST"])
def redirect_wallet():

    form_data = request.form.to_dict()
    user_id = form_data["user_id"]

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)

    print("\ntoken: ", current_session.jws_token)
    print("\nsession_id: ", session_id)

    return redirect(
        url_get(
            cfgserv.OpenID_first_endpoint,
            {
                "token": current_session.jws_token,
                "username": session_id,
            },
        )
    )


""" @dynamic.route("/redirect_wallet", methods=["GET", "POST"])
def redirect_wallet():

    form_data = request.form.to_dict()

    user_id = form_data["user_id"]

    print("\nuser_id: ", user_id)
    print("\ntoken: ", session["authorization_params"]["token"])

    return redirect(
        url_get(
            cfgserv.OpenID_first_endpoint,
            {
                "jws_token": session["authorization_params"]["token"],
                "username": user_id,
            },
        )
    ) """


def generate_connector_authorization_url(
    oauth_data: dict, country: str, credentials_requested: list
):
    metadata_url = (
        f"{oauth_data.get('base_url')}/.well-known/oauth-authorization-server"
    )

    metadata_json = requests.get(metadata_url).json()

    authorization_endpoint = metadata_json["authorization_endpoint"]

    state = str(uuid4())
    session["oauth_state"] = state

    params = {
        "client_id": oauth_data["client_id"],
        "redirect_uri": oauth_data["redirect_uri"],
        "response_type": "code",
        "scope": credentials_requested[0],
        "state": state,
        "entity": country,
        # "credentials_requested": credentials_requested[0],
        # "metadata_url": f"{cfgserv.service_url}.well-known/openid-credential-issuer2",
    }

    full_url = f"{authorization_endpoint}?{urlencode(params)}"

    return full_url


@dynamic.route("/connector_callback", methods=["GET", "POST"])
def connector_callback():

    state = request.args.get("state")
    if state != session.get("oauth_state"):
        return "State mismatch error", 400

    auth_code = request.args.get("code")

    if not auth_code:
        return "Authorization code missing", 400

    token_endpoint = "https://eidas.projj.eu/token"

    user_info_endpoint = "https://eidas.projj.eu/api/me"

    params = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": f"{cfgserv.service_url}dynamic/connector_callback",
    }

    try:
        response = requests.post(
            token_endpoint,
            data=params,
            auth=(
                "9ztCyAEB3CFwJVhjBoQ2U2fu",
                "BH2tXs26hD5wba6xpiPIHE6NqH3m4DnaKAoG5bFHqM805kvh",
            ),
        )

        response.raise_for_status()
        token_data = response.json()
        print("Access Token:", token_data.get("access_token"))

        access_token = token_data.get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        response = requests.get(user_info_endpoint, headers=headers)

        response.raise_for_status()

        user_data = response.json()

        print("\nuser_data: ", user_data)

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching user data: {e}")
        if response:
            print("Response Body:", response.text)

    print("\nsession_id", session["session_id"])

    return ""
