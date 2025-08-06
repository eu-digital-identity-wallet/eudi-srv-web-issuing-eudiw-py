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
from formatter_func import cbor2elems
import threading
import schedule
import time
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
)
from flask_api import status
from flask_cors import CORS
import requests
import urllib.parse
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
    #session["credentials_requested"] = credentials_requested

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

        #session["returnURL"] = cfgserv.OpenID_first_endpoint
        #session["country"] = country

        cfgserv.app_logger.info(
            ", Session ID: "
            + session["session_id"]
            + ", "
            + "Authorization selection, Type: "
            + country
        )
        return dynamic_R1(country)

    # render page where user can select pid_countries

    #session["authorization_params"] = {"token": token}

    #print("\nsession token: ", session)

    #session["jws_token"] = token  # authorization_params["token"]

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

    #session["returnURL"] = cfgserv.OpenID_first_endpoint
    #session["country"] = form_country

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
    session_manager.update_country(
        session_id=session_id, country=country
    )

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

        optional_attributes_raw = getAttributesForm2(current_session.credentials_requested)

        print("\nMandatory: ", mandatory_attributes)
        print("\nOptional: ", optional_attributes_raw)

        optional_attributes_filtered = {
            key: value for key, value in optional_attributes_raw.items() if key not in mandatory_attributes
        }
        
        return render_template(
            "dynamic/dynamic-form.html",
            mandatory_attributes=mandatory_attributes,
            optional_attributes=optional_attributes_filtered,
            redirect_url=cfgserv.service_url + "dynamic/form",
        )

    elif country == "sample":
        
        session_manager.update_user_data(session_id=session_id, user_data=cfgserv.sample_data.copy())

        """ form_dynamic_data[user_id] = cfgserv.sample_data.copy()
        form_dynamic_data[user_id].update(
            {"expires": datetime.now() + timedelta(minutes=cfgserv.form_expiry)}
        ) """

        #session["returnURL"] = cfgserv.OpenID_first_endpoint

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
        return redirect(cfgcountries.supported_countries[country]["pid_url_oidc"])

    elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
        country_data = cfgcountries.supported_countries[country]["oidc_auth"].copy()

        url = country_data["url"] + "redirect_uri=" + country_data["redirect_uri"]

        pt_attributes = list()

        if isinstance(country_data["scope"], dict):
            scope_final = list()
            for request in credentials_requested:
                if credentialsSupported[request]["format"] == "mso_mdoc":
                    scope = credentialsSupported[request]["doctype"]
                elif credentialsSupported[request]["format"] == "dc+sd-jwt":
                    scope = credentialsSupported[request]["issuer_config"]["doctype"]
                if scope not in scope_final:
                    scope_final.append(scope)

            for scope in scope_final:
                if scope in country_data["scope"]:
                    attributes = country_data["scope"][scope]

                    for a in attributes:
                        if attributes[a] not in pt_attributes:
                            pt_attributes.append(attributes[a])

            scope_pt = " ".join(pt_attributes)

            country_data["scope"] = scope_pt

        for url_part in country_data:
            if url_part == "url" or url_part == "redirect_uri":
                pass
            else:
                url = url + "&" + url_part + "=" + country_data[url_part]

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
    #session["route"] = "/dynamic/redirect"

    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)
    
    if current_session.country == "PT":

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

        """ i = 0
        while "error" in data and data["error"] == "Pending" and i < 20:
            time.sleep(2)
            data = dynamic_R2_data_collect(
            country=session["country"], user_id= token + "&authenticationContextId=" + r1.json()["authenticationContextId"]
            )
            i =+ 2 """

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

            """ if form_data[doctype]["birth_date"] != "Pending":
                form_data[doctype].update({"age_over_18": True if calculate_age(form_data[doctype]["birth_date"]) >= 18 else False})
            else:
                form_data[doctype].update({"age_over_18":"Pending"}) """

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

        session_manager.update_country(session_id=session_id, country= country)

        session_manager.update_jws_token(session_id=session_id, jws_token=jws_token)
        #session["jws_token"] = jws_token
        #session["country"] = country

    (v, l) = validate_mandatory_args(request.args, ["code"])
    if not v:  # if not all arguments are available
        return authentication_error_redirect(
            jws_token=current_session.jws_token,
            error="Missing fields",
            error_description="Missing mandatory IdP fields",
        )

    metadata_url = (
        cfgcountries.supported_countries[current_session.country]["oidc_auth"]["base_url"]
        + "/.well-known/openid-configuration"
    )
    metadata_json = requests.get(metadata_url).json()

    token_endpoint = metadata_json["token_endpoint"]

    redirect_data = cfgcountries.supported_countries[current_session.country][
        "oidc_redirect"
    ]

    # url = redirect_data["url"]
    headers = redirect_data["headers"]

    data = "code=" + request.args.get("code")
    for key in redirect_data:
        if key != "headers":
            data = data + "&" + key + "=" + redirect_data[key]

    """ data = (
        "grant_type="
        + redirect_data["grant_type"]
        + "&code="
        + request.args.get("code")
        + "&redirect_uri="Form
        + redirect_data["redirect_uri"]
    ) """

    r = requests.post(token_endpoint, headers=headers, data=data)
    json_response = json.loads(r.text)
    session["access_token"] = json_response["access_token"]

    cfgserv.app_logger.info(
        " - INFO - "
        + "/dynamic/redicret"
        + " - Version:"
        + cfgserv.current_version
        + " - Country: "
        + current_session.country
        + "- Code: "
        + request.args.get("code")
        + " -  entered the route"
    )

    data = dynamic_R2_data_collect(
        country=current_session.country, user_id=session["access_token"]
    )

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    presentation_data = dict()

    for credential_requested in current_session.credentials_requested:

        scope = credentialsSupported[credential_requested]["scope"]

        """ if scope in cfgserv.common_name:
            credential=cfgserv.common_name[scope]

        else:
            credential = scope  """

        credential = credentialsSupported[credential_requested]["display"][0]["name"]

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
        presentation_data[credential].update({"issuing_country": current_session.country}),

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

        if "driving_privileges" in presentation_data[credential]:
            json_priv = json.loads(presentation_data[credential]["driving_privileges"])
            presentation_data[credential].update({"driving_privileges": json_priv})

        if "portrait" in presentation_data[credential]:
            presentation_data[credential].update(
                {
                    "portrait": base64.b64encode(
                        base64.urlsafe_b64decode(
                            presentation_data[credential]["portrait"]
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

    #session["country"] = country
    #session["version"] = cfgserv.current_version
    #session["route"] = "/dynamic/form_R2"

    data = dynamic_R2_data_collect(country=country, user_id=user_id)

    if "error" in data:
        return data

    # log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")

    credential_response = credentialCreation(
        credential_request=credential_request, data=data, country=country, session_id=user_id
    )

    return credential_response


def dynamic_R2_data_collect(country, user_id):
    """
    Funtion to get attributes from selected credential issuer country

    Keyword arguments:"
    user_id -- user identifier needed to get respective attributes
    country -- credential issuing country that user selected
    """
    
    if country == "FC":

        current_session = session_manager.get_session(session_id=user_id)

        data = (
            current_session.user_data
        )  # form_dynamic_data.get(user_id, "Data not found")

        if data == "Data not found":
            return {"error": "error", "error_description": "Data not found"}

        #session["version"] = cfgserv.current_version
        #session["country"] = data["issuing_country"]

        return data

    if country == "sample":
        #data = form_dynamic_data.get(user_id, "Data not found")
        
        """ if data == "Data not found":
            return {"error": "error", "error_description": "Data not found"} """

        #session["version"] = cfgserv.current_version
        #session["country"] = data["issuing_country"]

        current_session = session_manager.get_session(session_id=user_id)

        data = (
            current_session.user_data
        )

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
        attribute_request = cfgcountries.supported_countries[country][
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
            )

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
            url = userinfo_endpoint + "?access_token=" + user_id

            headers = attribute_request["header"]
        else:
            url = userinfo_endpoint
            headers = attribute_request["header"]
            headers["Authorization"] = f"Bearer {user_id}"

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

        pdata = dynamic_formatter(format, doctype, form_data, device_publickey, session_id)
        
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

    if "effective_from_date" in form_data:
        date_part = form_data["effective_from_date"].split("T")[0]
        dt = datetime.strptime(date_part, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        rfc3339_string = dt.isoformat().replace("+00:00", "Z")
        form_data.update({"effective_from_date": rfc3339_string})

    grouped = {}
    for key, value in form_data.items():
        if not value:
            continue
        if "option" in key and "on" in value:
            continue
        if "[" not in key and "]" not in key:
            grouped.update({key: value})
        else:
            parts = key.replace("][", "/").replace("[", "/").replace("]", "").split("/")

            sub_key = ""
            if "-" in key:
                hyphen_parts = key.split("-")
                base_key = hyphen_parts[0]
                # sub_key = hyphen_parts[1]
                if len(parts) == 3:
                    sub_key = parts[2]
                    index = parts[1]
                else:
                    sub_key = parts[1]
                    index = 0

            else:

                base_key = parts[0]
                index = int(parts[1])
                sub_key = parts[2]

            if base_key not in grouped:
                grouped.update({base_key: [{sub_key: value}]})

            else:

                if len(grouped[base_key]) > int(index):
                    grouped[base_key][int(index)].update({sub_key: value})
                else:
                    grouped[base_key].append({sub_key: value})

    for item in grouped:

        if item == "nationality" or item == "nationalities":
            if isinstance(grouped[item], list):
                cleaned_data[item] = [item["country_code"] for item in grouped[item]]
                cleaned_data["nationalities"] = cleaned_data[item]
            else:
                cleaned_data[item] = grouped[item]
                cleaned_data["nationalities"] = cleaned_data[item]

        elif item == "capacities":
            if isinstance(grouped[item], list):
                cleaned_data[item] = [item["capacity_code"] for item in grouped[item]]
                cleaned_data["capacities"] = cleaned_data[item]
            else:
                cleaned_data[item] = grouped[item]
                cleaned_data["capacities"] = cleaned_data[item]

        elif item == "codes":
            if isinstance(grouped[item], list):
                cleaned_data[item] = [item["code"] for item in grouped[item]]
                cleaned_data["codes"] = cleaned_data[item]
            else:
                cleaned_data[item] = grouped[item]
                cleaned_data["codes"] = cleaned_data[item]

        elif item == "authentic_source":
            if isinstance(grouped[item], list):
                cleaned_data[item] = grouped[item][0]

        elif item == "place_of_birth":
            if isinstance(grouped[item], list):
                joined_places = {}
                for d in grouped[item]:
                    joined_places.update(d)
                cleaned_data[item] = joined_places

        elif item == "address":
            if isinstance(grouped[item], list):
                joined_places = {}
                for d in grouped[item]:
                    joined_places.update(d)
                cleaned_data[item] = joined_places
            else:
                if grouped[item] != "" and grouped[item] != "unset":
                    cleaned_data[item] = grouped[item]

        elif item == "residence_address":
            if isinstance(grouped[item], list):
                joined_places = {}
                for d in grouped[item]:
                    joined_places.update(d)
                cleaned_data[item] = joined_places

        elif item == "birth_date":
            cleaned_data["birthdate"] = grouped[item]
            cleaned_data[item] = grouped[item]

        elif item == "age_equal_or_over" and isinstance(grouped[item], list):
            cleaned_data[item] = grouped[item][0]

        elif item == "portrait":
            if grouped[item] == "Port1":
                cleaned_data["portrait"] = cfgserv.portrait1
            elif grouped[item] == "Port2":
                cleaned_data["portrait"] = cfgserv.portrait2
            elif grouped[item] == "Port3":
                portrait = request.files["Image"]

                img = Image.open(portrait)
                # imgbytes = img.tobytes()
                bio = io.BytesIO()
                img.save(bio, format="JPEG")
                del img

                response, error_msg = validate_image(portrait)

                if response == False:
                    return authentication_error_redirect(
                        jws_token=session["jws_token"],
                        error="Invalid Image",
                        error_description=error_msg,
                    )
                else:
                    imgurlbase64 = base64.urlsafe_b64encode(bio.getvalue()).decode(
                        "utf-8"
                    )
                    cleaned_data["portrait"] = imgurlbase64
        
        elif item == "image":
            if grouped[item] == "Port1":
                cleaned_data["image"] = cfgserv.portrait1
            elif grouped[item] == "Port2":
                cleaned_data["image"] = cfgserv.portrait2
            elif grouped[item] == "Port3":
                portrait = request.files["Image"]

                img = Image.open(portrait)
                # imgbytes = img.tobytes()
                bio = io.BytesIO()
                img.save(bio, format="JPEG")
                del img

                response, error_msg = validate_image(portrait)

                if response == False:
                    return authentication_error_redirect(
                        jws_token=session["jws_token"],
                        error="Invalid Image",
                        error_description=error_msg,
                    )
                else:
                    imgurlbase64 = base64.urlsafe_b64encode(bio.getvalue()).decode(
                        "utf-8"
                    )
                    cleaned_data["image"] = imgurlbase64

        elif item == "Category1":
            DrivingPrivileges = []
            i = 1
            for i in range(int(grouped["NumberCategories"])):
                f = str(i + 1)
                drivP = {
                    "vehicle_category_code": grouped["Category" + f],
                    "issue_date": grouped["IssueDate" + f],
                    "expiry_date": grouped["ExpiryDate" + f],
                }
                DrivingPrivileges.append(drivP)

            cleaned_data["driving_privileges"] = json.dumps(DrivingPrivileges)

        elif grouped[item] == "true":
            cleaned_data[item] = True

        elif grouped[item] == "false":
            cleaned_data[item] = False

        else:
            if grouped[item] != "" and grouped[item] != "unset":
                cleaned_data[item] = grouped[item]

    cleaned_data.update(
        {
            "issuing_country": session_manager.get_session(session["session_id"]).country,
            "issuing_authority": cfgserv.mdl_issuing_authority,
        }
    )

    return cleaned_data


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

        credential = credentialsSupported[credential_requested]["display"][0]["name"]

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
        presentation_data[credential].update({"issuing_country": current_session.country}),

        if credential_requested == "eu.europa.ec.eudi.seafarer_mdoc":
            presentation_data[credential].update(
                {
                    "issuing_authority_logo": base64.b64encode(
                        base64.urlsafe_b64decode(
                            cfgserv.issuing_authority_logo
                        )
                    ).decode("utf-8")
                }
            )

            presentation_data[credential].update(
                {
                    "signature_usual_mark_issuing_officer": base64.b64encode(
                        base64.urlsafe_b64decode(
                            cfgserv.signature_usual_mark_issuing_officer
                        )
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

        if "driving_privileges" in presentation_data[credential]:
            json_priv = json.loads(presentation_data[credential]["driving_privileges"])
            presentation_data[credential].update({"driving_privileges": json_priv})

        if "portrait" in presentation_data[credential]:
            presentation_data[credential].update(
                {
                    "portrait": base64.b64encode(
                        base64.urlsafe_b64decode(
                            presentation_data[credential]["portrait"]
                        )
                    ).decode("utf-8")
                }
            )

        if "image" in presentation_data[credential]:
            presentation_data[credential].update(
                {
                    "image": base64.b64encode(
                        base64.urlsafe_b64decode(
                            presentation_data[credential]["image"]
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
    #session["route"] = "/dynamic/form"
    #session["country"] = "FC"

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

    cleaned_data = form_formatter(form_data)
    print("\nCleaned Data: ", cleaned_data)

    session_manager.update_user_data(
        session_id=session_id, user_data=cleaned_data
    )

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
