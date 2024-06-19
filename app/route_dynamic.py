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
from datetime import datetime
import io
import json
import base64
from formatter_func import cbor2elems
import threading
import schedule
import time
from uuid import uuid4
from PIL import Image
from flask import Blueprint, Flask, redirect, render_template, request, session, jsonify
from flask_api import status
from flask_cors import CORS
import requests
from app.lighttoken import handle_response
from app.validate_vp_token import validate_vp_token

from boot_validate import (
    validate_mandatory_args,
)

from app_config.config_devtest import ConfTest as cfgdev
from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries
from redirect_func import  url_get
from misc import authentication_error_redirect, convert_png_to_jpeg, credential_error_resp, generate_unique_id, getAttributesForm, scope2details, validate_image
from dynamic_func import dynamic_formatter
from . import oidc_metadata

# /pid blueprint
dynamic = Blueprint("dynamic", __name__, url_prefix="/dynamic")
CORS(dynamic)  # enable CORS on the blue print

# Log
from app_config.config_service import ConfService as log

app = Flask(__name__)
app.config["SECRET_KEY"] = "chave_secreta"
app.config["dynamic"] = {}


@dynamic.route("/", methods=["GET", "POST"])
def Supported_Countries():
    """Initial PID page.
    Loads country config information and renders pid_index.html so that the user can select the PID issuer country.
    """

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template("misc/auth_method.html", redirect_url= cfgserv.service_url)
    
    authorization_params = session["authorization_params"]
    authorization_details = []
    if "authorization_details" in authorization_params:
        authorization_details.extend(
            json.loads(authorization_params["authorization_details"])
        )
    if "scope" in authorization_params:
        authorization_details.extend(scope2details(authorization_params["scope"]))

    if not authorization_details:
        return authentication_error_redirect(
            jws_token=authorization_params["token"],
            error="invalid authentication",
            error_description="No authorization details or scope found in dynamic route.",
        )

    session["authorization_details"] = authorization_details

    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])
        elif "vct" in cred:
            if cred["vct"] not in credentials_requested:
                credentials_requested.append(cred["vct"])

    session["credentials_requested"] = credentials_requested

    display_countries = {}
    for country in cfgcountries.supported_countries:
        res = all(
            ele in cfgcountries.supported_countries[country]["supported_credentials"]
            for ele in credentials_requested
        )
        if res:
            display_countries.update(
                {str(country): str(cfgcountries.supported_countries[country]["name"])}
            )

    form_keys = request.form.keys()
    form_country = request.form.get("country")

    # if country was selected
    if (
        "country" in form_keys
        and "proceed" in form_keys
        and form_country in display_countries.keys()
    ):
        session["returnURL"] = cfgserv.OpenID_first_endpoint
        session["country"] = form_country

        """ log.logger_info.info(
            " - INFO - "
            + session["route"]
            + " - Version:"
            + cfgserv.current_version
            + " - Country: "
            + session["country"]
            + "- Credentials requested: "
            + session["credentials_requested"]
            + " -  entered the route"
        ) """

        return dynamic_R1(session["country"])

    # render page where user can select pid_countries

    session["jws_token"] = authorization_params["token"]

    return render_template(
        "dynamic/dynamic-countries.html",
        countries=display_countries,
        authorization_details=json.dumps(authorization_details),
        redirect_url= cfgserv.service_url
    )


def dynamic_R1(country):
    """
    Function to create url to redirect to the selected credential issuer country

    Keyword arguments:
    country -- Country selected by user
    """

    credentials_requested = session["credentials_requested"]
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    log.logger_info.info(
        " - INFO -  Version:"
        + cfgserv.current_version
        + " -  URL_R1 for Country: "
        + country
        + " has been created"
    )

    if country == "FC":
        attributesForm = getAttributesForm(session["credentials_requested"])
        if "user_pseudonym" in attributesForm:
            attributesForm.update({"user_pseudonym":uuid4()})
        return render_template("dynamic/dynamic-form.html", attributes=attributesForm, redirect_url= cfgserv.service_url+"dynamic/form")

    elif cfgcountries.supported_countries[country]["connection_type"] == "eidasnode":
        return redirect(cfgcountries.supported_countries[country]["pid_url_oidc"])

    elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
        country_data = cfgcountries.supported_countries[country]["oidc_auth"].copy()

        url = country_data["url"] + "redirect_uri=" + country_data["redirect_uri"]
        

        pt_attributes = list()

        if isinstance(country_data["scope"], dict):
            scope_final = list()
            for request in credentials_requested:
                scope = credentialsSupported[request]["scope"]

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
            country_data["state"] = country + "." + session["jws_token"]

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
    session["route"] = "/dynamic/redirect"
    if session["country"] == "PT":

        if not request.args:  # if args is empty
            return render_template("/dynamic/pt_url.html")

        (v, l) = validate_mandatory_args(request.args, ["access_token"])
        if not v:  # if not all arguments are available
            return authentication_error_redirect(
                jws_token=session["jws_token"],
                error="Missing mandatory args-PT",
                error_description="Missing mandatory PT-IdP fields",
            )

        token = request.args.get("access_token")
        r1 = requests.post(
            "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager",
            json={"token": token},
        )


        log.logger_info.info(
            " - INFO - "
            + session["route"]
            + " - Version:"
            + cfgserv.current_version
            + " - Country: "
            + session["country"]
            + " -  entered the route"
        )

        return redirect(
            url_get(
                session["returnURL"],
                {
                    "jws_token": session["jws_token"],
                    "username": session["country"]
                    + "."
                    + token
                    + "&authenticationContextId="
                    + r1.json()["authenticationContextId"],
                },
            )
        )

    elif session["country"] is None:

        country, jws_token = request.args.get("state").split(".")
        session["jws_token"] = jws_token
        session["country"] == country

    (v, l) = validate_mandatory_args(request.args, ["code"])
    if not v:  # if not all arguments are available
        return authentication_error_redirect(
            jws_token=session["jws_token"],
            error="Missing fields",
            error_description="Missing mandatory IdP fields",
        )
    

    metadata_url = cfgcountries.supported_countries[session["country"]]["oidc_auth"]["base_url"] + "/.well-known/openid-configuration"
    metadata_json = requests.get(metadata_url).json()

    token_endpoint = metadata_json["token_endpoint"]

    redirect_data = cfgcountries.supported_countries[session["country"]][
        "oidc_redirect"
    ]

    #url = redirect_data["url"]
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
        + "&redirect_uri="
        + redirect_data["redirect_uri"]
    ) """

    r = requests.post(token_endpoint, headers=headers, data=data)
    json_response = json.loads(r.text)
    session["access_token"] = json_response["access_token"]

    log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " - Version:"
        + cfgserv.current_version
        + " - Country: "
        + session["country"]
        + "- Code: "
        + request.args.get("code")
        + " -  entered the route"
    )

    return redirect(
        url_get(
            cfgserv.OpenID_first_endpoint,
            {
                "jws_token": session["jws_token"],
                "username": session["country"] + "." + session["access_token"],
            },
        )
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

    user = json_request["user_id"]

    country, user_id = user.split(".", 1)

    credential_request = json_request["credential_requests"]

    session["country"] = country
    session["version"] = cfgserv.current_version
    session["route"] = "/dynamic/form_R2"

    data = dynamic_R2_data_collect(
        country=country, user_id=user_id, json_request=json_request
    )

    print("\n-----dynamic R2 data-----", data)

    if "error" in data:
        return data

    # log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")

    credential_response = credentialCreation(
        credential_request=credential_request, data=data, country=country
    )

    return credential_response


def dynamic_R2_data_collect(country, user_id, json_request):
    """
    Funtion to get attributes from selected credential issuer country

    Keyword arguments:"
    user_id -- user identifier needed to get respective attributes
    country -- credential issuing country that user selected
    json_request -- json that arrives on the dynamic_R2 route

    """
    if country == "FC":
        data = app.config["dynamic"].get(user_id, "Data not found")

        if data == "Data not found":
            return {"error": "error", "error_description": "Data not found"}

        session["version"] = data["version"]
        session["country"] = data["issuing_country"]

        return data

    elif cfgcountries.supported_countries[country]["connection_type"] == "eidasnode":
        (b, data) = handle_response(user_id)

        if "custom_modifiers" in cfgcountries.supported_countries[country]:
                custom_modifiers = cfgcountries.supported_countries[country]["custom_modifiers"]
                for modifier in custom_modifiers:
                    if custom_modifiers[modifier] in data:
                        data[modifier] = data[custom_modifiers[modifier]]
                        data.pop(custom_modifiers[modifier])
        return data
    
    elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
        attribute_request = cfgcountries.supported_countries[country][
            "attribute_request"
        ]
        url = attribute_request["url"] + user_id
        #headers = attribute_request["header"]
        try:
            r2 = requests.get(url)

            json_response = r2.json()
            for attribute in json_response:
                if attribute["state"] == "Pending":
                    return {"error":"Pending"}

            data = json_response
            
            return data
        except:
            credential_error_resp("invalid_credential_request","openid connection failed")
        
    elif cfgcountries.supported_countries[country]["connection_type"] == "openid":
        attribute_request = cfgcountries.supported_countries[country][
            "attribute_request"
        ]

        metadata_url = cfgcountries.supported_countries[session["country"]]["oidc_auth"]["base_url"] + "/.well-known/openid-configuration"
        metadata_json = requests.get(metadata_url).json()

        userinfo_endpoint = metadata_json["userinfo_endpoint"]

        if country == "EE":
            url = userinfo_endpoint + "?access_token=" + user_id

            headers = attribute_request["header"]
        else:
            url = userinfo_endpoint
            headers =attribute_request["header"]
            headers["Authorization"] = f'Bearer {user_id}'
            
        try:
            r2 = requests.get(url, headers=headers)
            json_response = json.loads(r2.text)
            data = json_response
            if "custom_modifiers" in cfgcountries.supported_countries[country]["attribute_request"]:
                custom_modifiers = cfgcountries.supported_countries[country]["attribute_request"]["custom_modifiers"]
                for modifier in custom_modifiers:
                    if custom_modifiers[modifier] in data:
                        data[modifier] = data[custom_modifiers[modifier]]
                        data.pop(custom_modifiers[modifier])

            return data
        except:
            credential_error_resp("invalid_credential_request","openid connection failed")
    else:
        credential_error_resp("invalid_credential_request","Not supported")


def credentialCreation(credential_request, data, country):
    """
    Function to create credentials requested by user

    Keyword arguments:"
    credential_request -- dictionary with credentials requested
    data -- attributes from user
    country -- credential issuing country


    """

    credentials_supported = oidc_metadata["credential_configurations_supported"]
    document_mappings = cfgserv.document_mappings

    credential_response = {"credential_responses": []}
    for credential in credential_request:

        if "credential_identifier" in credential:
            doctype = credentials_supported[credential["credential_identifier"]][
                "scope"
            ]
            format = credentials_supported[credential["credential_identifier"]][
                "format"
            ]
        elif "vct" in credential and "format" in credential:
            doctype = credentials_supported[credential["vct"]]["scope"]
            format = credential["format"]

        elif "format" in credential and "doctype" in credential:
            format = credential["format"]
            doctype = credential["doctype"]

        else:
            return {
                "error": "invalid_credential_request",
                "error_description": "invalid request",
            }

        device_publickey = credential["device_publickey"]

        #formatting_functions = document_mappings[doctype]["formatting_functions"]

        form_data = {}
        if country == "FC":
            form_data = data

        elif (
            cfgcountries.supported_countries[country]["connection_type"] == "eidasnode"
        ):
            form_data = data

        elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
            if country == "PT":

                portuguese_fields = cfgcountries.supported_countries[country]["oidc_auth"]["scope"][doctype]

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

                form_data["birth_date"] = datetime.datetime.strptime(
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
                "version": session["version"],
                "issuing_country": session["country"],
            }
        )

        pdata = dynamic_formatter(format, doctype, form_data, device_publickey)

        credential_response["credential_responses"].append(
        {"credential": pdata}
        )

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

@dynamic.route("/getpidoid4vp", methods=["GET", "POST"])
def getpidoid4vp():
    presentation_id = request.args.get("presentation_id")
    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="

    headers = {
    'Content-Type': 'application/json',
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg= str(response.status_code)
        return jsonify({"error": error_msg}),400
    
    error, error_msg= validate_vp_token(response.json())

    if error == True:
        return authentication_error_redirect(
                        jws_token=session["authorization_params"]["token"],
                        error="invalid_request",
                        error_description=error_msg)
    
    mdoc_json = cbor2elems(response.json()["vp_token"])


    attributesForm={}

    if "authorization_params" in session and "authorization_details" in session["authorization_params"]:
        cred_request_json = json.loads(session["authorization_params"]["authorization_details"])

        for cred_request in cred_request_json:
            if "credential_configuration_id" in cred_request:
                if cred_request["credential_configuration_id"] == "eu.europa.ec.eudiw.pseudonym_over18_mdoc" or cred_request["credential_configuration_id"] == "eu.europa.ec.eudiw.pseudonym_over18_mdoc_deferred_endpoint":
                    attributesForm.update({"user_pseudonym":uuid4()})
            elif "vct" in cred_request:
                if cred_request["vct"] == "eu.europa.ec.eudiw.pseudonym_jwt_vc_json":
                    attributesForm.update({"user_pseudonym":uuid4()})

    elif "authorization_params" in session and "scope" in session["authorization_params"]:
        cred_scopes = session["authorization_params"]["scope"]
        if "eu.europa.ec.eudiw.pseudonym.age_over_18.1" in cred_scopes or "eu.europa.ec.eudiw.pseudonym.age_over_18.deferred_endpoint" in cred_scopes:
            attributesForm.update({"user_pseudonym":uuid4()})

    for doctype in mdoc_json:
        for attribute, value in mdoc_json[doctype]:
            if attribute == "age_over_18":
                attributesForm.update({attribute:value})

    return render_template("dynamic/form_authorize.html", attributes=attributesForm, redirect_url= cfgserv.service_url)

@dynamic.route("/auth_method", methods=["GET", "POST"])
def auth():

    authorization_params= session["authorization_params"]
    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return authentication_error_redirect(
                        jws_token=authorization_params["token"],
                        error="Process Canceled",
                        error_description="User canceled authentication")
    choice= request.form.get("optionsRadios")

    choice= request.form.get("optionsRadios")
    if choice == "link1":
            return redirect(cfgserv.service_url + "oid4vp")
    elif choice == "link2":
        return redirect(cfgserv.service_url + "dynamic/")
    

@dynamic.route("/preauth", methods=["GET"])
def preauthRed():
    
    url = cfgserv.service_url + "pushed_authorizationv2"

    payload = 'response_type=code&state=af0ifjsldkj&client_id=ID&redirect_uri=https%3A%2F%2Fissuer.eudiw.dev%2Fpreauth-code&code_challenge=-ciaVij0VMswVfqm3_GK758-_dAI0E9i97hu1SAOiFQ&code_challenge_method=S256&authorization_details=%5B%0A%20%20%7B%0A%20%20%20%20%22type%22%3A%20%22openid_credential%22%2C%0A%20%20%20%20%22credential_configuration_id%22%3A%20%22eu.europa.ec.eudiw.loyalty_mdoc%22%0A%20%20%7D%0A%5D'
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    par_response = response.json()

    return redirect(cfgserv.service_url +"authorization-preauth?client_id=ID&request_uri=" + par_response["request_uri"])
    


@dynamic.route("/preauth-form", methods=["GET"])
def preauthForm():
    """ Form used for pre-authorization
    Form page where the user information is parsed.
    """
    attributesForm={"given_name":"string",
                    "family_name":"string",
                    "company":"string",
                    "client_id":"string"}

    return render_template("dynamic/dynamic-form.html", attributes=attributesForm, redirect_url= cfgserv.service_url+"dynamic/form2")

@dynamic.route("/form2", methods=["GET", "POST"])
def Dynamic_form2():
    """Form PID page.
    Form page where the user can enter its PID data.
    """
    session["route"] = "/dynamic/form"
    session["version"] = "0.4"
    session["country"] = "FC"
    # if GET
    if request.method == "GET":
        # print("/pid/form GET: " + str(request.args))
        if (
            session.get("country") is None or session.get("returnURL") is None
        ):  # someone is trying to connect directly to this endpoint
            return (
                "Error 101: " + cfgserv.error_list["101"] + "\n",
                status.HTTP_400_BAD_REQUEST,
            )

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template('Misc/Auth_method.html')

    # if submitted form is valid
    """  v = validate_params_getpid_or_mdl(
        request.form,
        ["version", "country", "certificate", "returnURL", "device_publickey"],
    )
    if not isinstance(v, bool):  # getpid params were not correctly validated
        return v """

    form_data = request.form.to_dict()

    user_id = generate_unique_id()
    timestamp = int(datetime.timestamp(datetime.now()))

    form_data.pop("proceed")
    cleaned_data = {}
    for item in form_data:

        if item == "portrait":
            if form_data[item] == "Port1":
                cleaned_data["portrait"] = cfgdev.portrait1
            elif form_data[item] == "Port2":
                cleaned_data["portrait"] = cfgdev.portrait2
            elif form_data[item] == "Port3":
                portrait= request.files["Image"]

                img = Image.open(portrait)
                #imgbytes = img.tobytes()
                bio = io.BytesIO()
                img.save(bio, format="JPEG")
                del img

                response,error_msg = validate_image(portrait)

                if response==False:
                    return authentication_error_redirect(
                        jws_token=session["jws_token"],
                        error="Invalid Image",
                        error_description=error_msg,
                    )
                else :
                    imgurlbase64=base64.urlsafe_b64encode(bio.getvalue()).decode('utf-8')
                    cleaned_data["portrait"]=imgurlbase64

        elif item == "Category1":
            DrivingPrivileges = []
            i = 1
            for i in range(int(form_data["NumberCategories"])):
                f = str(i + 1)
                drivP = {
                    "vehicle_category_code": form_data["Category" + f],
                    "issue_date": form_data["IssueDate" + f],
                    "expiry_date": form_data["ExpiryDate" + f],
                }
                DrivingPrivileges.append(drivP)

            cleaned_data["driving_privileges"] = json.dumps(DrivingPrivileges)

        else:
            cleaned_data[item] = form_data[item]

    cleaned_data.update(
        {
            "version": session["version"],
            "issuing_country": session["country"],
            "issuing_authority": cfgserv.mdl_issuing_authority,
            "timestamp": timestamp,
        }
    )

    app.config["dynamic"][user_id] = cleaned_data

    
    if "jws_token" not in session or "authorization_params" in session:
        session["jws_token"] = session["authorization_params"]["token"]

    session["returnURL"] = cfgserv.OpenID_first_endpoint
    
    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "FC." + user_id,
            },
        )
    )

@dynamic.route("/form", methods=["GET", "POST"])
def Dynamic_form():
    """Form PID page.
    Form page where the user can enter its PID data.
    """
    session["route"] = "/dynamic/form"
    session["version"] = "0.4"
    session["country"] = "FC"
    # if GET
    if request.method == "GET":
        # print("/pid/form GET: " + str(request.args))
        if (
            session.get("country") is None or session.get("returnURL") is None
        ):  # someone is trying to connect directly to this endpoint
            return (
                "Error 101: " + cfgserv.error_list["101"] + "\n",
                status.HTTP_400_BAD_REQUEST,
            )

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template('misc/auth_method.html')

    # if submitted form is valid
    """  v = validate_params_getpid_or_mdl(
        request.form,
        ["version", "country", "certificate", "returnURL", "device_publickey"],
    )
    if not isinstance(v, bool):  # getpid params were not correctly validated
        return v """

    form_data = request.form.to_dict()

    user_id = generate_unique_id()
    timestamp = int(datetime.timestamp(datetime.now()))

    form_data.pop("proceed")
    cleaned_data = {}
    for item in form_data:

        if item == "portrait":
            if form_data[item] == "Port1":
                cleaned_data["portrait"] = cfgdev.portrait1
            elif form_data[item] == "Port2":
                cleaned_data["portrait"] = cfgdev.portrait2
            elif form_data[item] == "Port3":
                portrait= request.files["Image"]

                img = Image.open(portrait)
                #imgbytes = img.tobytes()
                bio = io.BytesIO()
                img.save(bio, format="JPEG")
                del img

                response,error_msg = validate_image(portrait)

                if response==False:
                    return authentication_error_redirect(
                        jws_token=session["jws_token"],
                        error="Invalid Image",
                        error_description=error_msg,
                    )
                else :
                    imgurlbase64=base64.urlsafe_b64encode(bio.getvalue()).decode('utf-8')
                    cleaned_data["portrait"]=imgurlbase64

        elif item == "Category1":
            DrivingPrivileges = []
            i = 1
            for i in range(int(form_data["NumberCategories"])):
                f = str(i + 1)
                drivP = {
                    "vehicle_category_code": form_data["Category" + f],
                    "issue_date": form_data["IssueDate" + f],
                    "expiry_date": form_data["ExpiryDate" + f],
                }
                DrivingPrivileges.append(drivP)

            cleaned_data["driving_privileges"] = json.dumps(DrivingPrivileges)
        
        elif item == "age_over_18":
            if form_data[item] == "on":
                cleaned_data["age_over_18"] = True
            else:
                cleaned_data["age_over_18"] = False

        else:
            cleaned_data[item] = form_data[item]

    cleaned_data.update(
        {
            "version": session["version"],
            "issuing_country": session["country"],
            "issuing_authority": cfgserv.mdl_issuing_authority,
            "timestamp": timestamp,
        }
    )

    if "age_over_18" not in cleaned_data:
        cleaned_data["age_over_18"] = False

    app.config["dynamic"][user_id] = cleaned_data

    if "jws_token" not in session or "authorization_params" in session:
        session["jws_token"] = session["authorization_params"]["token"]

    session["returnURL"] = cfgserv.OpenID_first_endpoint
    
    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "FC." + user_id,
            },
        )
    )



def clear_data():
    """Function to clear app.config['data']"""
    now = datetime.now()
    aux = []

    for unique_id, dados in app.config["dynamic"].items():
        timestamp = datetime.fromtimestamp(dados.get("timestamp", 0))
        diff = now - timestamp
        if diff.total_seconds() > (
            cfgserv.max_time_data * 60
        ):  # minutes * 60 seconds -> data is deleted after being saved for 1 minute
            aux.append(unique_id)

    for unique_id in aux:
        del app.config["dynamic"][unique_id]

    if aux:
        print(f"Entradas {aux} eliminadas.")


def job():
    clear_data()


schedule.every(cfgserv.schedule_check).minutes.do(
    job
)  # scheduled to run every 5 minutes


def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)


scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()
