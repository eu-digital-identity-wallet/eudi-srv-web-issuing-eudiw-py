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
The QEAA Issuer Web service is a component of the QEAA Provider backend. 
Its main goal is to issue the PID, MDL and QEAA in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This route_qeaa.py file is the blueprint for the route /qeaa of the PID Issuer Web service.
"""

import logging
import time
import requests
import base64
import xml.etree.ElementTree as ET


from datetime import datetime, timedelta

from flask import (
    Blueprint,
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_api import status
from flask_cors import CORS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests

from crypto_func import decrypt_ECC, pubkeyPoint

from boot_validate import (
    validate_mandatory_args,
    validate_params_getpid_or_mdl,
    validate_params_showpid_or_mdl,
)

# from .crypto_func import eccEnc, pubkeyDER, pubkeyPoint, decrypt_ECC
from app_config.config_devtest import ConfTest as cfgdev
from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries
from redirect_func import redirect_getpid_or_mdl, url_get
from misc import create_dict
from formatter_func import cbor2elems
from qeaa_func import process_qeaa_form


# /qeaa
qeaa = Blueprint('qeaa', __name__, url_prefix='/V04/qeaa')
CORS(qeaa) # enable CORS on the blue print


# Log
from app_config.config_service import ConfService as log


app = Flask(__name__)
app.config["SECRET_KEY"] = "chave_secreta"
app.config["qeaa"] = {}


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /qeaa with current version
@qeaa.route("", methods=["GET", "POST"])
# route to /qeaa/
@qeaa.route("/", methods=["GET", "POST"])
def qeaa_route():

    """Initial qeaa Func page.
    Loads country config information and renders qeaaFunc_countries.html so that the user can select the mdl issuer country.
    """
    # countries_name = create_dict(cfgcountries.supported_countries, 'name')
    countries_name = {"FC": "Form Country", "PT": "Portugal"}
    form_keys = request.form.keys()
    form_country = request.form.get("country")

    # if country was selected
    if (
        "country" in form_keys
        and "proceed" in form_keys
        and form_country in countries_name.keys()
    ):
        session["privkey"] = base64.b64encode(cfgdev.privkeystr).decode("utf-8")
        # print(base64.urlsafe_b64encode(cfgdev.device_publickey.encode('utf-8')).decode('utf-8'))

        # print("pid_root: " + session['privkey'])
        return redirect(
            url_get(
                cfgserv.service_url + "V04/qeaa/getqeaa",
                {
                    "returnURL": cfgserv.OpenID_first_endpoint,
                    "country": form_country,
                    "certificate": base64.urlsafe_b64encode(cfgdev.certificate).decode(
                        "utf-8"
                    ),
                    "device_publickey": cfgdev.device_publickey,
                },
            )
        )

    # render page where user can select pid_countries

    session["jws_token"] = request.args.get("token")

    # render page where user can select mdl_countries
    return render_template("route_qeaa/qeaa-countries.html", countries=countries_name)



@qeaa.route("/getqeaa", methods=["GET"])
def getqeaa():
    """QEAA request. Starts the process of issuance of the qeaa in CBOR and SD-JWT format.

    Get query parameters:
    + version (mandatory) - API version
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
    + certificate (mandatory) - certificate (PEM format) encoded in base64urlsafe.
    + returnURL (mandatory) - URL where the response will be redirected.
    + device_publickey - Device public key (PEM format), encoded in base64urlsafe

    Return: HTTP_400_BAD_REQUEST if returnURL is missing. Otherwise, GET redirect to returnURL.
    """
    
    session['route'] = "/V04/qeaa/getqeaa"
    session['version'] = "0.4"

    # v = validate_params_getmdl(request.args, ['version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    # if not isinstance(v, bool): # getmdl params were not correctly validated
    #     return v
    v = validate_params_getpid_or_mdl(
        request.args, ["country", "certificate", "returnURL", "device_publickey"]
    )
    if not isinstance(v, bool):  # getpid params were not correctly validated
        return v

    log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " - Version: "
        + session["version"]
        + " - Country: "
        + request.args["country"]
        + " - Certificate: "
        + request.args["certificate"]
        + " - Return Url: "
        + request.args["returnURL"]
        + " - Device Public Key: "
        + request.args["device_publickey"]
        + " -  entered the route"
    )

    # getmdl params correctly validated
    session["country"] = request.args["country"]
    session["certificate"] = request.args["certificate"]
    session["returnURL"] = request.args["returnURL"]
    session["device_publickey"] = request.args["device_publickey"]

    if session["country"] == "":
        return redirect(
            cfgserv.service_url
            + "qeaa?version="
            + session["version"]
            + "&country="
            + session["country"]
            + "&certificate="
            + session["certificate"]
            + "&returnURL="
            + session["returnURL"]
            + "&device_publickey="
            + session["device_publickey"]
        )

    # print("getmdl privkey: " + str(session.get('privkey')) + " - " + str(session.keys()) + "\n" + str(request.args))
    # session.pop('privkey', default=None)

    return redirect(
        cfgcountries.supported_countries[request.args["country"]]["qeaa_func"]
    )


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /qeaa/form
@qeaa.route("/form", methods=["GET", "POST"])
def qeaa_form():
    """Form qeaa page.
    Form page where the user can enter its qeaa data.
    """

    session['route'] = "/V04/qeaa/form"
    session['version'] = "0.4"

    # if GET
    if request.method == "GET":
        if (
            session.get("version") is None
            or session.get("country") is None
            or session.get("certificate") is None
            or session.get("returnURL") is None
            or session.get("device_publickey") is None
        ):  # someone is trying to connect directly to this endpoint
            return (
                "Error 101: " + cfgserv.error_list["101"] + "\n",
                status.HTTP_400_BAD_REQUEST,
            )
        # all the session needed elements exist
        return render_template(
            "route_qeaa/qeaa-form.html",
            hidden_elems=[
                ("version", session.get("version")),
                ("country", session.get("country")),
                ("certificate", session.get("certificate")),
                ("returnURL", session.get("returnURL")),
                ("device_publickey", session.get("device_publickey")),
            ],
        )

    # if POST
    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template(
            "route_qeaa/qeaa-countries.html",
            countries=create_dict(cfgcountries.supported_countries, "name"),
        )

    (b, l) = validate_mandatory_args(
        request.form,
        [
            "nipc",
            "name",
            "entidade",
            "entidade",
            "nipc2",
            "email",
            "contr",
            "version",
            "certificate",
            "returnURL",
            "device_publickey",
        ],
    )
    if not b:  # valid form has not been submitted
        # render page where user can select mdl_countries
        return render_template(
            "route_qeaa/qeaa-form.html",
            hidden_elems=[
                ("version", cfgserv.current_version),
                ("country", cfgcountries.formCountry),
                (
                    "certificate",
                    base64.urlsafe_b64encode(cfgdev.certificate).decode("utf-8"),
                ),
                ("returnURL", cfgserv.service_url + "qeaa/show"),
                ("device_publickey", cfgdev.device_publickey),
            ],
        )

    # if submitted form is valid
    v = validate_params_getpid_or_mdl(
        request.form,
        ["version", "country", "certificate", "returnURL", "device_publickey"],
    )
    if not isinstance(v, bool):  # getmdl params were not correctly validated
        return v

    user_id = generate_unique_id()
    timestamp = int(datetime.timestamp(datetime.now()))

    dados = {
        "version": request.form["version"],
        "country": request.form["country"],
        "certificate": request.form["certificate"],
        "returnURL": request.form["returnURL"],
        "device_publickey": request.form["device_publickey"],
        "nipc": request.form["nipc"],
        "name": request.form["name"],
        "entidade": request.form["entidade"],
        "nipc2": request.form["nipc2"],
        "email": request.form["email"],
        "contr": request.form["contr"],
        "timestamp": timestamp,
    }

    app.config["qeaa"][user_id] = dados

    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "FC." + user_id,
            },
        )
    )


def generate_unique_id():
    """Function to generate a random uuid"""

    import uuid

    return str(uuid.uuid4())


@qeaa.route("/form_R2", methods=["GET", "POST"])
def form_R2():
    """Route acessed by OpenID to get qeaa attributes from country FC

    Get query parameters:
    + user_id - token to obtain qeaa attributes

    Return:qeaa in sd-jwt and mdoc formats

    """
    user_id = request.args["user_id"]
    dados = app.config["qeaa"].get(user_id, "Data not found")

    if dados == "Data not found":
        return {"error": "error", "error_description": "Data not found"}

    session["version"] = dados["version"]
    session["country"] = dados["country"]
    session["certificate"] = dados["certificate"]
    session["returnURL"] = dados["returnURL"]
    session["device_publickey"] = request.args["device_publickey"]

    session["route"] = "/V04/qeaa/form_R2"
    log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " - "
        + session["device_publickey"]
        + " -  entered the route"
    )

    form = {
        "nipc": dados["nipc"],
        "name": dados["name"],
        "entidade": dados["entidade"],
        "nipc2": dados["nipc2"],
        "email": dados["email"],
        "contr": dados["contr"],
        "version": session["version"],
        "country": session["country"],
        "certificate": "",
        "returnURL": "",
    }

    (error_code, mdoc, nonce, authTag, pub64, sd_jwt) = process_qeaa_form(
        form, cipher=False
    )

    return {"mdoc": mdoc, "sd-jwt": sd_jwt}


def clear_data():
    """Function to clear app.config['qeaa']"""
    now = datetime.now()
    aux = []

    for unique_id, dados in app.config["qeaa"].items():
        timestamp = datetime.fromtimestamp(dados.get("timestamp", 0))
        diff = now - timestamp
        if diff.total_seconds() > (
            cfgserv.max_time_data * 60
        ):  # minutes * 60 seconds -> data is deleted after being saved for 1 minute
            aux.append(unique_id)

    for unique_id in aux:
        del app.config["qeaa"][unique_id]

    if aux:
        print(f"Entradas {aux} eliminadas.")


import threading
import schedule
import time


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


@qeaa.route("/view")
def vi():
    """Route for getting app.config['qeaa']

    Return:app.config['qeaa']
    """
    return app.config["qeaa"]


# route to /qeaa/redirectqeaa
@qeaa.route("/redirectqeaa", methods=["GET"])
def redqeaa():
    """Receives token from PT IDP - communication originated in route /qeaa/getqeaa for country PT
    GET parameters:
    + code (mandatory) - Token code to retrieve the shared attributes consented by the user.
    + scope (mandatory) - scope of the request.
    + state (mandatory) - state of the request.

    Return: Redirect result to returnURL.
    """
    session["route"] = "/V04/qeaa/redirectqeaa"
    session["version"] = "0.4"
    log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " - "
        + session["device_publickey"]
        + " -  entered the route"
    )

    if not request.args:  # if args is empty
        return render_template("/route_qeaa/qeaa-pt_qeaa.html")

    (v, l) = validate_mandatory_args(request.args, ["access_token"])
    if not v:  # if not all arguments are available
        return redirect_getpid_or_mdl(session["version"], session["returnURL"], 501, [])

    # Retrieve the shared attributes consented by the user
    token = request.args.get("access_token")
    r1 = requests.post(
        "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager",
        json={"token": token},
    )

    session["returnURL"] = cfgserv.OpenID_first_endpoint

    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "PT."
                + token
                + "&authenticationContextId="
                + r1.json()["authenticationContextId"],
            },
        )
    )


@qeaa.route("/R2", methods=["GET"])
def red2():
    """Receives token from oid4vci

    GET parameters:
    + user_id: concatenation of token plus authenticationContextId to get the qeaa attributes from country PT

    Return: qeaa in sd-jwt and mdoc formats
    """

    user_id = request.args.get("user_id")

    # info = user_id.split(".")

    # token = info[0]
    authenticationContextId = request.args.get("authenticationContextId")

    time.sleep(10)
    r2 = requests.get(
        "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager?token="
        + user_id
        + "&authenticationContextId="
        + authenticationContextId
    )
    json_data = r2.json()

    session["country"] = "PT"
    session["version"] = "0.4"

    session["device_publickey"] = request.args.get("device_publickey")

    session['route'] = "/V04/qeaa/R2"

    primeira_pessoa = json_data[0]  # This accesses the first dictionary in the list.
    value = primeira_pessoa[
        "value"
    ]  # This accesses the "name" key within the first dictionary.

    # Parse the XML
    root = ET.fromstring(value)

    info_dict = {}

    nipc_element = root.find(
        ".//{http://www.scap.autenticacao.gov.pt/FAScapAttributes}Nipc"
    )
    if nipc_element is not None:
        nipc = nipc_element.text
    else:
        nipc = "N/A"

    name_element = root.find(
        ".//{http://www.scap.autenticacao.gov.pt/FAScapAttributes}Name"
    )
    if name_element is not None:
        name = name_element.text
    else:
        name = "N/A"

    info_dict["Nipc"] = nipc
    info_dict["Name"] = name

    sub_attributes = root.findall(
        ".//{http://www.scap.autenticacao.gov.pt/FAScapAttributes}SubAttribute"
    )

    for sub_attribute in sub_attributes:
        description_element = sub_attribute.find(
            ".//{http://www.scap.autenticacao.gov.pt/FAScapAttributes}Description"
        )
        value_element = sub_attribute.find(
            ".//{http://www.scap.autenticacao.gov.pt/FAScapAttributes}Value"
        )

        if description_element is not None and value_element is not None:
            description = description_element.text
            value = value_element.text
            info_dict[description] = value

    form = {
        "nipc": info_dict["NIPC"],
        "name": info_dict["Name"],
        "entidade": info_dict["Nome da entidade"],
        "nipc2": info_dict["Nipc"],
        "email": info_dict["E-mail do funcion\u00e1rio"],
        "contr": info_dict["Atribu\u00eddo por"],
    }

    (error_code, mdoc, nonce, authTag, pub64, sd_jwt) = process_qeaa_form(
        form, cipher=False
    )

    if not error_code == 0:
        return redirect_getpid_or_mdl(
            session["version"], session["returnURL"], error_code, []
        )

    json = {"mdoc": mdoc, "sd-jwt": sd_jwt}

    return json

    # (error_code, ciphertext, nonce, authTag, pub64, sd_jwt) = process_qeaa_form({'nipc': info_dict['NIPC'], 'name': info_dict['Name'], 'entidade': info_dict['Nome da entidade'],
    #                                                                            'nipc2': info_dict['Nipc'], 'email':info_dict['E-mail do funcion\u00e1rio'],'contr': info_dict['Atribu\u00eddo por'],
    #                                                                            'IssuingAuthority':cfgserv.qeaa_issuing_authority,'version': session['version'], 'country': session['country'],
    #                                                                            'certificate': session['certificate'], 'returnURL': session['returnURL']}, cipher=not(session['version'] == "0.1"))


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /qeaa/show
@qeaa.route("/show", methods=["GET"])
def showQeaa():
    """Is used by /qeaa as a default route to show qeaa.

    Get query parameters:
    + mdoc (mandatory) - Qeaa in cbor/mdoc format, ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + nonce (mandatory) - random AES initialization vector (bytes encoded in base64urlsafe format).
    + authTag (mandatory) - MAC code of the encrypted text, obtained by the GCM block mode (bytes encoded in base64urlsafe format).
    + ciphertextPubKey (mandatory) - randomly generated ephemeral public key, that will be used to derive the symmetric encryption key, using the ECDH key agreement scheme. Public key in DER format, encoded in base64urlsafe format.
    + sd-jwt - Qeaa in sd-jwt format (with disclosures), ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + error (mandatory) - error number. 0 if no error.
    + error_str (mandatory) - Error information.

    Return: Render web page
    """
    session["route"] = "/V04/qeaa/show"
    log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " - "
        + session["device_publickey"]
        + " -  entered the route"
    )

    if session["version"] == "0.3":
        v = validate_params_showpid_or_mdl(
            request.args,
            [
                "mdoc",
                "nonce",
                "authTag",
                "ciphertextPubKey",
                "sd_jwt",
                "error",
                "error_str",
            ],
        )
        if not isinstance(v, bool):  # getpid params were not correctly validated
            return v
    else:
        v = validate_params_showpid_or_mdl(
            request.args,
            [
                "mdoc",
                "mdoc_nonce",
                "mdoc_authTag",
                "mdoc_ciphertextPubKey",
                "error",
                "error_str",
            ],
        )
        if not isinstance(v, bool):  # getpid params were not correctly validated
            return v
    sd_jwt = request.args.get("sd_jwt")
    if session["version"] == "0.1":  # mdoc not ciphered
        mdoc = request.args.get("mdoc").encode("utf-8")
        return render_template(
            "route_pid/pid-show.html",
            elems=cbor2elems(mdoc),
            mdoc=mdoc.decode("utf-8"),
            sd_jwt=sd_jwt,
        )
    if session["version"] == "0.2":
        privkey = serialization.load_pem_private_key(
            base64.b64decode(session["privkey"]),
            password=None,
            backend=default_backend(),
        )
        mdoc = decrypt_ECC(
            base64.urlsafe_b64decode(request.args.get("mdoc").encode("utf-8")),
            base64.urlsafe_b64decode(request.args.get("mdoc_nonce").encode("utf-8")),
            base64.urlsafe_b64decode(request.args.get("mdoc_authTag").encode("utf-8")),
            pubkeyPoint(
                serialization.load_der_public_key(
                    base64.urlsafe_b64decode(
                        request.args.get("mdoc_ciphertextPubKey").encode("utf-8")
                    )
                )
            ),
            privkey.private_numbers().private_value,
        )
        return render_template(
            "route_pid/pid-show.html",
            elems=cbor2elems(mdoc),
            mdoc=mdoc.decode("utf-8"),
            sd_jwt=sd_jwt,
        )
    else:
        # decipher mdoc
        privkey = serialization.load_pem_private_key(
            base64.b64decode(session["privkey"]),
            password=None,
            backend=default_backend(),
        )
        mdoc = decrypt_ECC(
            base64.urlsafe_b64decode(request.args.get("mdoc").encode("utf-8")),
            base64.urlsafe_b64decode(request.args.get("nonce").encode("utf-8")),
            base64.urlsafe_b64decode(request.args.get("authTag").encode("utf-8")),
            pubkeyPoint(
                serialization.load_der_public_key(
                    base64.urlsafe_b64decode(
                        request.args.get("ciphertextPubKey").encode("utf-8")
                    )
                )
            ),
            privkey.private_numbers().private_value,
        )
        return render_template(
            "route_qeaa/qeaa-show.html",
            elems=cbor2elems(mdoc),
            mdoc=mdoc.decode("utf-8"),
            sd_jwt=sd_jwt,
        )
