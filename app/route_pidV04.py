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


This route_pidV04.py file is the blueprint for the route /V04/pid of the PID Issuer Web service.
"""
from datetime import datetime, timedelta
import json
import logging
import base64

from flask import (
    Blueprint, Flask, flash, g, redirect, render_template, request, session, url_for
)
from flask_api import status
from flask_cors import CORS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from boot_validate import validate_getpidtest_result, validate_params_getpid_or_mdl, validate_params_showpid_or_mdl, validate_mandatory_args
from crypto_func import eccEnc, pubkeyDER, pubkeyPoint, decrypt_ECC
from app_config.config_devtest import ConfTest as cfgdev
from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries
from redirect_func import redirect_getpid_or_mdl, url_get
from misc import convert_png_to_jpeg, create_dict
from formatter_func import cbor2elems
from pid_func import process_pid_form

# /pid blueprint
openid = Blueprint('V04', __name__, url_prefix='/V04')
CORS(openid) # enable CORS on the blue print

# Log
from app_config.config_service import ConfService as log

app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta'
app.config['data'] = {}


@openid.route('/pid', methods=['GET','POST'])
def pid_root_v04():
    """Initial PID page. 
    Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""
    countries_name = create_dict(cfgcountries.supported_countries, 'name')
    form_keys = request.form.keys()
    form_country = request.form.get('country')
    
    # if country was selected
    if 'country' in form_keys and 'proceed' in form_keys and form_country in countries_name.keys():
        session['privkey'] = base64.b64encode(cfgdev.privkeystr).decode('utf-8') 
        #print(base64.urlsafe_b64encode(cfgdev.device_publickey.encode('utf-8')).decode('utf-8'))
        
        #print("pid_root: " + session['privkey'])    
        return redirect(url_get(cfgserv.service_url + "V04/getpid", 
                                {'returnURL': cfgserv.OpenID_first_endpoint, 
                                 'country': form_country,
                                 'certificate': base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8'),
                                 'device_publickey': cfgdev.device_publickey}))

    # render page where user can select pid_countries

    session["jws_token"] = request.args.get("token")

    return render_template('openid/pid-countries.html', countries = countries_name)


@openid.route('/getpid', methods=['GET'])
#@cross_origin(supports_credentials=True)
def getPid_04():
    """PID request. Starts the process of issuance of the PID in CBOR (ISO 18013-5 mdoc) and SD-JWT format.
    
    Get query parameters:
    + version (mandatory) - API version
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
    + certificate (mandatory) - certificate (PEM format) encoded in base64urlsafe. 
    + returnURL (mandatory) - URL where the response will be redirected.
    + device_publickey -  Device public key (PEM format), encoded in base64urlsafe 

    Return: HTTP_400_BAD_REQUEST if returnURL is missing. Otherwise, GET redirect to returnURL.
    """
    session['route'] = "/V04/getpid"
    session['version'] = "0.4"
    session["tries"] = log.eidasnode_retry

    
    v = validate_params_getpid_or_mdl(request.args, ['country', 'certificate', 'returnURL', 'device_publickey'])

    if not isinstance(v, bool): # getpid params were not correctly validated
        return v
    
    log.logger_info.info(" - INFO - " + session["route"] + " - Version: 0.4"  + " - Country: " + request.args['country'] + " - Certificate: " + request.args['certificate'] + " - Return Url: " + request.args['returnURL'] + " - Device Public Key: " + request.args['device_publickey'] + " -  entered the route")

    # getpid params correctly validated
    session['country'] = request.args['country']
    session['certificate'] = request.args['certificate']
    session['returnURL'] = request.args['returnURL']
    session['device_publickey'] = request.args['device_publickey']

    if (session['country'] == ""):
        return redirect(cfgserv.service_url + 'v04/pid?version='+ session['version']+ '&country=' + session['country'] + '&certificate=' + session ['certificate'] + '&returnURL=' + session['returnURL'] + '&device_publickey='+ session['device_publickey'] )


    #print("getpid privkey: " + str(session.get('privkey')) + " - " + str(session.keys()) + "\n" + str(request.args))
    #session.pop('privkey', default=None)

    if session["country"] == "EE":
        return redirect("https://tara-test.ria.ee/oidc/authorize?redirect_uri=" + "https://pprpid.provider.eudiw.projj.eu/tara/redirect" + "&scope=openid&state=" + session["jws_token"] +"&response_type=code&client_id=eu_europa_ec_eudiw_pid_provider_1_ppr")
    
    return redirect(cfgcountries.supported_countries[request.args['country']]['pid_url_oidc'])


@openid.route('/form', methods=['GET','POST'])
def V04_pid_form():
    """Form PID page. 
    Form page where the user can enter its PID data.
    """
    session['route'] = "/V04/form"
    session['version'] = "0.4"

    log.logger_info.info(" - INFO - " + session["route"] +" -  entered the route")


    # print("/pid/form: " + str(request.method))
    # print("/pid/form session:  " + session['version'])

    # if GET
    if request.method == 'GET':
        # print("/pid/form GET: " + str(request.args))
        if session.get('country') is None or session.get('certificate') is None or session.get('returnURL') is None or session.get('device_publickey') is None: # someone is trying to connect directly to this endpoint
            return "Error 101: " + cfgserv.error_list['101'] + "\n", status.HTTP_400_BAD_REQUEST
        # all the session needed elements exist
        return render_template('openid/pid-form.html', hidden_elems=[('version', session.get('version')), ('country', session.get('country')), ('certificate', session.get('certificate')), ('returnURL', session.get('returnURL')), ('device_publickey', session.get('device_publickey'))])

    # if POST   
    # print("/pid/form POST: " + str(request.form)) 
    if 'Cancelled' in request.form.keys(): # Form request Cancelled
        return render_template('openid/pid-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
    (b, l) = validate_mandatory_args(request.form, ['CurrentGivenName', 'CurrentFamilyName', 'DateOfBirth',  'version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not b: # valid form has not been submitted 
        # render page where user can select pid_countries
        #print("/pid/form POST - mandatory args do not exist: " + str(l))
        return render_template('openid/pid-form.html', hidden_elems=[('version', cfgserv.current_version), ('country', cfgcountries.formCountry), ('certificate', base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8')), ('returnURL', cfgserv.service_url + 'pid/show'), ('device_publickey', cfgdev.device_publickey)])

    # if submitted form is valid
    v = validate_params_getpid_or_mdl(request.form, ['version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not isinstance(v, bool): # getpid params were not correctly validated
        return v

    user_id = generate_unique_id()
    timestamp = int(datetime.timestamp(datetime.now()))

    dados = {
        'version': request.form['version'], 
        'country': request.form['country'], 
        'certificate': request.form['certificate'], 
        'returnURL': request.form['returnURL'], 
        'device_publickey': request.form['device_publickey'],
        'CurrentGivenName': request.form['CurrentGivenName'],
        'CurrentFamilyName': request.form['CurrentFamilyName'],
        'DateOfBirth': request.form['DateOfBirth'],

        'timestamp': timestamp
    }
    app.config['data'][user_id] = dados
    
    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "FC." + user_id,
            },
        )
    )


@openid.route('/form_R2', methods=['GET','POST'])
def form_R2():
    """ Route acessed by OpenID to get PID attributes from country FC

    Get query parameters:
    + user_id - token to obtain PID attributes
    
    Return:PID in sd-jwt and mdoc formats

    """
    user_id = request.args['user_id']
    
    dados =  app.config['data'].get(user_id, 'Data not found')
    
    if(dados == "Data not found"):
        return  {
            "error": "error",
            "error_description": "Data not found"
        }
    
    session['version'] = dados['version']
    session['country'] = dados['country']
    session['certificate'] = dados['certificate']
    session['returnURL'] = dados['returnURL']
    session['device_publickey'] = request.args["device_publickey"]

    session['route'] = "/V04/form_R2"
    log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")


    form = {
        "CurrentGivenName": dados["CurrentGivenName"],
        "CurrentFamilyName": dados["CurrentFamilyName"],
        "DateOfBirth": dados['DateOfBirth'],
        "version": session["version"],
        "country": session["country"],
        "certificate": "",
        "returnURL": "",
    }
    (error_code, mdoc, nonce, authTag, pub64, sd_jwt) = process_pid_form(form, cipher=False)

    return  {
        "mdoc": mdoc,
        "sd-jwt": sd_jwt
    }
             

def generate_unique_id():
    """ Function to generate a random uuid

    """

    import uuid
    return str(uuid.uuid4())

# @openid.route('/view')
# def vi():
#     """ Route for getting app.config['data']
    
#     Return:app.config['data']
#     """
#     return app.config['data']

def clear_data():
    """ Function to clear app.config['data']

    """
    now = datetime.now()
    aux = []

    for unique_id, dados in app.config['data'].items():
        timestamp = datetime.fromtimestamp(dados.get('timestamp', 0))
        diff = now - timestamp
        if diff.total_seconds() > (cfgserv.max_time_data * 60): #minutes * 60 seconds -> data is deleted after being saved for 1 minute
            aux.append(unique_id)
    
    for unique_id in aux:
        del app.config['data'][unique_id]
    
    if aux:
        print (f"Entradas {aux} eliminadas.")

import threading
import schedule
import time
def job():
    clear_data()


schedule.every(cfgserv.schedule_check).minutes.do(job) #scheduled to run every 5 minutes


def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()
