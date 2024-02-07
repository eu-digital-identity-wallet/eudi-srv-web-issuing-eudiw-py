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


This route_mdl.py file is the blueprint for the route /mdl of the PID Issuer Web service.
"""

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

from crypto_func import decrypt_ECC, pubkeyPoint

from boot_validate import  validate_mandatory_args, validate_params_getpid_or_mdl, validate_params_showpid_or_mdl
# from .crypto_func import eccEnc, pubkeyDER, pubkeyPoint, decrypt_ECC
from app_config.config_devtest import ConfTest as cfgdev
from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries
from redirect_func import redirect_getpid_or_mdl, url_get
from misc import create_dict
from formatter_func import cbor2elems
from mdl_func import process_mdl_form
from datetime import datetime, timedelta

# /mdl blueprint
mdl = Blueprint('mdl', __name__, url_prefix='/V04/mdl')
CORS(mdl) # enable CORS on the blue print

# Log
from app_config.config_service import ConfService as log

app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta'
app.config['mdl'] = {}

# --------------------------------------------------------------------------------------------------------------------------------------
# route to /mdl with current version
@mdl.route('', methods=['GET','POST'])
# route to /mdl/
@mdl.route('/', methods=['GET','POST'])
def mdl_root():
    """Initial mdl page. 
    Loads country config information and renders mdl_countries.html so that the user can select the mdl issuer country."""
    #countries_name = create_dict(cfgcountries.supported_countries, 'name')
    countries_name={
        'FC': 'FormEU', 
        'PT': 'Portugal'
    }
    form_keys = request.form.keys()
    form_country = request.form.get('country')

   
    # if country was selected
    if 'country' in form_keys and 'proceed' in form_keys and form_country in countries_name.keys():
        session['privkey'] = base64.b64encode(cfgdev.privkeystr).decode('utf-8') 
        #print(base64.urlsafe_b64encode(cfgdev.device_publickey.encode('utf-8')).decode('utf-8'))
        
        #print("pid_root: " + session['privkey'])    
        return redirect(url_get(cfgserv.service_url + "V04/mdl/getmdl", 
                                {'returnURL': cfgserv.OpenID_first_endpoint, 
                                 'country': form_country,
                                 'certificate': base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8'),
                                 'device_publickey': cfgdev.device_publickey}))

    # render page where user can select pid_countries

    session["jws_token"] = request.args.get("token")

    # render page where user can select mdl_countries
    return render_template('route_mdl/mdl-countries.html', countries = countries_name)

# --------------------------------------------------------------------------------------------------------------------------------------
# route to /mdl/getmdl
@mdl.route('/getmdl', methods=['GET'])
#@cross_origin(supports_credentials=True)
def getmdl():
    """MDL request. Starts the process of issuance of the mdl in CBOR (ISO 18013-5 mdoc) and SD-JWT format.
    
    Get query parameters:
    + version (mandatory) - API version
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
    + certificate (mandatory) - certificate (PEM format) encoded in base64urlsafe.
    + returnURL (mandatory) - URL where the response will be redirected.
    + device_publickey - Device public key (PEM format), encoded in base64urlsafe 

    Return: HTTP_400_BAD_REQUEST if returnURL is missing. Otherwise, GET redirect to returnURL.
    """
    session['route'] = "/V04/mdl/getmdl"
    session['version'] = "0.4"

    # v = validate_params_getmdl(request.args, ['version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    # if not isinstance(v, bool): # getmdl params were not correctly validated
    #     return v
    v = validate_params_getpid_or_mdl(request.args, ['country', 'certificate', 'returnURL', 'device_publickey'])
    if not isinstance(v, bool): # getpid params were not correctly validated
        return v

    log.logger_info.info(" - INFO - " + session["route"] + " - Version: " + session['version'] + " - Country: " + request.args['country'] + " - Certificate: " + request.args['certificate'] + " - Return Url: " + request.args['returnURL'] + " - Device Public Key: " + request.args['device_publickey'] + " -  entered the route")

    # getmdl params correctly validated
    session['country'] = request.args['country']
    session['certificate'] = request.args['certificate']
    session['returnURL'] = request.args['returnURL']
    session['device_publickey'] = request.args['device_publickey']

    if (session['country'] == ""):
        return redirect(cfgserv.service_url + 'V04/mdl/?version='+ session['version']+ '&country=' + session['country'] + '&certificate=' + session ['certificate'] + '&returnURL=' + session['returnURL'] + '&device_publickey='+ session['device_publickey'] )


    #print("getmdl privkey: " + str(session.get('privkey')) + " - " + str(session.keys()) + "\n" + str(request.args))
    #session.pop('privkey', default=None)

    return redirect(cfgcountries.supported_countries[request.args['country']]['mdl_url'])

# --------------------------------------------------------------------------------------------------------------------------------------
# route to /mdl/form
@mdl.route('/form', methods=['GET','POST'])
def mdl_form():
    """Form mdl page. 
    Form page where the user can enter its mdl data.
    """
    session['route'] = "/V04/mdl/form"
    session['version'] = "0.4"

    # if GET
    if request.method == 'GET':
        if session.get('country') is None or session.get('certificate') is None or session.get('returnURL') is None or session.get('device_publickey') is None: # someone is trying to connect directly to this endpoint
            return "Error 101: " + cfgserv.error_list['101'] + "\n", status.HTTP_400_BAD_REQUEST
        # all the session needed elements exist
        return render_template('route_mdl/mdl-form.html', hidden_elems=[('version', session.get('version')), ('country', session.get('country')), ('certificate', session.get('certificate')), ('returnURL', session.get('returnURL')), ('device_publickey', session.get('device_publickey'))])

    # if POST    
    if 'Cancelled' in request.form.keys(): # Form request Cancelled
        return render_template('route_mdl/mdl-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
    
    (b, l) = validate_mandatory_args(request.form, ['CurrentGivenName', 'CurrentFamilyName', 'DateOfBirth', 'DocumentNumber','BirthPlace', 'Portrait', 'version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not b: # valid form has not been submitted 
        # render page where user can select mdl_countries
        return render_template('route_mdl/mdl-form.html', hidden_elems=[('version', cfgserv.current_version), ('country', cfgcountries.formCountry), ('certificate', base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8')), ('returnURL', cfgserv.service_url + 'mdl/show'), ('device_publickey', cfgdev.device_publickey)])

    # if submitted form is valid
    v = validate_params_getpid_or_mdl(request.form, ['version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not isinstance(v, bool): # getmdl params were not correctly validated
        return v

    #session['version'] = request.form['version']
    #session['country'] = request.form['country']
    #session['certificate'] = request.form['certificate']
    #session['returnURL'] = request.form['returnURL']
    
    
    DrivingPrivileges=[]
    dictdata=request.form.to_dict()
    

    if dictdata['Portrait']== "Port1":
        dictdata['Portrait']= cfgdev.portrait1
    if dictdata['Portrait']== "Port2":
        dictdata['Portrait']= cfgdev.portrait2

    i=1
    for i in range(int(request.form['NumberCategories'])):
        f=str(i+1)
        drivP={
            'vehicle_category_code':request.form['Category'+f],
            'issue_date':request.form['IssueDate'+f],
            'expiry_date':request.form['ExpiryDate'+f],
        }

        DrivingPrivileges.append(drivP)

    jsondata=json.dumps(DrivingPrivileges)

    user_id = generate_unique_id()
    timestamp = int(datetime.timestamp(datetime.now()))

    dados = {
        'version': request.form['version'], 
        'country': request.form['country'], 
        'certificate': request.form['certificate'], 
        'returnURL': request.form['returnURL'], 
        'device_publickey': request.form['device_publickey'],
        'CurrentGivenName': dictdata['CurrentGivenName'],
        'CurrentFamilyName': dictdata['CurrentFamilyName'],
        'DateOfBirth': dictdata['DateOfBirth'],
        'IssuingAuthority': cfgserv.mdl_issuing_authority,
        'DocumentNumber': dictdata['DocumentNumber'],
        'Portrait': dictdata['Portrait'],
        'DrivingPrivileges': jsondata,
        'BirthPlace': dictdata['BirthPlace'],

        'timestamp': timestamp
    }

    # (error_code, ciphertext, nonce, authTag, pub64, sd_jwt) = process_mdl_form({'CurrentGivenName': dictdata['CurrentGivenName'], 'CurrentFamilyName': dictdata['CurrentFamilyName'], 'DateOfBirth': dictdata['DateOfBirth'],
    # 'IssuingAuthority':cfgserv.mdl_issuing_authority, 'DocumentNumber':dictdata['DocumentNumber'],'Portrait': dictdata['Portrait'],
    # 'DrivingPrivileges':jsondata,'BirthPlace':dictdata['BirthPlace'] ,'version': session['version'], 'country': session['country'],
    # 'certificate': session['certificate'], 'returnURL': session['returnURL']}, cipher=not(session['version'] == "0.1"))

    app.config['mdl'][user_id] = dados
    
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
    """ Function to generate a random uuid"""
    import uuid
    return str(uuid.uuid4())


@mdl.route('/form_R2', methods=['GET','POST'])
def form_R2():
    """ Route acessed by OpenID to get mdl attributes from country FC

    Get query parameters:
    + user_id - token to obtain mdl attributes
    
    Return:mdl in sd-jwt and mdoc formats

    """
    user_id = request.args['user_id']
    
    dados =  app.config['mdl'].get(user_id, 'Data not found')
    
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

    session['route'] = "/V04/mdl/form_R2"
    log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")
    
    form = {
        'CurrentGivenName': dados['CurrentGivenName'],
        'CurrentFamilyName': dados['CurrentFamilyName'],
        'DateOfBirth': dados['DateOfBirth'],
        'IssuingAuthority': dados['IssuingAuthority'],
        'DocumentNumber': dados['DocumentNumber'],
        'Portrait': dados['Portrait'],
        'DrivingPrivileges': dados['DrivingPrivileges'],
        'BirthPlace': dados['BirthPlace'],
        "version": session["version"],
        "country": session["country"],
        "certificate": "",
        "returnURL": "",
    }
    
    (error_code, mdoc, nonce, authTag, pub64, sd_jwt) = process_mdl_form(form, cipher=False)
    return  {
        "mdoc": mdoc,
        "sd-jwt": sd_jwt
    }

def clear_data():
    """ Function to clear app.config['mdl']

    """
    now = datetime.now()
    aux = []

    for unique_id, dados in app.config['mdl'].items():
        timestamp = datetime.fromtimestamp(dados.get('timestamp', 0))
        diff = now - timestamp
        if diff.total_seconds() > (cfgserv.max_time_data * 60): #minutos * 60 segundos -> os dados sao eliminados depois de estarem guardados durante 1 minuto
            aux.append(unique_id)
    
    for unique_id in aux:
        del app.config['mdl'][unique_id]
    
    if aux:
        print (f"Entradas {aux} eliminadas.")

import threading
import schedule
import time
def job():
    clear_data()


schedule.every(cfgserv.schedule_check).minutes.do(job) #agendado para correr a cada 5 minutos


def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()


@mdl.route('/view')
def vi():
    """ Route for getting app.config['data']
    
    Return:app.config['data']
    """
    return app.config['mdl']



# --------------------------------------------------------------------------------------------------------------------------------------
# route to /mdl/show
@mdl.route('/show', methods=['GET'])
def showMDL():
    """Is used by /mdl as a default route to show MDL.
    
    Get query parameters:
    + mdoc (mandatory) - MDL in cbor/mdoc format, ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + nonce (mandatory) - random AES initialization vector (bytes encoded in base64urlsafe format).
    + authTag (mandatory) - MAC code of the encrypted text, obtained by the GCM block mode (bytes encoded in base64urlsafe format).
    + ciphertextPubKey (mandatory) - randomly generated ephemeral public key, that will be used to derive the symmetric encryption key, using the ECDH key agreement scheme. Public key in DER format, encoded in base64urlsafe format.
    + sd-jwt - MDL in sd-jwt format (with disclosures), ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + error (mandatory) - error number. 0 if no error.
    + error_str (mandatory) - Error information.

    Return: Render web page
    """
    session['route'] = "/V04/mdl/show"
    log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")
  

    if session['version'] == "0.3":
        v = validate_params_showpid_or_mdl(request.args, ['mdoc', 'nonce', 'authTag', 'ciphertextPubKey','sd_jwt', 'error', 'error_str'])
        if not isinstance(v, bool): # getpid params were not correctly validated
            return v
    else:
        v = validate_params_showpid_or_mdl(request.args, ['mdoc', 'mdoc_nonce', 'mdoc_authTag', 'mdoc_ciphertextPubKey','error', 'error_str'])
        if not isinstance(v, bool): # getpid params were not correctly validated
            return v
        
    sd_jwt=request.args.get('sd_jwt')
    if session['version'] == "0.1": # mdoc not ciphered
        mdoc = request.args.get('mdoc').encode('utf-8')
        return render_template('route_mdl/mdl-show.html', elems = cbor2elems(mdoc), mdoc = mdoc.decode('utf-8'), sd_jwt= sd_jwt)
    if session['version'] == "0.2":
        privkey = serialization.load_pem_private_key(base64.b64decode(session['privkey']), password=None, backend=default_backend())
        mdoc = decrypt_ECC(base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')), 
                        base64.urlsafe_b64decode(request.args.get('mdoc_nonce').encode('utf-8')),
                        base64.urlsafe_b64decode(request.args.get('mdoc_authTag').encode('utf-8')), 
                        pubkeyPoint(serialization.load_der_public_key(base64.urlsafe_b64decode(request.args.get('mdoc_ciphertextPubKey').encode("utf-8")))),
                        privkey.private_numbers().private_value)
        return render_template('route_mdl/mdl-show.html', elems = cbor2elems(mdoc), mdoc = mdoc.decode('utf-8'), sd_jwt= sd_jwt) 
    else:
        # decipher mdoc
        privkey = serialization.load_pem_private_key(base64.b64decode(session['privkey']), password=None, backend=default_backend())
        mdoc = decrypt_ECC(base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')), 
                        base64.urlsafe_b64decode(request.args.get('nonce').encode('utf-8')),
                        base64.urlsafe_b64decode(request.args.get('authTag').encode('utf-8')), 
                        pubkeyPoint(serialization.load_der_public_key(base64.urlsafe_b64decode(request.args.get('ciphertextPubKey').encode("utf-8")))),
                        privkey.private_numbers().private_value)
        return render_template('route_mdl/mdl-show.html', elems = cbor2elems(mdoc), mdoc = mdoc.decode('utf-8'), sd_jwt= sd_jwt ) 

# --------------------------------------------------------------------------------------------------------------------------------------
# route to /mdl version 0.1
@mdl.route('/v01', methods=['GET','POST'])
def mdl_root_v01():
    """Initial MDL page. 
    Loads country config information and renders mdl-countries_v01.html so that the user can select the MDL issuer country and set the version 0.1."""
    countries_name ={
        'FC': 'Form Country', 'PT': 'Portugal',
    }
    form_keys = request.form.keys()
    form_country = request.form.get('country')

    # if country was selected
    if 'country' in form_keys and 'proceed' in form_keys and form_country in countries_name.keys():
        session['privkey'] = base64.b64encode(cfgdev.privkeystr).decode('utf-8')        
        return redirect(url_get(cfgserv.service_url + "mdl/getmdl", 
                                {'returnURL': cfgserv.service_url + 'mdl/show', 
                                 'version': "0.1",
                                 'country': form_country,
                                 'device_publickey': cfgdev.device_publickey,
                                 'certificate': base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8')}))

    # render page where user can select pid_countries
    return render_template('route_mdl/mdl-countries_v01.html', countries = countries_name)