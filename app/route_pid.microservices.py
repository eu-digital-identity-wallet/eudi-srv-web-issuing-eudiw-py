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


This route_pid.py file is the blueprint for the route /pid of the PID Issuer Web service.
"""

import logging
import base64

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from flask_api import status
from flask_cors import CORS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from validate import validate_getpidtest_result, validate_params_getpid, validate_params_showpid, validate_mandatory_args
from crypto_func import eccEnc, pubkeyDER, pubkeyPoint, decrypt_ECC
from app_config.config_devtest import ConfTest as cfgdev
from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries
from redirect_func import redirect_getpid_or_mdl, url_get
from misc import create_dict
from formatter_func import cbor2elems
from pid_func import process_pid_form

# /pid blueprint
pid = Blueprint('pid', __name__, url_prefix='/pid')
CORS(pid) # enable CORS on the blue print

# Log
logger = logging.getLogger()


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /pid with current version
@pid.route('', methods=['GET','POST'])
# route to /pid/
@pid.route('/', methods=['GET','POST'])
def pid_root():
    """Initial PID page. 
    Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""
    countries_name = create_dict(cfgcountries.supported_countries, 'name')
    form_keys = request.form.keys()
    form_country = request.form.get('country')


    # if country was selected
    if 'country' in form_keys and 'proceed' in form_keys and form_country in countries_name.keys():
        session['privkey'] = base64.b64encode(cfgdev.privkeystr).decode('utf-8') 
        #print(base64.urlsafe_b64encode(cfgdev.device_publickey.encode('utf-8')).decode('utf-8'))

        
        # #if country is empty
        # if (session['country'] == ""):

        #     return redirect(url_get(cfgserv.service_url + "pid/getpid", 
        #                         {'returnURL': session['returnURL'] , 
        #                          'version': session['version'] ,
        #                          'country': form_country,
        #                          'certificate': session ['certificate'],
        #                          'device_publickey': session['device_publickey']}))
        
        #print("pid_root: " + session['privkey'])    
        return redirect(url_get(cfgserv.service_url + "pid/getpid", 
                                {'returnURL': cfgserv.service_url + 'pid/show', 
                                 'version': cfgserv.current_version,
                                 'country': form_country,
                                 'certificate': base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8'),
                                 'device_publickey': cfgdev.device_publickey}))

    # render page where user can select pid_countries
    return render_template('route_pid/pid-countries.html', countries = countries_name)


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /pid version 0.1
@pid.route('/v01', methods=['GET','POST'])
def pid_root_v01():
    """Initial PID page. 
    Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""
    countries_name = create_dict(cfgcountries.supported_countries, 'name')
    form_keys = request.form.keys()
    form_country = request.form.get('country')

    # if country was selected
    if 'country' in form_keys and 'proceed' in form_keys and form_country in countries_name.keys():
        session['privkey'] = base64.b64encode(cfgdev.privkeystr).decode('utf-8')        
        return redirect(url_get(cfgserv.service_url + "pid/getpid", 
                                {'returnURL': cfgserv.service_url + 'pid/show', 
                                 'version': "0.1",
                                 'country': form_country,
                                 'device_publickey': cfgdev.device_publickey,
                                 'certificate': base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8')}))

    # render page where user can select pid_countries
    return render_template('route_pid/pid-countries_v01.html', countries = countries_name)


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /pid/getpid
@pid.route('/getpid', methods=['GET'])
#@cross_origin(supports_credentials=True)
def getPid():
    """PID request. Starts the process of issuance of the PID in CBOR (ISO 18013-5 mdoc) and SD-JWT format.
    
    Get query parameters:
    + version (mandatory) - API version
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
    + certificate (mandatory) - certificate (PEM format) encoded in base64urlsafe. 
    + returnURL (mandatory) - URL where the response will be redirected.
    + device_publickey -  Device public key (PEM format), encoded in base64urlsafe 

    Return: HTTP_400_BAD_REQUEST if returnURL is missing. Otherwise, GET redirect to returnURL.
    """

    v = validate_params_getpid(request.args, ['version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not isinstance(v, bool): # getpid params were not correctly validated
        return v

    # getpid params correctly validated
    session['version'] = request.args['version']
    session['country'] = request.args['country']
    session['certificate'] = request.args['certificate']
    session['returnURL'] = request.args['returnURL']
    session['device_publickey'] = request.args['device_publickey']

    if (session['country'] == ""):

        return redirect(cfgserv.service_url + 'pid/?version='+ session['version']+ '&country=' + session['country'] + '&certificate=' + session ['certificate'] + '&returnURL=' + session['returnURL'] + '&device_publickey='+ session['device_publickey'] )


    #print("getpid privkey: " + str(session.get('privkey')) + " - " + str(session.keys()) + "\n" + str(request.args))
    #session.pop('privkey', default=None)

    return redirect(cfgcountries.supported_countries[request.args['country']]['pid_url'])


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /pid/show
@pid.route('/show', methods=['GET'])
def showPid():
    """Is used by /pid as a default route to show PID.
    
    Get query parameters:
    + mdoc (mandatory) - PID in cbor/mdoc format, ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + nonce (mandatory) - random AES initialization vector (bytes encoded in base64urlsafe format).
    + authTag (mandatory) - MAC code of the encrypted text, obtained by the GCM block mode (bytes encoded in base64urlsafe format).
    + ciphertextPubKey (mandatory) - randomly generated ephemeral public key, that will be used to derive the symmetric encryption key, using the ECDH key agreement scheme. Public key in DER format, encoded in base64urlsafe format.
    + sd-jwt - PID in sd-jwt format (with disclosures), ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + error (mandatory) - error number. 0 if no error.
    + error_str (mandatory) - Error information.

    Return: Render web page
    """
    v = validate_params_showpid(request.args, ['mdoc', 'nonce', 'authTag', 'ciphertextPubKey','sd_jwt', 'error', 'error_str'])
    if not isinstance(v, bool): # getpid params were not correctly validated
        return v
    
    if session['version'] == "0.1": # mdoc not ciphered
        #mdoc = base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8'))
        # microservices
        print("test microservice: " + request.args.get('mdoc'))
        
        mdoc = base64.b64decode(request.args.get('mdoc').encode('utf-8'))
        sd_jwt=request.args.get('sd_jwt')
        return render_template('route_pid/pid-show.html', elems = cbor2elems(mdoc), mdoc = mdoc, sd_jwt= sd_jwt )
    if session['version'] == "0.2":
        privkey = serialization.load_pem_private_key(base64.b64decode(session['privkey']), password=None, backend=default_backend())
        mdoc = decrypt_ECC(base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')), 
                        base64.urlsafe_b64decode(request.args.get('nonce').encode('utf-8')),
                        base64.urlsafe_b64decode(request.args.get('authTag').encode('utf-8')), 
                        pubkeyPoint(serialization.load_der_public_key(base64.urlsafe_b64decode(request.args.get('ciphertextPubKey').encode("utf-8")))),
                        privkey.private_numbers().private_value)
        return render_template('route_pid/pid-show.html', elems = cbor2elems(mdoc), mdoc = mdoc) 
    else:
        # decipher mdoc
        privkey = serialization.load_pem_private_key(base64.b64decode(session['privkey']), password=None, backend=default_backend())
        mdoc = decrypt_ECC(base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')), 
                        base64.urlsafe_b64decode(request.args.get('nonce').encode('utf-8')),
                        base64.urlsafe_b64decode(request.args.get('authTag').encode('utf-8')), 
                        pubkeyPoint(serialization.load_der_public_key(base64.urlsafe_b64decode(request.args.get('ciphertextPubKey').encode("utf-8")))),
                        privkey.private_numbers().private_value)
        sd_jwt=request.args.get('sd_jwt')
        return render_template('route_pid/pid-show.html', elems = cbor2elems(mdoc), mdoc = mdoc, sd_jwt= sd_jwt ) 

    


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /pid/getpidtest
@pid.route('/getpidtest', methods=['GET'])
def getPidTest():
    """PID request for developpers, so that they can test the return PID in cbor/mdoc and SD-JWT format, without the input of the enduser.
    
    Get query parameters:
    + version (mandatory) - API version
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
    + certificate (mandatory) - certificate (PEM format) encoded in base64urlsafe. 
    + returnURL (mandatory) - URL where the response will be redirected.
    + device_publickey -  Device public key (PEM format), encoded in base64urlsafe 

    Return: HTTP_400_BAD_REQUEST if returnURL is missing. Otherwise, GET redirect to returnURL.
    """
    session['version']= request.args.get('version')
    
    v = validate_params_getpid(request.args, ['version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not isinstance(v, bool): # getpid params were not correctly validated
        return v

    # use test cbor mdoc
    plaintext = cfgdev.mdoc64
    sd_jwt=cfgdev.sd_jwt



    if request.args.get('version') == "0.1": # result is not ciphered
        return redirect_getpid_or_mdl(request.args.get('version'), request.args.get('returnURL'), 0, [('mdoc', base64.urlsafe_b64encode(plaintext.encode()).decode('utf-8')), ('mdoc_nonce', ""), ('mdoc_authTag', ""), ('mdoc_ciphertextPubKey', "")])
    if request.args.get('version') == "0.2":
        encryptedMsg = eccEnc(base64.urlsafe_b64decode(request.args.get('certificate')), plaintext)
        ciphertext = base64.urlsafe_b64encode(encryptedMsg[0]).decode('utf-8')
        nonce = base64.urlsafe_b64encode(encryptedMsg[1]).decode('utf-8')
        authTag = base64.urlsafe_b64encode(encryptedMsg[2]).decode('utf-8')
        pub64 = base64.urlsafe_b64encode(pubkeyDER(encryptedMsg[3].x, encryptedMsg[3].y)).decode("utf-8")

        return redirect_getpid_or_mdl(request.args.get('version'), request.args.get('returnURL'), 0, [('mdoc', ciphertext), ('mdoc_nonce', nonce), ('mdoc_authTag', authTag), ('mdoc_ciphertextPubKey', pub64)])

    encryptedMsg = eccEnc(base64.urlsafe_b64decode(request.args.get('certificate')), plaintext)
    ciphertext = base64.urlsafe_b64encode(encryptedMsg[0]).decode('utf-8')
    nonce = base64.urlsafe_b64encode(encryptedMsg[1]).decode('utf-8')
    authTag = base64.urlsafe_b64encode(encryptedMsg[2]).decode('utf-8')
    pub64 = base64.urlsafe_b64encode(pubkeyDER(encryptedMsg[3].x, encryptedMsg[3].y)).decode("utf-8")    

    return redirect_getpid_or_mdl(request.args.get('version'), request.args.get('returnURL'), 0, [('mdoc', ciphertext), ('nonce', nonce), ('authTag', authTag), ('ciphertextPubKey', pub64), ('sd_jwt', sd_jwt)])


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /pid/returnpidtest
#
# Can be tested with the following curl command line
# curl -L -v https://issuer.eudiw.dev/pid/getpidtest?version="0.2"\&country="PT"\&returnURL="https://issuer.eudiw.dev/pid/returnpidtest"\&certificate="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIzakNDQVlXZ0F3SUJBZ0lVWWJFTlJQN3VWOTUrQ3BBVlFDcHl6VmNRVmlVd0NnWUlLb1pJemowRUF3SXcKUlRFTE1Ba0dBMVVFQmhNQ1FWVXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4SVRBZkJnTlZCQW9NR0VsdQpkR1Z5Ym1WMElGZHBaR2RwZEhNZ1VIUjVJRXgwWkRBZUZ3MHlNekEzTVRBeE1EUTFOVFZhRncweU5EQTNNRFF4Ck1EUTFOVFZhTUVVeEN6QUpCZ05WQkFZVEFrRlZNUk13RVFZRFZRUUlEQXBUYjIxbExWTjBZWFJsTVNFd0h3WUQKVlFRS0RCaEpiblJsY201bGRDQlhhV1JuYVhSeklGQjBlU0JNZEdRd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqTwpQUU1CQndOQ0FBVHdnUkFHUGdKbDNkaUo5ZWVPcEdXMGdpSWtQcGFGa1RFU1E5U0E5SEw5akM1NFd3azNvOTZICkNxMjlUVVhQYlNkYjFseFFzck9ncUphQ0dJM0xmem5RbzFNd1VUQWRCZ05WSFE0RUZnUVV5VkgxV0drQ1FOcnoKNjJFTHkvd1lmekFRYVZVd0h3WURWUjBqQkJnd0ZvQVV5VkgxV0drQ1FOcno2MkVMeS93WWZ6QVFhVlV3RHdZRApWUjBUQVFIL0JBVXdBd0VCL3pBS0JnZ3Foa2pPUFFRREFnTkhBREJFQWlCYXZLbU5TSWxCWXh6TmcxdU1Fd3BJCkZGNlZFdmlRQllwWnNYYURvQmRhQ1FJZ00rZUFBUE5zNXErNnZ0SVR1R1pTUkdoN1U3U1VMdWNqWGZJNmU0N2IKSjI4PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
#
@pid.route('/returnpidtest', methods=['GET'])
def returnPidTest():
    """Validates the result of /pid/getpidtest when using predefined certificate
    
    Get query parameters:
    + mdoc (mandatory) - PID in cbor/mdoc format, ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + nonce (mandatory) - random AES initialization vector (bytes encoded in base64urlsafe format).
    + authTag (mandatory) - MAC code of the encrypted text, obtained by the GCM block mode (bytes encoded in base64urlsafe format).
    + ciphertextPubKey (mandatory) - randomly generated ephemeral public key, that will be used to derive the symmetric encryption key, using the ECDH key agreement scheme. Public key in DER format, encoded in base64urlsafe format.
    + sd_jwt - PID in sd-jwt format (with disclosures), ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
    + error (mandatory) - error number. 0 if no error.
    + error_str (mandatory) - Error information.

    Return: HTTP_200 with Info about the correct decipher of the mdoc.
    """

    if session['version'] == "0.3":
        v = validate_params_showpid(request.args, ['mdoc', 'nonce', 'authTag', 'ciphertextPubKey','sd_jwt', 'error', 'error_str'])
        if not isinstance(v, bool): # getpid params were not correctly validated
            return v


        if request.args.get('nonce') == "": # assume that mdoc was not ciphered
            return "/pid/getpidtest result validated: " + str(base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')).decode() == cfgdev.mdoc64) + "\n", status.HTTP_200_OK

        val = validate_getpidtest_result(
            base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')), 
            base64.urlsafe_b64decode(request.args.get('nonce').encode('utf-8')), 
            base64.urlsafe_b64decode(request.args.get('authTag').encode('utf-8')), 
            serialization.load_der_public_key(base64.urlsafe_b64decode(request.args.get('ciphertextPubKey').encode("utf-8"))),
            cfgdev.mdoc64,
            serialization.load_pem_private_key(cfgdev.privkeystr, password=None, backend=default_backend())
            )
    
        return "/pid/getpidtest result validated: " + str(val) + "\n", status.HTTP_200_OK
    
    else:
        v = validate_params_showpid(request.args, ['mdoc', 'mdoc_nonce', 'mdoc_authTag', 'mdoc_ciphertextPubKey','error', 'error_str'])
        
        if not isinstance(v, bool): # getpid params were not correctly validated
            return v


        if request.args.get('mdoc_nonce') == "": # assume that mdoc was not ciphered
            return "/pid/getpidtest result validated: " + str(base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')).decode() == cfgdev.mdoc64) + "\n", status.HTTP_200_OK

        val = validate_getpidtest_result(
            base64.urlsafe_b64decode(request.args.get('mdoc').encode('utf-8')), 
            base64.urlsafe_b64decode(request.args.get('mdoc_nonce').encode('utf-8')), 
            base64.urlsafe_b64decode(request.args.get('mdoc_authTag').encode('utf-8')), 
            serialization.load_der_public_key(base64.urlsafe_b64decode(request.args.get('mdoc_ciphertextPubKey').encode("utf-8"))),
            cfgdev.mdoc64,
            serialization.load_pem_private_key(cfgdev.privkeystr, password=None, backend=default_backend())
            )
    
        return "/pid/getpidtest result validated: " + str(val) + "\n", status.HTTP_200_OK


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /pid/form
@pid.route('/form', methods=['GET','POST'])
def pid_form():
    """Form PID page. 
    Form page where the user can enter its PID data.
    """
    #print("/pid/form POST: " + str(request.form))
    #print("/pid/form GET: " + str(request.args))
    #print("/pid/form session:  " + session['version'])


    # if GET
    if request.method == 'GET':
        if session.get('version') is None or session.get('country') is None or session.get('certificate') is None or session.get('returnURL') is None or session.get('device_publickey') is None: # someone is trying to connect directly to this endpoint
            return "Error 101: " + cfgserv.error_list['101'] + "\n", status.HTTP_400_BAD_REQUEST
        # all the session needed elements exist
        return render_template('route_pid/pid-form.html', hidden_elems=[('version', session.get('version')), ('country', session.get('country')), ('certificate', session.get('certificate')), ('returnURL', session.get('returnURL')), ('device_publickey', session.get('device_publickey'))])

    # if POST    
    if 'Cancelled' in request.form.keys(): # Form request Cancelled
        return render_template('route_pid/pid-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
    (b, l) = validate_mandatory_args(request.form, ['CurrentGivenName', 'CurrentFamilyName', 'DateOfBirth', 'PersonIdentifier', 'version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not b: # valid form has not been submitted 
        # render page where user can select pid_countries
        return render_template('route_pid/pid-form.html', hidden_elems=[('version', cfgserv.current_version), ('country', cfgcountries.formCountry), ('certificate', base64.urlsafe_b64encode(cfgdev.certificate).decode('utf-8')), ('returnURL', cfgserv.service_url + 'pid/show'), ('device_publickey', cfgdev.device_publickey)])

    # if submitted form is valid
    v = validate_params_getpid(request.form, ['version', 'country', 'certificate', 'returnURL', 'device_publickey'])
    if not isinstance(v, bool): # getpid params were not correctly validated
        return v

    #session['version'] = request.form['version']
    #session['country'] = request.form['country']
    #session['certificate'] = request.form['certificate']
    #session['returnURL'] = request.form['returnURL']

    if session['version'] == "0.1": # result is not ciphered
        (error_code, ciphertext, nonce, authTag, pub64, sd_jwt) = process_pid_form(request.form, cipher=False)
    else: #result is ciphered
        (error_code, ciphertext, nonce, authTag, pub64, sd_jwt) = process_pid_form(request.form)

    if not error_code == 0:
        return redirect_getpid_or_mdl(session['version'], session['returnURL'], error_code, [])

    return redirect_getpid_or_mdl(session['version'], session['returnURL'], 0, [('mdoc', ciphertext), ('nonce', nonce), ('authTag', authTag), ('ciphertextPubKey', pub64), ('sd_jwt', sd_jwt)])


