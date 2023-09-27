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


This route_ee_tara.py file is the blueprint for the route /tara (EE - Estonia) of the PID Issuer Web service.
"""
import logging
import requests
import json

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from .validate import validate_mandatory_args
from .redirect_func import redirect_getpid
from .pid_func import process_pid_form


# /tara blueprint
tara = Blueprint('tara', __name__, url_prefix='/tara')

# Log
logger = logging.getLogger()


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /tara
# @tara.route('', methods=['GET','POST'])
# # route to /tara/
# @tara.route('/', methods=['GET','POST'])
# def tara():
#     """Initial eIDAS-node page. 
#     Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""


#     if 'country' in request.form.keys():
#         print(cfgcountries.supported_countries[request.form.get('country')]['pid_url'])
#     return render_template('route_pid/pid-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
#     return "to be implemented", status.HTTP_200_OK
 

# --------------------------------------------------------------------------------------------------------------------------------------
# route to /tara/redirect
@tara.route('/redirect', methods=['GET'])
def red():
    """Receives token from EE Tara IDP - communication originated in route /pid/getpid for country EE
    
    GET parameters:
    + code (mandatory) - Token code to retrieve the shared attributes consented by the user.
    + scope (mandatory) - scope of the request.
    + state (mandatory) - state of the request.

    Return: Redirect answer to returnURL.
    """
    (v, l) = validate_mandatory_args(request.args, ['code', 'scope', 'state'])
    if not v: # if not all arguments are available
        return redirect_getpid(session['version'], session['returnURL'], 501, [])

    # Retrieve the shared attributes consented by the user
    url = "https://tara-test.ria.ee/oidc/token"
    headers = {"Host": "tara-test.ria.ee", "Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic ZXVfZXVyb3BhX2VjX2V1ZGl3X3BpZF9wcm92aWRlcl8xX3BwcjpINUVpVjdPaGZMTUs1TFBvcXB0NG5WT1FJeEdicEZ3MQ=="}
    data = "grant_type=authorization_code&code="+request.args.get('code')+"&redirect_uri=https://pprpid.provider.eudiw.projj.eu/tara/redirect"
    r = requests.post(url, headers = headers, data = data)
    json_response = json.loads(r.text)

    url = "https://tara-test.ria.ee/oidc/profile?access_token=" + json_response["access_token"]
    headers = {"Host": "tara-test.ria.ee"}
    r = requests.get(url, headers = headers)
    json_response=json.loads(r.text)

    (error_code, ciphertext, nonce, authTag, pub64, sd_jwt) = process_pid_form({'CurrentGivenName': json_response["given_name"], 'CurrentFamilyName': json_response["family_name"], 'DateOfBirth': json_response["date_of_birth"], 'PersonIdentifier': json_response["sub"], 'version': session['version'], 'country': session['country'], 'certificate': session['certificate'], 'returnURL': session['returnURL']}, cipher=not(session['version'] == "0.1"))    

    if not error_code == 0:
        return redirect_getpid(session['version'], session['returnURL'], error_code, [])

    return redirect_getpid(session['version'], session['returnURL'], 0, [('mdoc', ciphertext), ('nonce', nonce), ('authTag', authTag), ('ciphertextPubKey', pub64), ('sd_jwt', sd_jwt) ])

