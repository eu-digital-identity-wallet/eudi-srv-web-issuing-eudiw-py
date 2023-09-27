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


This route_fromatter.py file is the blueprint for the route /formatter of the PID Issuer Web service.
"""
import logging


from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from .validate import validate_mandatory_args
from .app_config.config_service import ConfService as cfgservice
from .formatter_func import mdocFormatter,sdjwtFormatter


# /formatter blueprint
formatter = Blueprint('formatter', __name__, url_prefix='/formatter')

# Log
logger = logging.getLogger()


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /formatter
# @formatter.route('', methods=['GET','POST'])
# # route to /formatter/
# @formatter.route('/', methods=['GET','POST'])
# def formatter_root():
#     """Initial eIDAS-node page. 
#     Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""


#     if 'country' in request.form.keys():
#         print(cfgcountries.supported_countries[request.form.get('country')]['pid_url'])
#     return render_template('route_pid/pid-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
#     return "to be implemented", status.HTTP_200_OK
 

# --------------------------------------------------------------------------------------------------------------------------------------
# route to /formatter/cbor
@formatter.route('/cbor', methods=['POST'])
def cborformatter():
    """Creates ISO 18013-5 mdoc in cbor format, and returns signed mdoc
    
    POST json parameters:
    + version (mandatory) - API version.
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
    + doctype (mandatory) - mdoc doctype
    + device_publickey(mandatory) - Public key from user device 
    + data (mandatory) - doctype data "dictionary" with one or more "namespace": {"namespace data and fields"} tuples
    + signature (optional) - "dictionary" with the following fields: "signing_certificate_hash", "signed_country", "signed_doctype", "signed_data". Purpose of this field is twofold:
         + formatter/cbor request can only be performed by allowed entities;
          + non-repudiation of the formatter/cbor request.

    Return: Returns the mdoc, error_code and error_message in a JSON object:
    + mdoc - signed cbor encoded 18013-5 mdoc (in base 64 urlsafe encode).
    + error_code - error number. 0 if no error. Additional errors defined below. If error != 0, mdoc field may have an empty value.
    + error_message - Error information.
    """
    (b, l) = validate_mandatory_args(request.json, ['version', 'country', 'doctype', 'device_publickey', 'data'])
    if not b: # nota all mandatory args are present
        return jsonify({'error_code': 401, 'error_message': cfgservice.error_list['401'], 'mdoc': ''})
    

    base64_mdoc = mdocFormatter(request.json['data'], request.json['doctype'], request.json['country'], request.json['device_publickey'])

    return jsonify({'error_code': 0, 'error_message': cfgservice.error_list['0'], 'mdoc': base64_mdoc})


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /formatter/sd-jwt
@formatter.route('/sd-jwt', methods=['POST'])
def sd_jwtformatter():
    """Creates sd-jwt, and returns sd-jwt
    
    POST json parameters:
    + version (mandatory) - API version.
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
    + doctype (mandatory) - sd-jwt doctype
    + device_publickey(mandatory) - Public key from user device 
    + data (mandatory) - doctype data "dictionary" with one or more "namespace": {"namespace data and fields"} tuples

    Return: Returns the sd-jwt, error_code and error_message in a JSON object:
    + sd-jwt - sd-jwt
    + error_code - error number. 0 if no error. Additional errors defined below. If error != 0, mdoc field may have an empty value.
    + error_message - Error information.
    """

    PID= request.get_json()

    #try:

        #validate(PID, schema)

    #except ValidationError as e:

        #error_message = {  
            #"error_message":str(e)
       # }
        
        #return error_message

    sd_jwt=sdjwtFormatter(PID)
    
    response = {
        "sd-jwt":sd_jwt, 
        "error_code": 0, 
        "error_message": ""
    }

    return response

