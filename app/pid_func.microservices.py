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


This pid_func.py file contains PID related auxiliary functions.
"""
import datetime
import base64
from flask import session
from app_config.config_service import ConfService as cfgserv
from misc import calculate_age
from redirect_func import json_post
from crypto_func import eccEnc, pubkeyDER


def format_pid_data(dict, country):
    """Formats PID data, from the format received from the eIDAS node, into the format expected by the CBOR formatter (route formatter/cbor)
    
    Keyword arguments:
    dict -- dictionary with PID data received from the eIDAS node
    country -- PID issuing country

    Return: dictionary in the format expected by the CBOR formatter (route formatter/cbor)
    """
    birthdate = dict['DateOfBirth']
    today = datetime.date.today()
    expiry = today + datetime.timedelta(days = cfgserv.pid_validity)
    pdata = {'family_name': dict['CurrentFamilyName'], 'given_name': dict['CurrentGivenName'], 'birth_date': birthdate, 
             'unique_id': dict['PersonIdentifier'],
             'age_over_18': True if calculate_age(birthdate) >= 18 else False,
             'issuance_date': today.strftime("%Y-%m-%d"),
             'expiry_date': expiry.strftime("%Y-%m-%d"),
             'issuing_authority': cfgserv.pid_issuing_authority,
             'issuing_country': country}

    return pdata

def format_sd_jwt_pid_data(dict, country):
    """Formats PID data, from the format received from the eIDAS node, into the format expected by the CBOR formatter (route formatter/cbor)
    
    Keyword arguments:
    dict -- dictionary with PID data received from the eIDAS node
    country -- PID issuing country

    Return: dictionary in the format expected by the CBOR formatter (route formatter/cbor)
    """
    birthdate = dict['DateOfBirth']
    today = datetime.date.today()
    expiry = today + datetime.timedelta(days = cfgserv.pid_validity)
    pdata = {
        'evidence':[{
            'type':'link do issuer',
            'source':{
                    'organization_name': cfgserv.pid_issuing_authority,
                    'organization_id':'IPA Code',
                    'country_code': country
            }
        }],
        'claims':{
            'eu.europa.ec.eudiw.pid.1':{
                'family_name': dict['CurrentFamilyName'],
                'given_name': dict['CurrentGivenName'],
                'birth_date': birthdate, 
                'unique_id': dict['PersonIdentifier'],
                'age_over_18': True if calculate_age(birthdate) >= 18 else False,
                'issuance_date': today.strftime("%Y-%m-%d"),
                'expiry_date': expiry.strftime("%Y-%m-%d"),
            },
            'eu.europa.ec.eudiw.DE.1':{
                "signature_usual_mark": "a36776657273696f6e63312e3069646f63756d656e..."
            }
        }
    }

    return pdata



def format_form_data(l, country):
    """Formats PID data, from the format received from the PID form (route pid/form), into the format expected by the CBOR formatter (route formatter/cbor)
    
    Keyword arguments:
    l -- list of tuples with PID data received from the PID form
    country -- PID issuing country

    Return: dictionary in the format expected by the CBOR formatter (route formatter/cbor)
    """
    dict = dict(l)
    birthdate = dict['birthdate']
    today = datetime.date.today()
    expiry = today + datetime.timedelta(days = cfgserv.pid_validity)
    pdata = {'family_name': dict['familyname'], 'given_name': dict['firstname'], 'birth_date': birthdate, 
             'unique_id': dict['nationalidentifier'],
             'age_over_18': True if calculate_age(birthdate) >= 18 else False,
             'issuance_date': today.strftime("%Y-%m-%d"),
             'expiry_date': expiry.strftime("%Y-%m-%d"),
             'issuing_authority': cfgserv.pid_issuing_authority,
             'issuing_country': country}

    return pdata



def process_pid_form(d, cipher=True):
    """Process the data received from the PID form (route /pid/form)
    
    Keyword arguments:
    + d -- request.form
    + cipher -- if True ciphertext is ciphered

    Return: Returns (error_code, ciphertext, nonce, authTag, pub64, sd-jwt). If error_code != 0, an error occured.
    """
    pdata = format_pid_data(dict(d), session['country'])

    pdata1= format_sd_jwt_pid_data(dict(d), session['country'])

    # r = json_post(cfgserv.service_url + "formatter/cbor", 
    #               {'version': session['version'], 'country': session['country'], 'doctype': cfgserv.pid_doctype, 'device_publickey': session['device_publickey'],
    #                'data':{cfgserv.pid_namespace: pdata}
    #                }).json()
    # if not r['error_code'] == 0:
    #     return (r['error_code'], None, None, None, None)
    
    # microservice
    a = {
  "version": "1.0",
  "documents": [
    {
      "docType": "eu.europa.ec.eudiw.pid.1",
      "metadata": {
        "device_cert": session['certificate'],
        "validity_info": {
          "expected_update": "2024-01-01",
          "valid_until": "2025-01-01"
        },
        "random_length": "128"
      },
      "namespaces": {
          "eu.europa.ec.eudiw.pid.1":{
            "family_name": "Garcia", 
            "given_name": "javier", 
            "birth_date": "1965-01-01", 
            "age_over_18": True, 
            "unique_id": "86b73c6c-7542-4923-a986-97d2cdf7f07a",
            "issuance_date": "2023-07-19",
            "expiry_date": "2023-10-19",
            "issuing_authority": "Bundes...",
            "issuing_country": "DE"
        }
      }
    }
  ]
}
    r = json_post("https://mso-service.azurewebsites.net/api/v1/MDoc/CreateResponse", a).json()  


    r1 = json_post(cfgserv.service_url + "formatter/sd-jwt", 
                  {'version': session['version'], 'country': session['country'], 'doctype': cfgserv.pid_doctype, 'device_publickey': session['device_publickey'],
                   'data': pdata1
                   }).json()    
    if not r1['error_code'] == 0:
        return (r1['error_code'], None, None, None, None)
 
    # mdoc from urlsafe_b64encode to b64encode
    # mdoc = bytes(r['mdoc'], 'utf-8')

    # microservices
    mdoc = bytes(r['response'], 'utf-8')

    sd_jwt=r1['sd-jwt']
    

    # if cipher:
    #     #cipher mdoc
    #     encryptedMsg = eccEnc(base64.urlsafe_b64decode(session['certificate']), mdoc.decode())
    #     ciphertext = base64.urlsafe_b64encode(encryptedMsg[0]).decode('utf-8')
    #     nonce = base64.urlsafe_b64encode(encryptedMsg[1]).decode('utf-8')
    #     authTag = base64.urlsafe_b64encode(encryptedMsg[2]).decode('utf-8')
    #     pub64 = base64.urlsafe_b64encode(pubkeyDER(encryptedMsg[3].x, encryptedMsg[3].y)).decode("utf-8")
    # else:
    #     ciphertext = base64.urlsafe_b64encode(mdoc).decode('utf-8')
    #     nonce = authTag = pub64 = ""

    # microservices
    ciphertext = base64.urlsafe_b64encode(mdoc).decode('utf-8')
    nonce = authTag = pub64 = ""
    
    return (0, ciphertext, nonce, authTag, pub64, sd_jwt)
