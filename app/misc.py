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


This misc.py file includes different miscellaneous functions.
"""
import base64
import datetime

# from app.route_oidc import authentication_error_redirect
from io import BytesIO
import secrets
from urllib import request
from PIL import Image
from app import oidc_metadata
from flask import jsonify, current_app, redirect
from flask.helpers import make_response
from redirect_func import url_get
import json
import uuid


def create_dict(dict, item):
    """Create dictionary with key and value element. The key will be the key of dict and the value will be dict[item]

    Keyword arguments:
    + dict -- dictionary
    + item -- dictionary item

    Return: Return dictionary key: value, where key is the key of dict, and value is dict[item]
    """
    d = {}
    for key in dict:
        try:
            d[key] = dict[key][item]
        except:
            pass
    return d

def urlsafe_b64encode_nopad(data: bytes) -> str:
    """
    Encodes bytes using URL-safe base64 and removes padding.
    
    Args:
        data (bytes): The data to encode.

    Returns:
        str: Base64 URL-safe encoded string without padding.
    """
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def urlsafe_b64encode_nopad(data: bytes) -> str:
    """
    Encodes bytes using URL-safe base64 and removes padding.
    
    Args:
        data (bytes): The data to encode.
    Returns:
        str: Base64 URL-safe encoded string without padding.
    """
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def calculate_age(date_of_birth: str):
    """returns the age, based on the date_of_birth

    Keyword arguments:
    + date_of_birth -- date of birth in the format Year-Month-Day

    Return: Age
    """
    birthDate = datetime.datetime.strptime(date_of_birth, "%Y-%m-%d").date()
    today = datetime.date.today()
    age = today.year - birthDate.year
    if today < datetime.date(today.year, birthDate.month, birthDate.day):
        age -= 1
    return age


def convert_png_to_jpeg(png_bytes):
    # Open the PNG image from bytes
    png_image = Image.open(BytesIO(png_bytes))

    # Create a new in-memory file-like object
    jpeg_buffer = BytesIO()

    # Convert the PNG image to JPEG format and save to the buffer
    png_image.convert("RGB").save(jpeg_buffer, format="JPEG")

    # Get the JPEG bytes from the buffer
    jpeg_bytes = jpeg_buffer.getvalue()

    return jpeg_bytes

def getNamespaces(claims):
    namespaces = []
    for claim in claims:
        if "path" in claim:
            if claim["path"][0] not in namespaces:
                namespaces.append(claim["path"][0])
    
    return namespaces


def getAttributesForm(credentials_requested):
    """
    Function to get attributes needed to populate form depending credentials requested by user

    Keyword arguments:"
    credentials_requested --credentials requested by the user

    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    attributes = {}
    
    for request in credentials_requested:
        format = credentialsSupported[request]["format"]

        attributes_req = {}
        if format == "mso_mdoc":
            namescapes = getNamespaces(credentialsSupported[request]["claims"])
            for namescape in namescapes:
                attributes_req = getMandatoryAttributes(
                    credentialsSupported[request]["claims"],namescape
                )

        elif format == "dc+sd-jwt":
            attributes_req.update(
                getMandatoryAttributesSDJWT(credentialsSupported[request]["claims"])
            )

        for attribute in attributes_req:
            if attribute not in attributes:
                attributes.update({attribute: attributes_req[attribute]})

        if "birth_date" in attributes and "birthdate" in attributes:
            attributes.pop("birthdate")

    return attributes


def getMandatoryAttributes(claims, namespace):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    #for x, value in enumerate(list(attributes.keys())):

    for claim in claims:
        if "overall_issuer_conditions" in claim:
            for key,value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key:value})
        
        elif claim["mandatory"] == True and claim["path"][0] == namespace:

            attribute_name = claim["path"][1]

            if "value_type" in claim:
                attributes_form.update({attribute_name: {"type": claim["value_type"],"filled_value":None}})

            if "issuer_conditions" in claim:
                attributes_form[attribute_name]["type"] = "list"

                if "cardinality" in claim["issuer_conditions"]:
                    attributes_form[attribute_name]["cardinality"] = claim["issuer_conditions"]["cardinality"]
                
                if claim["value_type"] in claim["issuer_conditions"]:
                    #attributes_form[attribute_name]["attributes"] = [attribute_data["issuer_conditions"][attribute_data["value_type"]]]
                    nested_attributes = {}
                    nested_attributes_list = []

                    for key, value in claim["issuer_conditions"][claim["value_type"]].items():

                        if "issuer_conditions" not in value:
                            nested_attributes[key] = value
                        
                        else:
                            
                            attributes_append = {"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}
                           # attributes.append[{"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}]

                            for key2,value2 in value["issuer_conditions"][value["value_type"]].items():
                                attributes_append[key2] = value2

                            if "not_used_if" in value["issuer_conditions"]:
                                attributes_append["not_used_if"] = value["issuer_conditions"]["not_used_if"]

                            nested_attributes_list.append(attributes_append)

                            
                    nested_attributes_list.append(nested_attributes)

                    attributes_form[attribute_name]["attributes"] = nested_attributes_list

    return attributes_form

def getMandatoryAttributesSDJWT(claims):
    """
    Function to get mandatory attributes from credential in sd-jwt vc format
    """
    attributes_form = {}

    level1_claims = []
    level2_claims = []
    level3_claims = []

    for claim in claims:
        if "overall_issuer_conditions" in claim:
            for key,value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key:value})

        else:
        
            claim_depth = len(claim["path"])

            if claim_depth == 1:
                if claim["mandatory"] == True:
                    level1_claims.append(claim)
            elif claim_depth == 2:
                level2_claims.append(claim)
            elif claim_depth == 3:
                level3_claims.append(claim)

    

    for claim in level1_claims:
        attribute_name = claim["path"][0]
        if attribute_name == "nationalities":
            
            attributes_form.update({attribute_name: {"type": claim["value_type"],"filled_value":None}})
            attributes_form[attribute_name]["cardinality"] = {'min': 0,'max': 'n'}
            attributes_form[attribute_name]["attributes"] = [{'country_code': {'mandatory': True,'value_type': 'string','source': 'user'}}]

        if "value_type" in claim and attribute_name != "nationalities":
            attributes_form.update({attribute_name: {"type": claim["value_type"],"filled_value":None}})

        if "issuer_conditions" in claim and attribute_name != "nationalities":
            if "cardinality" in claim["issuer_conditions"]:
                attributes_form[attribute_name]["cardinality"] = claim["issuer_conditions"]["cardinality"]

    for claim in level2_claims:  
        attributes = {}
        attribute_name = claim["path"][0]
        
        if attribute_name not in attributes_form:
            continue

        attributes_form[attribute_name]["type"] = "list"
        
        level2_name = claim["path"][1]
        attributes[level2_name] = {"mandatory":claim["mandatory"],"value_type":claim["value_type"],"source":claim["source"]} 
        
        if "issuer_conditions" in claim:
            if "cardinality" in claim["issuer_conditions"]:
                attributes["cardinality"] = claim["issuer_conditions"]["cardinality"]
            if "not_used_if" in claim["issuer_conditions"]:
                attributes["not_used_if"] = claim["issuer_conditions"]["not_used_if"]
                    
        if "attributes" in attributes_form[attribute_name]:
            if "cardinality" in attributes_form[attribute_name]["attributes"][0]:
                attributes_form[attribute_name]["attributes"].append(attributes)
            else:
                attributes_form[attribute_name]["attributes"][0].update(attributes)
        else:
            attributes_form[attribute_name]["attributes"] = [attributes]

    for claim in level3_claims: 

        attribute_name = claim["path"][0]

        if attribute_name not in attributes_form:
            continue

        level2_name = claim["path"][1]        

        level3_name = claim["path"][2]        

        attributes = {}

        for attribute in attributes_form[attribute_name]["attributes"]:
            if level2_name in attribute:
                attribute.update({
                    "attribute": level2_name,
                    level3_name : {"mandatory":claim["mandatory"],"value_type":claim["value_type"],"source":claim["source"]}
                })
                attribute.pop(level2_name)

                if "cardinality" in attribute:
                    attribute["cardinality"] = attribute["cardinality"]
                if "not_used_if" in attribute:
                    attribute["not_used_if"] = attribute["not_used_if"]

            elif "attribute" in attribute:
                attribute.update({
                    level3_name : {"mandatory":claim["mandatory"],"value_type":claim["value_type"],"source":claim["source"]}
                })
    
    return attributes_form


def getOptionalAttributesSDJWT(claims):
    """
    Function to get optional attributes from credential in sd-jwt vc format
    """
    attributes_form = {}

    level1_claims = []
    level2_claims = []
    level3_claims = []

    for claim in claims:
        if "overall_issuer_conditions" in claim:
            for key,value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key:value})

        else:
            claim_depth = len(claim["path"])

            if claim_depth == 1:
                if claim["mandatory"] == False:
                    level1_claims.append(claim)
            elif claim_depth == 2:
                level2_claims.append(claim)
            elif claim_depth == 3:
                level3_claims.append(claim)
        

    for claim in level1_claims:
        attribute_name = claim["path"][0]
        if attribute_name == "nationalities":            
            attributes_form.update({attribute_name: {"type": claim["value_type"],"filled_value":None}})
            attributes_form[attribute_name]["cardinality"] = {'min': 0,'max': 'n'}
            attributes_form[attribute_name]["attributes"] = [{'country_code': {'mandatory': True,'value_type': 'string','source': 'user'}}]

        if "value_type" in claim and attribute_name != "nationalities":
            attributes_form.update({attribute_name: {"type": claim["value_type"],"filled_value":None}})

        if "issuer_conditions" in claim and attribute_name != "nationalities":
            if "cardinality" in claim["issuer_conditions"]:
                attributes_form[attribute_name]["cardinality"] = claim["issuer_conditions"]["cardinality"]

    for claim in level2_claims:  
        attributes = {}
        attribute_name = claim["path"][0]
        
        if attribute_name not in attributes_form:
            continue
        
        attributes_form[attribute_name]["type"] = "list"

        level2_name = claim["path"][1]
        attributes[level2_name] = {"mandatory":claim["mandatory"],"value_type":claim["value_type"],"source":claim["source"]} 
        

        if "issuer_conditions" in claim:
            if "cardinality" in claim["issuer_conditions"]:
                attributes["cardinality"] = claim["issuer_conditions"]["cardinality"]
            if "not_used_if" in claim["issuer_conditions"]:
                attributes["not_used_if"] = claim["issuer_conditions"]["not_used_if"]
                    
        if "attributes" in attributes_form[attribute_name]:
            if "cardinality" in attributes_form[attribute_name]["attributes"][0]:
                attributes_form[attribute_name]["attributes"].append(attributes)
            else:
                attributes_form[attribute_name]["attributes"][0].update(attributes)
        else:
            attributes_form[attribute_name]["attributes"] = [attributes]

    for claim in level3_claims: 

        attribute_name = claim["path"][0]

        if attribute_name not in attributes_form:
            continue

        level2_name = claim["path"][1]

        level3_name = claim["path"][2]
        

        attributes = {}

        for attribute in attributes_form[attribute_name]["attributes"]:
            if level2_name in attribute:
                attribute.update({
                    "attribute": level2_name,
                    level3_name : {"mandatory":claim["mandatory"],"value_type":claim["value_type"],"source":claim["source"]}
                })
                attribute.pop(level2_name)

                if "cardinality" in attribute:
                    attribute["cardinality"] = attribute["cardinality"]
                if "not_used_if" in attribute:
                    attribute["not_used_if"] = attribute["not_used_if"]

            elif "attribute" in attribute:
                attribute.update({
                    level3_name : {"mandatory":claim["mandatory"],"value_type":claim["value_type"],"source":claim["source"]}
                })

    return attributes_form

def getAttributesForm2(credentials_requested):
    """
    Function to get attributes needed to populate form depending credentials requested by user

    Keyword arguments:"
    credentials_requested --credentials requested by the user

    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    attributes = {}
    for request in credentials_requested:
        format = credentialsSupported[request]["format"]
        attributes_req = {}

        if format == "mso_mdoc":
            namescapes = getNamespaces(credentialsSupported[request]["claims"])
            for namescape in namescapes:
                attributes_req = getOptionalAttributes(
                    credentialsSupported[request]["claims"],namescape
                )

        elif format == "dc+sd-jwt":
            attributes_req.update(
                getOptionalAttributesSDJWT(credentialsSupported[request]["claims"])
            )

        for attribute in attributes_req:
            if attribute not in attributes:
                attributes.update({attribute: attributes_req[attribute]})

        if "birth_date" in attributes and "birthdate" in attributes:
            attributes.pop("birthdate")

    return attributes


def getOptionalAttributes(claims, namespace):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for claim in claims:
        
        if "overall_issuer_conditions" in claim:
            for key,value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key:value})

        elif claim["mandatory"] == False and claim["path"][0] == namespace:

            attribute_name = claim["path"][1]

            #("\nMisc attribute_name: ", attribute_name)

            if "value_type" in claim:
                attributes_form.update({attribute_name: {"type": claim["value_type"],"filled_value":None}})

            if "issuer_conditions" in claim:
                attributes_form[attribute_name]["type"] = "list"

                if "cardinality" in claim["issuer_conditions"]:
                    attributes_form[attribute_name]["cardinality"] = claim["issuer_conditions"]["cardinality"]
                
                if claim["value_type"] in claim["issuer_conditions"]:
                    #attributes_form[attribute_name]["attributes"] = [attribute_data["issuer_conditions"][attribute_data["value_type"]]]
                    nested_attributes = {}
                    nested_attributes_list = []

                    for key, value in claim["issuer_conditions"][claim["value_type"]].items():

                        if "issuer_conditions" not in value:
                            nested_attributes[key] = value
                        
                        else:
                            
                            attributes_append = {"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}
                           # attributes.append[{"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}]

                            for key2,value2 in value["issuer_conditions"][value["value_type"]].items():
                                attributes_append[key2] = value2

                            if "not_used_if" in value["issuer_conditions"]:
                                attributes_append["not_used_if"] = value["issuer_conditions"]["not_used_if"]

                            nested_attributes_list.append(attributes_append)

                            
                    nested_attributes_list.append(nested_attributes)

                    attributes_form[attribute_name]["attributes"] = nested_attributes_list

    return attributes_form

def getIssuerFilledAttributes(claims, namespace):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for claim in claims:
        if "source" in claim and claim["source"] == "issuer" and claim["path"][0] == namespace:
            attributes_form.update({claim["path"][1]:""})

    return attributes_form

def getIssuerFilledAttributesSDJWT(claims):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for claim in claims:
        if "source" in claim and claim["source"] == "issuer":
            attributes_form.update({claim["path"][0]:""})

    return attributes_form

def generate_unique_id():
    """Function to generate a random uuid"""

    return str(uuid.uuid4())


def validate_image(file):
    """
    Converts input file value into base64url
    """
    try:
        if file.filename == "":
            return False, "No selected file"

        img = Image.open(file)

        width, height = img.size
        if width != 360 or height != 433:
            return False, "Image dimensions are invalid."
    except:
        return False, "Failed to open image."

    return True, None

def getSubClaims(claimLv1, vct):
    subclaims = []
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential_id, credential in credentialsSupported.items():
        if "vct" not in credential or credential["vct"] != vct:
            continue
        else:
            for claim in credential["claims"]:
                if claim["path"][0] != claimLv1:
                    continue
                else:
                    subclaims.append(claim["path"])
    return subclaims


#Searches for credential metadata from doctype and format
def doctype2credential(doctype,format):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential_id, credential in credentialsSupported.items():
        if credential["format"] != format or credential["doctype"] != doctype:
            continue
        else:
            return credential
        
#Searches for credential metadata from doctype and format
def doctype2credentialSDJWT(doctype,format):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential_id, credential in credentialsSupported.items():
        if credential["format"] == format and credential["issuer_config"]["doctype"] == doctype:
            return credential
        else:
            continue
            

def vct2scope(vct: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if "vct" in credentialsSupported[credential] and credentialsSupported[credential]["vct"] == vct:
            return credentialsSupported[credential]["scope"]

def vct2doctype(vct: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if "vct" in credentialsSupported[credential] and credentialsSupported[credential]["vct"] == vct:
            return credentialsSupported[credential]["issuer_config"]["doctype"]

def vct2id(vct):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if "vct" in credentialsSupported[credential] and credentialsSupported[credential]["vct"] == vct:
            return credential

def doctype2vct(doctype: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if "vct" in credentialsSupported[credential] and credentialsSupported[credential]["scope"] == doctype:
            return credentialsSupported[credential]["vct"]

# Generates authorization details from a scope
# First supported credential found of that doctype
def scope2details(scope):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    configuration_ids = []
    if "openid" not in scope:
        configuration_ids.append("openid")

    for item in scope:
        if item != "openid":
            for credential in credentialsSupported:
                if "scope" in credentialsSupported[credential]:
                    if credentialsSupported[credential]["scope"] == item:
                        configuration_ids.append(
                            {"credential_configuration_id": credential}
                        )

    return configuration_ids


def credential_error_resp(error, desc):
    return (
        jsonify(
            {
                "error": error,
                "error_description": desc,
                "c_nonce": secrets.token_urlsafe(16),
                "c_nonce_expires_in": 86400,
            }
        ),
        400,
    )


# Error redirection to the wallet during authentication
def authentication_error_redirect(jws_token, error, error_description):
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        auth_args = authn_method.unpack_token(jws_token)
    except:
        return make_response(
            json.dumps(
                {"error": "invalid_request", "error_description": "Cookie Lost"}
            ),
            400,
        )

    if error is None:
        error = "invalid_request"

    if error_description is None:
        error_description = "invalid_request"

    return redirect(
        url_get(
            auth_args["return_uri"],
            {
                "error": error,
                "error_description": error_description,
            },
        ),
        code=302,
    )


# Error redirection to the wallet during authentication without jws_token
def auth_error_redirect(return_uri, error, error_description=None):

    error_msg = {
        "error": error,
    }

    if error_description is not None:
        error_msg["error_description"] = error_description

    return redirect(
        url_get(return_uri, error_msg),
        code=302,
    )
