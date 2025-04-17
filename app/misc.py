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


def getMandatoryAttributes(attributes):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = []
    for attribute in attributes:
        if attributes[attribute]["mandatory"] == True:
            attributes_form.append(attribute)

    """ attributes_form = {}

    for x, value in enumerate(list(attributes.keys())):
        attribute_name = list(attributes.keys())[x]
        attribute_data = attributes.get(attribute_name, {})

        if attribute_data["mandatory"] == True:    
            attributes_form.update({attribute_name}) """

    return attributes_form


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
        namescapes = credentialsSupported[request]["claims"]
        attributes_req = {}

        if format == "mso_mdoc":

            for namescape in namescapes:
                attributes_req = getMandatoryAttributes(
                    credentialsSupported[request]["claims"][namescape]
                )

        elif format == "vc+sd-jwt":
            attributes_req.update(
                getMandatoryAttributes(credentialsSupported[request]["claims"])
            )

        print("\n attributes_req: ", attributes_req)

        for attribute in attributes_req:
            if attribute not in attributes:
                attributes.update({attribute: attributes_req[attribute]})

        if "birth_date" in attributes and "birthdate" in attributes:
            attributes.pop("birthdate")

    return attributes


def getMandatoryAttributes(attributes):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for x, value in enumerate(list(attributes.keys())):
        attribute_name = list(attributes.keys())[x]
        attribute_data = attributes.get(attribute_name, {})

        if attribute_name == "issuer_conditions" and attribute_name not in attributes_form:
            for key,value in attribute_data.items():
                attributes_form.update({key:value})

        elif attribute_data["mandatory"] == True:
            if "value_type" in attribute_data:
                attributes_form.update({attribute_name: {"type": attribute_data["value_type"],"filled_value":None}})

            if "issuer_conditions" in attribute_data:
                attributes_form[attribute_name]["type"] = "list"

                if "cardinality" in attribute_data["issuer_conditions"]:
                    attributes_form[attribute_name]["cardinality"] = attribute_data["issuer_conditions"]["cardinality"]
                
                if attribute_data["value_type"] in attribute_data["issuer_conditions"]:
                    #print("\n[]: ", attribute_data["issuer_conditions"])
                    #print("\nValue Type: ", attribute_data["value_type"])
                    #attributes_form[attribute_name]["attributes"] = [attribute_data["issuer_conditions"][attribute_data["value_type"]]]
                    nested_attributes = {}
                    nested_attributes_list = []

                    #print("[]", type(attribute_data["issuer_conditions"][attribute_data["value_type"]]))

                    for key, value in attribute_data["issuer_conditions"][attribute_data["value_type"]].items():
                        print("\nKey_misc: ", key)
                        #print("\nValue: ", value)

                        if "issuer_conditions" not in value:
                            nested_attributes[key] = value
                        
                        else:
                            
                            attributes_append = {"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}
                           # attributes.append[{"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}]

                            for key2,value2 in value["issuer_conditions"][value["value_type"]].items():
                                attributes_append[key2] = value2

                                print("\nKey2", key2)

                            if "not_used_if" in value["issuer_conditions"]:
                                attributes_append["not_used_if"] = value["issuer_conditions"]["not_used_if"]

                            #print("\nattributes_append: ", attributes_append)
                            nested_attributes_list.append(attributes_append)

                            

                    #print("\nnested_attributes_list: ", nested_attributes_list)
                    #print("\nnested_attributes: ", nested_attributes)
                    nested_attributes_list.append(nested_attributes)

                    attributes_form[attribute_name]["attributes"] = nested_attributes_list

            

            

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
        namescapes = credentialsSupported[request]["claims"]
        attributes_req = {}
        if format == "mso_mdoc":

            for namescape in namescapes:
                attributes_req = getOptionalAttributes(
                    credentialsSupported[request]["claims"][namescape]
                )

        elif format == "vc+sd-jwt":
            attributes_req.update(
                getOptionalAttributes(credentialsSupported[request]["claims"])
            )

        for attribute in attributes_req:
            if attribute not in attributes:
                attributes.update({attribute: attributes_req[attribute]})

        if "birth_date" in attributes and "birthdate" in attributes:
            attributes.pop("birthdate")

    return attributes


def getOptionalAttributes(attributes):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for x, value in enumerate(list(attributes.keys())):
        attribute_name = list(attributes.keys())[x]
        attribute_data = attributes.get(attribute_name, {})

        if attribute_name == "issuer_conditions" and attribute_name not in attributes_form:
            for key,value in attribute_data.items():
                attributes_form.update({key:value})

        elif attribute_data["mandatory"] == False:
            
            if "value_type" in attribute_data:
                attributes_form.update({attribute_name: {"type": attribute_data["value_type"],"filled_value":None}})

            if "issuer_conditions" in attribute_data:
                attributes_form[attribute_name]["type"] = "list"

                if "cardinality" in attribute_data["issuer_conditions"]:
                    attributes_form[attribute_name]["cardinality"] = attribute_data["issuer_conditions"]["cardinality"]
                
                if attribute_data["value_type"] in attribute_data["issuer_conditions"]:
                    #print("\n[]: ", attribute_data["issuer_conditions"])
                    #print("\nValue Type: ", attribute_data["value_type"])
                    #attributes_form[attribute_name]["attributes"] = [attribute_data["issuer_conditions"][attribute_data["value_type"]]]
                    nested_attributes = {}
                    nested_attributes_list = []

                    #print("[]", type(attribute_data["issuer_conditions"][attribute_data["value_type"]]))

                    for key, value in attribute_data["issuer_conditions"][attribute_data["value_type"]].items():
                        print("\nKey: ", key)
                        #print("\nValue: ", value)

                        if "issuer_conditions" not in value:
                            nested_attributes[key] = value
                            print("\nKey,value",key,value)
                        
                        else:
                            
                            attributes_append = {"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}
                           # attributes.append[{"attribute": key, "cardinality":value["issuer_conditions"]["cardinality"]}]

                            for key2,value2 in value["issuer_conditions"][value["value_type"]].items():
                                attributes_append[key2] = value2

                                print("\nKey2", key2)

                            if "not_used_if" in value["issuer_conditions"]:
                                attributes_append["not_used_if"] = value["issuer_conditions"]["not_used_if"]

                            #print("\nattributes_append: ", attributes_append)
                            nested_attributes_list.append(attributes_append)

                            

                    #print("\nnested_attributes_list: ", nested_attributes_list)
                    #print("\nnested_attributes: ", nested_attributes)
                    nested_attributes_list.append(nested_attributes)

                    attributes_form[attribute_name]["attributes"] = nested_attributes_list

    return attributes_form

def getIssuerFilledAttributes(attributes):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for x, value in enumerate(list(attributes.keys())):
        attribute_name = list(attributes.keys())[x]
        attribute_data = attributes.get(attribute_name, {})

        if "source" in attribute_data and attribute_data["source"] == "issuer":
            attributes_form.update({attribute_name: ""})

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

def vct2scope(vct: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if "vct" in credentialsSupported[credential] and credentialsSupported[credential]["vct"] == vct:
            return credentialsSupported[credential]["scope"]

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
                if "doctype" in credentialsSupported[credential]:
                    if credentialsSupported[credential]["doctype"] == item:
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
