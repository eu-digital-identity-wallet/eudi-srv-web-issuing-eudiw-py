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


This formatter_func.py file contains formatter related auxiliary functions.
"""
import base64
import cbor2
from cryptography.hazmat.primitives import serialization
from pymdoccbor.mdoc.issuer import MdocCborIssuer
import datetime
import hashlib
import requests
from sd_jwt.common import SDObj
from jsonschema import ValidationError, validate
from sd_jwt import __version__
from sd_jwt.utils.demo_utils import (
    get_jwk,
    load_yaml_settings,
)
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.holder import SDJWTHolder
from sd_jwt.verifier import SDJWTVerifier
from sd_jwt.utils.yaml_specification import load_yaml_specification
from uuid import uuid4
import jwt

from misc import doctype2vct, urlsafe_b64encode_nopad
from app_config.config_countries import ConfCountries as cfgcountries
from app_config.config_service import ConfService as cfgservice
from app_config.config_secrets import revocation_api_key


def mdocFormatter(data, doctype, country, device_publickey):
    """Construct and sign the mdoc with the country private key

    Keyword arguments:
    + data -- doctype data "dictionary" with one or more "namespace": {"namespace data and fields"} tuples
    + doctype -- mdoc doctype
    + country -- Issuing country
    + device_publickey -- Holder's device public key

    Return: Returns the base64 urlsafe mdoc
    """
    # Load the private key
    with open(
        cfgcountries.supported_countries[country]["pid_mdoc_privkey"], "rb"
    ) as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=cfgcountries.supported_countries[country][
                "pid_mdoc_privkey_passwd"
            ],
        )

    # Extract the key parameters
    priv_d = private_key.private_numbers().private_value
    
    issuance_date = datetime.datetime.today()
    expiry_date = issuance_date + datetime.timedelta(days=cfgservice.config_doctype[doctype]["validity"])

    validity = {
        "issuance_date": issuance_date.strftime('%Y-%m-%d'),
        "expiry_date": expiry_date.strftime('%Y-%m-%d')
    }
    
    """ if doctype == "org.iso.18013.5.1.mDL":

        # data["org.iso.18013.5.1"]["signature_usual_mark"] = base64.urlsafe_b64decode(
        # data["org.iso.18013.5.1"]["signature_usual_mark"]
        # )

        if "issuance_date" in data["org.iso.18013.5.1"]:
            issuance_date = data["org.iso.18013.5.1"]["issuance_date"]
        elif "issue_date" in data["org.iso.18013.5.1"]:
            issuance_date = data["org.iso.18013.5.1"]["issue_date"]

        validity = {
            "issuance_date": issuance_date,
            "expiry_date": data["org.iso.18013.5.1"]["expiry_date"],
        }
    elif doctype == "eu.europa.ec.eudi.pid.1":
        validity = {
            "issuance_date": data["eu.europa.ec.eudi.pid.1"]["issuance_date"],
            "expiry_date": data["eu.europa.ec.eudi.pid.1"]["expiry_date"],
        }
    elif doctype == "eu.europa.ec.eudiw.qeaa.1":
        validity = {
            "issuance_date": data["eu.europa.ec.eudiw.qeaa.1"]["issuance_date"],
            "expiry_date": data["eu.europa.ec.eudiw.qeaa.1"]["expiry_date"],
        }
    else:
        first_key = list(data.keys())[0]
        validity = {
            "issuance_date": data[first_key]["issuance_date"],
            "expiry_date": data[first_key]["expiry_date"],
        } """
    
    namespace = cfgservice.config_doctype[doctype]["namespace"]

    if "portrait" in data[namespace]:
        data[namespace]["portrait"] = base64.urlsafe_b64decode(
            data[namespace]["portrait"]
        )

    if "user_pseudonym" in data[namespace]:
        data[doctype]["user_pseudonym"] = data[doctype]["user_pseudonym"].encode('utf-8')

    # Construct the COSE private key
    cose_pkey = {
        "KTY": "EC2",
        "CURVE": "P_256",
        "ALG": "ES256",
        "D": priv_d.to_bytes((priv_d.bit_length() + 7) // 8, "big"),
        "KID": b"mdocIssuer",
    }

    # Construct and sign the mdoc
    mdoci = MdocCborIssuer(private_key=cose_pkey, alg="ES256")

    revocation_json = None
    if revocation_api_key:
        payload = "doctype=" + doctype + "&country=" + country + "&expiry_date=" + validity["expiry_date"]
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Api-Key': revocation_api_key
        }

        response = requests.post(cfgservice.revocation_service_url, headers=headers, data=payload)

        if response.status_code == 200:
            revocation_json = response.json()

    mdoci.new(
        doctype=doctype,
        data=data,
        validity=validity,
        devicekeyinfo=device_publickey,
        cert_path=cfgcountries.supported_countries[country]["pid_mdoc_cert"],
        revocation = revocation_json
                    
          )

    return urlsafe_b64encode_nopad(mdoci.dump()) #base64.urlsafe_b64encode(mdoci.dump()).decode("utf-8")


def cbor2elems(mdoc):
    """Receives the base64 encoded mdoc and returns a dict with the (element, value) contained in the namespaces of the mdoc

    Keyword arguments:
    + mdoc -- base64 encoded mdoc

    Return: Returns a dict with (element, values) contained in the namespaces of the mdoc. E.g. {'ns1': [('e1', 'v1'), ('e2', 'v2')], 'ns2': [('e3', 'v3')]}
    """
    d = {}
    namespaces = cbor2.decoder.loads(base64.urlsafe_b64decode(mdoc))["documents"][0][
        "issuerSigned"
    ]["nameSpaces"]
    for n in namespaces.keys():
        l = []
        for e in namespaces[n]:  # e is a CBORTag
            val = cbor2.decoder.loads(e.value)
            id = val["elementIdentifier"]
            if (
                id == "birth_date"
                or id == "expiry_date"
                or id == "issuance_date"
                or id == "issue_date"
            ):  # value of birthdate is a CBORTag
                l.append((id, val["elementValue"].value))
            # if id=='portrait':
            #     if is_base64_Portrait(val['elementValue'])==False:
            #         l.append(('Portrait', val['elementValue']))
            #     else:
            #         l.append((id, val['elementValue']))
            else:
                l.append((id, val["elementValue"]))
        d[n] = l
    return d


def sdjwtFormatter(PID, country):
    """Construct sd-jwt with the country private key

    Keyword arguments:
    + PID - doctype data "dictionary" with one or more "namespace": {"namespace data and fields"} tuples
    + country -- Issuing country

    Return: Returns the sd-jwt
    """
    hash_object = hashlib.sha256()

    seed = int(hash_object.hexdigest(), 16)
    doctype = PID["doctype"]
    if doctype == "org.iso.18013.5.1.mDL":
        PID_Claims_data = PID["data"]["claims"]["org.iso.18013.5.1"]
        iat = DatestringFormatter(PID_Claims_data["issue_date"])
        PID_Claims_data.pop("issue_date")
    else :
        PID_Claims_data = PID["data"]["claims"][doctype]
        iat = DatestringFormatter(PID_Claims_data["issuance_date"])
        PID_Claims_data.pop("issuance_date")

    exp = DatestringFormatter(PID_Claims_data["expiry_date"])

    validity = PID_Claims_data["expiry_date"]

    PID_Claims_data.pop("expiry_date")

    #jti = str(uuid4())

    pid_data = PID.get("data", {})
    device_key = PID["device_publickey"]

    vct = doctype2vct(doctype)

    revocation_json = None

    if revocation_api_key:
        payload = "doctype=" + doctype + "&country=" + country + "&expiry_date=" + validity
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Api-Key': revocation_api_key
        }

        response = requests.post(cfgservice.revocation_service_url, headers=headers, data=payload)

        if response.status_code == 200:
            revocation_json = response.json()
            

    claims = {
        "iss": cfgservice.service_url[:-1],
        #"iss": "https://issuer.eudiw.dev",
        #"jti": jti,
        "iat": iat,
        # "nbf": iat,
        "exp": exp,
        #"status": "validation status URL",
        #"vct":"urn:"+ doctype,
        "vct":vct,
    }

    if revocation_json:
        claims.update({"status":revocation_json})

    datafinal = {}

    JWT_PID_DATA = {}

    for x, value in enumerate(list(pid_data["claims"].keys())):
        namespace = list(pid_data["claims"].keys())[x]
        PID_DATA = pid_data["claims"].get(namespace, {})
        JWT_PID_DATA.update(DATA_sd_jwt(PID_DATA))

    datafinal.update(JWT_PID_DATA)

    claims.update(datafinal)

    with open(
        cfgcountries.supported_countries[country]["pid_mdoc_cert"], "rb"
    ) as certificate:
         certificate_data=certificate.read()
    
    certificate_base64=base64.b64encode(certificate_data).decode("utf-8")
    x5c={
        "x5c":[]
    }
    x5c["x5c"].append(certificate_base64)

    with open(
        cfgcountries.supported_countries[country]["pid_mdoc_privkey"], "rb"
    ) as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=cfgcountries.supported_countries[country][
                "pid_mdoc_privkey_passwd"
            ],
        )

    priv_d = private_key.private_numbers().private_value

    (private_key_curve_identifier, private_key_x, private_key_y) = KeyData(
        private_key, "private"
    )

    device_key_bytes = base64.urlsafe_b64decode(device_key.encode("utf-8"))
    public_key = serialization.load_pem_public_key(device_key_bytes)

    (public_key_curve_identifier, public_key_x, public_key_y) = KeyData(
        public_key, "public"
    )

    jwk_kwargs = {
        "issuer_key": {
            "kty": "EC",
            "d": jwt.utils.base64url_encode(
                priv_d.to_bytes((priv_d.bit_length() + 7) // 8, "big")
            ).decode("utf-8"),
            "crv": private_key_curve_identifier,
            "x": jwt.utils.base64url_encode(private_key_x).decode("utf-8"),
            "y": jwt.utils.base64url_encode(private_key_y).decode("utf-8"),
        },
        "holder_key": {
            "kty": "EC",
            "crv": public_key_curve_identifier,
            "x": jwt.utils.base64url_encode(public_key_x).decode("utf-8"),
            "y": jwt.utils.base64url_encode(public_key_y).decode("utf-8"),
        },
        "key_size": 256,
        "kty": "EC",
    }

    keys = get_jwk(jwk_kwargs, True, seed)

    ### Produce SD-JWT and SVC for selected example
    SDJWTIssuer.unsafe_randomness = False
    SDJWTIssuer.SD_JWT_HEADER="vc+sd-jwt"
    sdjwt_at_issuer = SDJWTIssuer(
        claims,
        keys["issuer_key"],
        keys["holder_key"],
        add_decoy_claims=False,
        extra_header_parameters=x5c
    )

    # sdjwt_at_holder = SDJWTHolder(sdjwt_at_issuer.sd_jwt_issuance)
    # sdjwt_at_holder.create_presentation(
    # example["holder_disclosed_claims"],
    # settings["key_binding_nonce"] if example.get("key_binding", False) else None,
    # settings["identifiers"]["verifier"] if example.get("key_binding", False) else None,
    # demo_keys["holder_key"] if example.get("key_binding", False) else None,
    # )

    return sdjwt_at_issuer.sd_jwt_issuance


def DATA_sd_jwt(PID):
    Data = {}
    age_equal_or_over={}
    place_of_birth={}
    address_dict={}
    for i in PID:
        if i in cfgservice.Registered_claims:

            r = cfgservice.Registered_claims.get(i)

            if "age_equal_or_over" in r:
                subAge=r.split(".")
                age_equal_or_over.update({subAge[1]:PID[i]})

            elif "place_of_birth" in r:
                place_Birth=r.split(".")
                place_of_birth.update({place_Birth[1]:PID[i]})

            elif "address" in r:
                address=r.split(".")
                address_dict.update({address[1]:PID[i]})

            else:
                data = {SDObj(value=r): PID[i]}
                Data.update(data)
        else:

            data = {SDObj(value=i): PID[i]}
            Data.update(data)

    if age_equal_or_over:
            data = {SDObj(value="age_equal_or_over"): recursive(age_equal_or_over)}
            Data.update(data)
    if place_of_birth:
            data = {SDObj(value="place_of_birth"): recursive(place_of_birth)}
            Data.update(data)
    if address_dict:
            data = {SDObj(value="address"): recursive(address_dict)}
            Data.update(data)        
            
    return Data


def recursive(dict):
    temp_dic={}
    for f in dict:
        recursive = {SDObj(value=f): dict[f]}
        temp_dic.update(recursive)
    return temp_dic 

def DatestringFormatter(date):
    date_objectiat = datetime.datetime.strptime(date, "%Y-%m-%d")

    datefinal = int(date_objectiat.timestamp())

    return datefinal


def KeyData(key, type):
    curve_map = {
        "secp256r1": "P-256",  # NIST P-256
        "secp384r1": "P-384",  # NIST P-384
        "secp521r1": "P-521",  # NIST P-521
    }

    key_curve_name = key.curve.name

    curve_identifier = curve_map.get(key_curve_name)

    if type == "public":
        # Extract the x and y coordinates from the public key
        x = key.public_numbers().x.to_bytes(
            (key.public_numbers().x.bit_length() + 7) // 8,  # Number of bytes needed
            "big",  # Byte order
        ).rjust(32, b'\x00')

        y = key.public_numbers().y.to_bytes(
            (key.public_numbers().y.bit_length() + 7) // 8,  # Number of bytes needed
            "big",  # Byte order
        ).rjust(32, b'\x00')
    else:
        # Extract the x and y coordinates from the public key
        x = key.private_numbers().public_numbers.x.to_bytes(
            (key.private_numbers().public_numbers.x.bit_length() + 7)
            // 8,  # Number of bytes needed
            "big",  # Byte order
        ).rjust(32, b'\x00')

        y = key.private_numbers().public_numbers.y.to_bytes(
            (key.private_numbers().public_numbers.y.bit_length() + 7)
            // 8,  # Number of bytes needed
            "big",  # Byte order
        ).rjust(32, b'\x00')

    return (curve_identifier, x, y)
