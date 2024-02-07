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

from app_config.config_countries import ConfCountries as cfgcountries


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

    if doctype == "org.iso.18013.5.1.mDL":

        data["org.iso.18013.5.1"]["portrait"] = base64.urlsafe_b64decode(
        data["org.iso.18013.5.1"]["portrait"]
        )
        
        #data["org.iso.18013.5.1"]["signature_usual_mark"] = base64.urlsafe_b64decode(
        #data["org.iso.18013.5.1"]["signature_usual_mark"]
        #) 

        if "issuance_date" in data["org.iso.18013.5.1"]:
            issuance_date = data["org.iso.18013.5.1"]["issuance_date"]
        elif "issue_date" in data["org.iso.18013.5.1"]:
            issuance_date = data["org.iso.18013.5.1"]["issue_date"]

        validity = {
            "issuance_date": issuance_date,
            "expiry_date": data["org.iso.18013.5.1"]["expiry_date"],
        }
    if doctype == "eu.europa.ec.eudiw.pid.1":
        validity = {
            "issuance_date": data["eu.europa.ec.eudiw.pid.1"]["issuance_date"],
            "expiry_date": data["eu.europa.ec.eudiw.pid.1"]["expiry_date"],
        }
    if doctype == "eu.europa.ec.eudiw.qeaa.1":
        validity = {
            "issuance_date": data["eu.europa.ec.eudiw.qeaa.1"]["issuance_date"],
            "expiry_date": data["eu.europa.ec.eudiw.qeaa.1"]["expiry_date"],
        }

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

    

    mdoci.new(
        doctype=doctype,
        data=data,
        validity=validity,
        devicekeyinfo=device_publickey,
        cert_path=cfgcountries.supported_countries[country]["pid_mdoc_cert"],
    )

    return base64.urlsafe_b64encode(mdoci.dump()).decode("utf-8")


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
    if doctype == "eu.europa.ec.eudiw.pid.1":
        PID_Claims_data = PID["data"]["claims"]["eu.europa.ec.eudiw.pid.1"]
        iat = DatestringFormatter(PID_Claims_data["issuance_date"])
    if doctype == "eu.europa.ec.eudiw.qeaa.1":
        PID_Claims_data = PID["data"]["claims"]["eu.europa.ec.eudiw.qeaa.1"]
        iat = DatestringFormatter(PID_Claims_data["issuance_date"])


    

    exp = DatestringFormatter(PID_Claims_data["expiry_date"])

    jti = str(uuid4())

    pid_data = PID.get("data", {})
    device_key = PID["device_publickey"]

    claims = {
        "iss": pid_data["evidence"][0]["source"]["organization_name"],
        "jti": jti,
        "iat": iat,
        # "nbf": iat,
        "exp": exp,
        "status": "validation status URL",
        "type": doctype,
    }

    evidence = pid_data["evidence"][0]

    datafinal = {
        "verified_claims": {
            "verification": {
                "trust_framework": "eidas",
                "assurance_level": "high",
            },
            "claims": {},
        }
    }

    disclosure_pid_data = {SDObj(value="evidence"): evidence}

    datafinal["verified_claims"]["verification"].update(disclosure_pid_data)

    JWT_PID_DATA = {}

    for x, value in enumerate(list(pid_data["claims"].keys())):
        namespace = list(pid_data["claims"].keys())[x]
        PID_DATA = pid_data["claims"].get(namespace, {})

        namespacedata = {namespace: {}}

        namespacedata[namespace].update(DATA_sd_jwt(PID_DATA))
        JWT_PID_DATA.update(namespacedata)

    datafinal["verified_claims"]["claims"].update(JWT_PID_DATA)

    # print(datafinal)

    claims.update(datafinal)

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
            "d": base64.b64encode(
                priv_d.to_bytes((priv_d.bit_length() + 7) // 8, "big")
            ).decode("utf-8"),
            "crv": private_key_curve_identifier,
            "x": base64.b64encode(private_key_x).decode("utf-8"),
            "y": base64.b64encode(private_key_y).decode("utf-8"),
        },
        "holder_key": {
            "kty": "EC",
            "crv": public_key_curve_identifier,
            "x": base64.b64encode(public_key_x).decode("utf-8"),
            "y": base64.b64encode(public_key_y).decode("utf-8"),
        },
        "key_size": 256,
        "kty": "EC",
    }

    keys = get_jwk(jwk_kwargs, True, seed)

    ### Produce SD-JWT and SVC for selected example
    SDJWTIssuer.unsafe_randomness = False
    sdjwt_at_issuer = SDJWTIssuer(
        claims,
        keys["issuer_key"],
        keys["holder_key"],
        add_decoy_claims=False,
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

    for i in PID:
        data = {SDObj(value=i): PID[i]}

        Data.update(data)

    return Data


def DatestringFormatter(date):
    date_objectiat = datetime.datetime.strptime(date, "%Y-%m-%d")

    datefinal = int(date_objectiat.timestamp() / (24 * 60 * 60))

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
        )

        y = key.public_numbers().y.to_bytes(
            (key.public_numbers().y.bit_length() + 7) // 8,  # Number of bytes needed
            "big",  # Byte order
        )
    else:
        # Extract the x and y coordinates from the public key
        x = key.private_numbers().public_numbers.x.to_bytes(
            (key.private_numbers().public_numbers.x.bit_length() + 7)
            // 8,  # Number of bytes needed
            "big",  # Byte order
        )

        y = key.private_numbers().public_numbers.y.to_bytes(
            (key.private_numbers().public_numbers.y.bit_length() + 7)
            // 8,  # Number of bytes needed
            "big",  # Byte order
        )

    return (curve_identifier, x, y)
