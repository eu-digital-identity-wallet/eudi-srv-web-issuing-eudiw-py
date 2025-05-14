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
This validate_vp_token.py file contains functions related to validate VP Token.

"""
import re
import cryptography
from pycose.messages import Sign1Message
from pycose.headers import X5chain
import base64
from pycose.messages import Sign1Message
import cbor2
from pycose.keys import EC2Key

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography import x509
import datetime
import hashlib
from . import trusted_CAs
from .app_config.config_service import ConfService as cfgservice


def validate_vp_token(response_json, credentials_requested):
    """
    Validate VP token, checking document and presentation_submission attributes
    """

    auth_request_values = {
        "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "id": "eu.europa.ec.eudi.pid.1",
        "input_descriptor": [
            "family_name",
            "given_name",
            "birth_date",
            "age_over_18",
            "issuing_authority",
            "issuing_country",
        ],
    }

    

    if (
        response_json["presentation_submission"]["definition_id"]
        != auth_request_values["definition_id"]
    ):

        return True, "Definition id received is different from the requested."

    elif response_json["presentation_submission"]["descriptor_map"][0]["path"] == "$":

        pos = 0

    else:
        matcher = re.search(
            r"\d+",
            response_json["presentation_submission"]["descriptor_map"][0]["path"],
        )
        if matcher:
            pos = int(matcher.group())
        else:
            pos = -1

    if pos == -1:

        return True, "The path value from presentation_submission is not valid."

    else:

        mdoc = response_json["vp_token"][0]
        mdoc_ver = None

        try:
            mdoc_ver = base64.urlsafe_b64decode(mdoc)

        except:
            mdoc_ver = base64.urlsafe_b64decode(mdoc + "==")

        mdoc_cbor = cbor2.decoder.loads(mdoc_ver)

        if mdoc_cbor["status"] != 0:

            return True, "Status invalid:" + str(mdoc_cbor["status"])

        error, errorMsg = validate_certificate(mdoc_cbor["documents"][pos])

        if error == False:

            return True, errorMsg

        # Validate values received are the same values requested
        namespaces = mdoc_cbor["documents"][pos]["issuerSigned"]["nameSpaces"]

        attributes_requested = []

        for id in credentials_requested:
            for doctype in cfgservice.dynamic_issuing[id]:
                for namespace in cfgservice.dynamic_issuing[id][doctype]:
                    for attribute in cfgservice.dynamic_issuing[id][doctype][namespace]:
                        attributes_requested.append(attribute)
        
        #attributes_requested = auth_request_values["input_descriptor"]
        attributes_received = []

        for n in namespaces.keys():
            l = []
            for e in namespaces[n]:  # e is a CBORTag
                val = cbor2.decoder.loads(e.value)
                id = val["elementIdentifier"]
                attributes_received.append(id)

        if len(attributes_received) != len(attributes_requested):

            if set(attributes_received).issubset(set(attributes_requested)):

                # missing_attributes = list(set(attributes_requested) - set(attributes_received))
                return True, "Missing attributes"  # missing_attributes
            else:
                return True, "There are values that weren't requested."

        if all(x in attributes_requested for x in attributes_received) and all(
            x in attributes_received for x in attributes_requested
        ):

            return False, ""


def validate_certificate(mdoc):
    """
    Function to validate certificate in MSO Header, the siganture and digests

    """

    certificate_data = mdoc["issuerSigned"]["issuerAuth"]

    tagged_data = cbor2.CBORTag(18, certificate_data)
    message = Sign1Message.decode(cbor2.dumps(tagged_data))

    payload = message.payload
    protected = message.phdr
    unprotected = message.uhdr
    signature = message.signature

    # Certificate
    certificate = x509.load_der_x509_certificate(
        unprotected[X5chain], default_backend()
    )

    # Validate Certificate (MSO Header)
    if certificate.issuer not in trusted_CAs:

        return False, "Certificate wasn't emitted by a Trusted CA "

    else:

        public_key_CA = trusted_CAs[certificate.issuer]["public_key"]

        x = (
            certificate.public_key()
            .public_numbers()
            .x.to_bytes(
                (certificate.public_key().public_numbers().x.bit_length() + 7)
                // 8,  # Number of bytes needed
                "big",  # Byte order
            )
        )

        y = (
            certificate.public_key()
            .public_numbers()
            .y.to_bytes(
                (certificate.public_key().public_numbers().y.bit_length() + 7)
                // 8,  # Number of bytes needed
                "big",  # Byte order
            )
        )

        ec_key = EC2Key(x=x, y=y, crv=1)

        try:
            public_key_CA.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        except:
            return False, "Certificate wasn't emitted by a Trusted CA "

        message.key = ec_key

        not_valid_after = trusted_CAs[certificate.issuer]["not_valid_after"].replace(
            tzinfo=datetime.timezone.utc
        )
        not_valid_before = trusted_CAs[certificate.issuer]["not_valid_before"].replace(
            tzinfo=datetime.timezone.utc
        )
        now = datetime.datetime.now(datetime.timezone.utc)

        if now < not_valid_before or not_valid_after < now:

            return False, "Certificate not valid"

        try:
            message.verify_signature()

        except Exception as e:
            return False, "Signature not valid"

    # Validate payload
    payload_decoded = cbor2.decoder.loads(cbor2.decoder.loads(payload).value)

    namespaces = mdoc["issuerSigned"]["nameSpaces"]

    doctype_MSO = payload_decoded["docType"]

    if doctype_MSO != mdoc["docType"]:
        return False, "Doctype from MSO not equal to doctype in document"

    algorithm = payload_decoded["digestAlgorithm"]

    # Validate Digests
    for n in namespaces.keys():
        i = 0
        for e in namespaces[n]:
            new_cbor_tag = cbor2.CBORTag(e.tag, e.value)

            if algorithm == "SHA-256":
                calculated_digest = hashlib.sha256(cbor2.dumps(new_cbor_tag)).digest()

            elif algorithm == "SHA-512":
                calculated_digest = hashlib.sha512(cbor2.dumps(new_cbor_tag)).digest()

            for digests in payload_decoded["valueDigests"][n].values():

                if calculated_digest == digests:
                    i += 1
                    break

        if i != len(namespaces[n]):
            return (
                False,
                "Missing digests or there aren't enough digests that correspond to the values in document",
            )

    # Validity Info
    ValidityInfo = payload_decoded["validityInfo"]

    signed = ValidityInfo["signed"]
    validFrom = ValidityInfo["validFrom"]
    validUntil = ValidityInfo["validUntil"]

    if signed < not_valid_before or not_valid_after < signed:
        return False, "Signed date isn't within validity period of the certificate"

    now = datetime.datetime.now(datetime.timezone.utc)

    if now < validFrom or validUntil < now:

        return False, "Period defined in ValidityInfo is invalid"

    return True, ""
