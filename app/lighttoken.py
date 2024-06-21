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


This lighttoken.py file contains the eIDAS-node lightToken auxiliary functions.
"""
from pyignite import Client
import requests
import datetime
import base64
import hashlib
import uuid
import xml.etree.ElementTree as ET

from app_config.config_service import ConfService as cfgserv
from app_config.config_secrets import eidasnode_lightToken_secret


def create_request(country, loa):
    """Create eIDAS node lightRequest and connects to the country's eIDAS node (must be defined in the local eIDAS node how to connect to the country's eIDAS node).

    Keyword arguments:
    + country -- eIDAS node country to connect.
    + loa -- level of assurance of the requested response from the country eIDAS node.

    Return: Returns the response to the specific.connector.response.receiver as defined in the eidas.xml file of the local eIDAS node
    """
    id = str(uuid.uuid4())
    lightRequest = (
        """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><lightRequest xmlns="http://cef.eidas.eu/LightRequest">
        <citizenCountryCode>"""
        + country
        + """</citizenCountryCode>
        <id>"""
        + id
        + """</id>
        <issuer>Pid Issuer lightconnector</issuer>
        <levelOfAssurance>"""
        + loa
        + """</levelOfAssurance>
        <nameIdFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</nameIdFormat>
        <providerName>PID Provider</providerName>
        <spType>public</spType>
        <requestedAttributes>
           <attribute>
                <definition>http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName</definition>
            </attribute>
            <attribute>
                <definition>http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName</definition>
            </attribute>
            <attribute>
                <definition>http://eidas.europa.eu/attributes/naturalperson/DateOfBirth</definition>
            </attribute>
            <attribute>
                <definition>http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier</definition>
            </attribute>
        </requestedAttributes>
    </lightRequest>"""
    )

    # Connect to cache
    client = Client()
    client.connect("127.0.0.1", 10900)
    specificNodeConnectorRequestCache = client.get_cache(
        "specificNodeConnectorRequestCache"
    )
    # Put Light Request in cache
    specificNodeConnectorRequestCache.put(id, lightRequest)

    issuer = "specificCommunicationDefinitionConnectorRequest"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %f")[:-3]
    timestamp = str(now)

    # calculation of digest id|issuer|timestamp|secret
    bltForDigest = (
        id + "|" + issuer + "|" + timestamp + "|" + eidasnode_lightToken_secret
    )
    digest = hashlib.sha256(bltForDigest.encode())
    digestBase64 = base64.b64encode(digest.digest())

    # BLT to be sent: issuer|id|timestamp|digest
    blt = issuer + "|" + id + "|" + timestamp + "|" + digestBase64.decode("utf-8")
    # BLT in Base64
    bltBase64 = base64.b64encode(blt.encode())

    payload = {"token": bltBase64}
    response = requests.post(cfgserv.eidasnode_lightToken_connectorEndpoint, payload)

    return "<base href=" + cfgserv.eidasnode_url + ">\n" + response.text


def handle_response(token):
    """Handles the response to /eidasnode/lightrequest sent by the eIDAS node. Connect to LightToken client to retrieve the attributes that the end-user agreed to share/disclose.

    Keyword arguments:
    + token -- token sent by eIDAS node.

    Return: (boolean, l)
    + If failure in obtaining the list of attributes that the end-user agreed to share/disclose, returns (False, error message)
    + Otherwise, returns (True, attributes dictionary)
    """
    blt = base64.b64decode(token)
    bltsplit = blt.split(b"|")
    bltid = bltsplit[1].decode("utf-8")

    # Connect to cache
    client = Client()
    client.connect("127.0.0.1", 10900)
    specificResponseCache = client.get_cache("nodeSpecificConnectorResponseCache")
    cacheXML = specificResponseCache.get(bltid)
    root = ET.fromstring(cacheXML)

    # Find the status elements
    namespace = {"ns": "http://cef.eidas.eu/LightResponse"}
    status_elements = root.findall(".//ns:status", namespace)

    # Retrieve status information
    for status in status_elements:
        failure = status.find("ns:failure", namespace).text
        status_message = status.find("ns:statusMessage", namespace).text

    if failure == "true":
        return False, status_message

    # Find attribute elements
    attribute_elements = root.findall(".//ns:attribute", namespace)

    # Fill attributes dictionary
    attributes = {}
    for attribute in attribute_elements:
        definition = attribute.find("ns:definition", namespace).text
        value_elements = attribute.findall("ns:value", namespace)
        attributes[definition.split("/")[-1]] = value_elements[0].text

    return True, attributes
