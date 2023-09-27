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

This config_service.py contains configuration data for the PID Issuer Web service. 

NOTE: You should only change it if you understand what you're doing.
"""

class ConfService:
    # ------------------------------------------------------------------------------------------------
    # PID issuer service URL
    service_url = "https://preprod.issuer.eudiw.dev/" 

    # ------------------------------------------------------------------------------------------------
    # eIDAS Node base href (used in lightrequest)
    eidasnode_url = "https://preprod.issuer.eudiw.dev/EidasNode/"

    # eIDAS secret connector request 
    # Defined in eIDAS node service file specificConnector/specificCommunicationDefinitionConnector.xml, 
    #                                   entry key="lightToken.connector.request.secret"
    eidasnode_lightToken_secret = "scaN+LhrJL+f9c1pULJ8MU5RQN+igrDoZZMUTw5MboY="

    # eIDAS node connector endpoint (for lightrequest)
    eidasnode_lightToken_connectorEndpoint = 'https://preprod.issuer.eudiw.dev/EidasNode/SpecificConnectorRequest'

    # eIDAS node PID attributes
    eidasnode_pid_attributes = ['CurrentFamilyName', 'CurrentGivenName', 'DateOfBirth', 'PersonIdentifier']


    # ------------------------------------------------------------------------------------------------
    # PID namespace
    pid_namespace = 'eu.europa.ec.eudiw.pid.1'

    # PID doctype
    pid_doctype = 'eu.europa.ec.eudiw.pid.1'

    # PID validity in days
    pid_validity = 7

    # PID issuing Authority
    pid_issuing_authority = 'Test PID issuer'

    # PID Organization ID 
    pid_organization_id = "EUDI Wallet Reference Implementation"

    # ------------------------------------------------------------------------------------------------
    # current version
    current_version= "0.3"

    # route /pid/getpid response fields per API version
    getpid_response_field = {
        "0.1": ['mdoc', 'mdoc_nonce', 'mdoc_authTag', 'mdoc_ciphertextPubKey', 'error', 'error_str'], # doesn't cipher the returned mdoc
        "0.2": ['mdoc', 'mdoc_nonce', 'mdoc_authTag', 'mdoc_ciphertextPubKey', 'error', 'error_str'], # doesn't cipher the returned mdoc
        "0.3": ['mdoc', 'nonce', 'authTag', 'ciphertextPubKey','sd_jwt', 'error', 'error_str']
    }

    # Supported certificate algorithms and curves
    cert_algo_list = {
        "ecdsa-with-SHA256": ['secp256r1'] 
    }


    # ------------------------------------------------------------------------------------------------
    # Error list (error number, error string)
    error_list = {    
        '-1': 'Error undefined. Please contact PID Provider backend support.',
        '0': 'No error.',
        '11': 'Query with no returnURL.',
        '12': 'Query with no version.',
        '13': 'Version is not supported.',
        '14': 'URL not well formed.',
        '15': 'Query with no device_publickey',
        '16': 'The device_publickey is not in the correct format',
        '101': 'Missing mandatory pid/getpid fields.',
        '102': 'Country is not supported.',
        '103': 'Certificate not correctly encoded.',
        '104': 'Certificate algorithm or curve not supported.',
        '301': 'Missing mandatory lightrequest eidasnode fields.',
        '302': 'Missing mandatory lightresponse eidasnode fields.',
        '303': 'Error obtaining attributes.',
        '304': 'PID attribute(s) missing.',
        '305': 'Certificate not available.',
        '401': 'Missing mandatory formatter fields.',
        '501': 'Missing mandatory IdP fields',
    }