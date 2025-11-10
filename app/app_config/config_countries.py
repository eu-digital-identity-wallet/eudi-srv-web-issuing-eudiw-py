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
The PID Issuer Web service is a component of the PID Provider backend.
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This config_countries.py contains configuration data related to the countries supported by the PID Issuer.
This config_countries.py contains configuration data related to the countries supported by the PID Issuer.

NOTE: You should only change it if you understand what you're doing.
"""

import os
from .config_service import ConfService as cfgserv

EIDAS_LOA_HIGH = "http://eidas.europa.eu/LoA/high"

eidas_node_connector_url = os.getenv(
    "EIDAS_NODE_CONNECTOR_URL",
    "test",
)

eidas_node_client_id = os.getenv(
    "EIDAS_NODE_CLIENT_ID",
    "test",
)

eidas_node_client_secret = os.getenv(
    "EIDAS_NODE_CLIENT_SECRET",
    "test",
)

pt_client_id = os.getenv(
    "PT_CLIENT_ID",
    "test",
)

pt_client_secret = os.getenv(
    "PT_CLIENT_SECRET",
    "test",
)

ee_client_id = os.getenv(
    "EE_CLIENT_ID",
    "test",
)

ee_auth_header = os.getenv(
    "EE_BASIC_AUTHORIZATION_HEADER",
    "test",
)

ee_redirect_uri = os.getenv(
    "EE_REDIRECT_URI",
    "test",
)


class ConfCountries:
    urlReturnEE = "https://pprpid.provider.eudiw.projj.eu/tara/redirect"

    formCountry = "FC"
    # supported countries
    supported_countries = {
        "EU": {
            "name": "nodeEU",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=EU",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_EU.pem",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_EU.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_EU.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes,
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_EU_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "eu.europa.ec.eudi.pid_mdoc_deferred",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
        formCountry: {
            "name": "FormEU",
            "pid_url": cfgserv.service_url + "pid/form",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_UT.pem",
            # "pid_mdoc_privkey": cfgserv.privKey_path + "hackathon-DS-0002_UT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_UT.pem',
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_UT.pem",
            # "pid_mdoc_privkey": cfgserv.privKey_path + "hackathon-DS-0002_UT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_UT.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_UT_cert.der",
            # "pid_mdoc_cert": cfgserv.trusted_CAs_path + "hackathon-DS-0002_UT_cert.der",
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_UT_cert.der",
            # "pid_mdoc_cert": cfgserv.trusted_CAs_path + "hackathon-DS-0002_UT_cert.der",
            "un_distinguishing_sign": "FC",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "eu.europa.ec.eudi.mdl_mdoc",
                "eu.europa.ec.eudi.over18_mdoc",
                "eu.europa.ec.eudi.loyalty_mdoc",
                "eu.europa.ec.eudi.photoid",
                "eu.europa.ec.eudi.por_mdoc",
                "eu.europa.ec.eudi.iban_mdoc",
                "eu.europa.ec.eudi.hiid_mdoc",
                "eu.europa.ec.eudi.tax_mdoc",
                "eu.europa.ec.eudi.msisdn_mdoc",
                "eu.europa.ec.eudi.pda1_mdoc",
                "eu.europa.ec.eudi.tax_sd_jwt_vc",
                "eu.europa.ec.eudi.por_sd_jwt_vc",
                "eu.europa.ec.eudi.msisdn_sd_jwt_vc",
                "eu.europa.ec.eudi.hiid_sd_jwt_vc",
                "eu.europa.ec.eudi.iban_sd_jwt_vc",
                "eu.europa.ec.eudi.ehic_mdoc",
                "eu.europa.ec.eudi.cor_mdoc",
                "eu.europa.ec.eudi.ehic_sd_jwt_vc",
                "eu.europa.ec.eudi.pda1_sd_jwt_vc",
                "org.iso.18013.5.1.reservation_mdoc",
                "eu.europa.ec.eudi.seafarer_mdoc",
                "eu.europa.ec.eudi.diploma_vc_sd_jwt",
                "eu.europa.ec.eudi.tax_residency_vc_sd_jwt",
                "eu.europa.ec.eudi.employee_mdoc",
                "eu.europa.ec.eudi.pid_mdoc_deferred",
            ],
        },
        "PT": {
            "name": "Portugal",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_PT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_PT.pem',
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_PT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_PT.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_PT_cert.der",
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_PT_cert.der",
            "un_distinguishing_sign": "P",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "eu.europa.ec.eudi.mdl_mdoc",
                "eu.europa.ec.eudi.over18_mdoc",
                "eu.europa.ec.eudi.pid_mdoc_deferred",
            ],
            "connection_type": "oauth",
            "custom_modifiers": {
                "http://interop.gov.pt/MDC/Cidadao/DataNascimento": "birth_date",
                "http://interop.gov.pt/MDC/Cidadao/NomeApelido": "family_name",
                "http://interop.gov.pt/MDC/Cidadao/NomeProprio": "given_name",
            },
            "oauth_auth": {
                "base_url": "https://country-connector.ageverification.dev",
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": pt_client_id,
                "client_secret": pt_client_secret,
            },
        },
        "EE": {
            "name": "Estonia",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_EE.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_EE.pem',
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_EE.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_EE.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_EE_cert.der",
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_EE_cert.der",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "connection_type": "openid",
            "oidc_auth": {
                "base_url": "https://tara-test.ria.ee",
                "redirect_uri": urlReturnEE,
                "scope": "openid",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": ee_client_id,
            },
            "attribute_request": {
                "header": {"Host": "tara-test.ria.ee"},
                "custom_modifiers": {
                    "birth_date": "date_of_birth",
                },
            },
            "oidc_redirect": {
                "headers": {
                    "Host": "tara-test.ria.ee",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": ee_auth_header,
                },
                "grant_type": "authorization_code",
                "redirect_uri": ee_redirect_uri,
            },
        },
        "CZ": {
            "name": "Czechia",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=CZ",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_CZ.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_CZ.pem',
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_CZ.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0002_CZ.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_CZ_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
        "NL": {
            "name": "Netherland",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=NL",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_NL.pem",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_NL.pem",
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_NL_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
        "LU": {
            "name": "Luxembourg",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=LU",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_LU.pem",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0002_LU.pem",
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0002_LU_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
    }


class ConfFrontend:
    registered_frontends = {
        cfgserv.default_frontend: {
            "url": os.getenv("DEFAULT_FRONTEND_URL", "https://ec.dev.issuer.eudiw.dev")
        }
    }
