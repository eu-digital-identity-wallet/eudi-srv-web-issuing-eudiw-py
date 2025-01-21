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

This config_countries.py contains configuration data related to the countries supported by the PID Issuer. 

NOTE: You should only change it if you understand what you're doing.
"""

from .config_service import ConfService as cfgserv


class ConfCountries:
    urlReturnEE = "https://pprpid.provider.eudiw.projj.eu/tara/redirect"

    formCountry = "FC"
    # supported countries
    supported_countries = {
        "EU": {
            "name": "nodeEU",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=EU",
            "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/PID-DS-0001_EU.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_EU.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes,
            "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/PID-DS-0001_EU_cert.der",
            "loa": "http://eidas.europa.eu/LoA/high",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_jwt_vc_json",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "eidasnode",
            "dynamic_R2": cfgserv.service_url + "eidasnode/dynamic_R2",
        },
        formCountry: {
            "name": "FormEU",
            "pid_url": cfgserv.service_url + "pid/form",
            "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/PID-DS-0001_UT.pem",
            # "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/hackathon-DS-0001_UT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_UT.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/PID-DS-0001_UT_cert.der",
            # "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/hackathon-DS-0001_UT_cert.der",
            "un_distinguishing_sign": "FC",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_jwt_vc_json",
                "eu.europa.ec.eudi.mdl_mdoc",
                "eu.europa.ec.eudi.over18_mdoc",
                "eu.europa.ec.eudi.loyalty_mdoc",
                "eu.europa.ec.eudi.pseudonym_over18_mdoc",
                "eu.europa.ec.eudi.pseudonym_over18_mdoc_deferred_endpoint",
                "eu.europa.ec.eudi.photoid",
                "eu.europa.ec.eudi.por_mdoc",
                "eu.europa.ec.eudi.iban_mdoc",
                "eu.europa.ec.eudi.hiid_mdoc",
                "eu.europa.ec.eudi.tax_mdoc",
                "eu.europa.ec.eudi.msisdn_mdoc",
            ],
            "dynamic_R2": cfgserv.service_url + "dynamic/form_R2",
        },
        "PT": {
            "name": "Portugal",
            "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/PID-DS-0001_PT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_PT.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/PID-DS-0001_PT_cert.der",
            "un_distinguishing_sign": "P",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_jwt_vc_json",
                "eu.europa.ec.eudi.mdl_mdoc",
                "eu.europa.ec.eudi.over18_mdoc",
            ],
            "connection_type": "oauth",
            "oidc_auth": {
                "url": "https://preprod.autenticacao.gov.pt/oauth/askauthorization?",
                "redirect_uri": "https://preprod.issuer.eudiw.dev/"
                + "dynamic/redirect",
                "scope": {
                    "eu.europa.ec.eudi.pid.1": {
                        "given_name": "http://interop.gov.pt/MDC/Cidadao/NomeProprio",
                        "family_name": "http://interop.gov.pt/MDC/Cidadao/NomeApelido",
                        "birth_date": "http://interop.gov.pt/MDC/Cidadao/DataNascimento",
                    },
                    "org.iso.18013.5.1.mDL": {
                        "nif": "http://interop.gov.pt/MDC/Cidadao/NIF",
                        "birth_date": "http://interop.gov.pt/MDC/Cidadao/DataNascimento",
                        "given_name": "http://interop.gov.pt/IMTT/Cidadao/NomeProprio",
                        "family_name": "http://interop.gov.pt/IMTT/Cidadao/NomeApelido",
                        "issuing_authority": "http://interop.gov.pt/IMTT/Cidadao/EntidadeEmissora",
                        "document_number": "http://interop.gov.pt/IMTT/Cidadao/NoCarta",
                        "portrait": "http://interop.gov.pt/DadosCC/Cidadao/Foto",
                        "driving_privileges": "http://interop.gov.pt/IMTT/Cidadao/Categorias",
                    },
                },
                "response_type": "token",
                "client_id": "4819147113201437011",
            },
            "attribute_request": {
                "url": "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager?token=",
                "headers": "",
                "custom_modifiers": "",
            },
        },
        "EE": {
            "name": "Estonia",
            "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/PID-DS-0001_EE.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_EE.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/PID-DS-0001_EE_cert.der",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_jwt_vc_json",
            ],
            "connection_type": "openid",
            "oidc_auth": {
                "base_url": "https://tara-test.ria.ee",
                "redirect_uri": urlReturnEE,
                "scope": "openid",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": "eu_europa_ec_eudiw_pid_provider_1_ppr",
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
                    "Authorization": "Basic ZXVfZXVyb3BhX2VjX2V1ZGl3X3BpZF9wcm92aWRlcl8xX3BwcjpINUVpVjdPaGZMTUs1TFBvcXB0NG5WT1FJeEdicEZ3MQ==",
                },
                "grant_type": "authorization_code",
                "redirect_uri": "https://pprpid.provider.eudiw.projj.eu/tara/redirect",
            },
        },
        "CZ": {
            "name": "Czechia",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=CZ",
            "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/PID-DS-0001_CZ.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_CZ.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/PID-DS-0001_CZ_cert.der",
            "loa": "http://eidas.europa.eu/LoA/high",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_jwt_vc_json",
            ],
            "connection_type": "eidasnode",
            "dynamic_R2": cfgserv.service_url + "eidasnode/dynamic_R2",
        },
        "NL": {
            "name": "Netherland",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=NL",
            "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/PID-DS-0001_NL.pem",
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/PID-DS-0001_NL_cert.der",
            "loa": "http://eidas.europa.eu/LoA/high",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_jwt_vc_json",
            ],
            "connection_type": "eidasnode",
            "dynamic_R2": cfgserv.service_url + "eidasnode/dynamic_R2",
        },
        "LU": {
            "name": "Luxembourg",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=LU",
            "pid_mdoc_privkey": "/etc/eudiw/pid-issuer/privKey/PID-DS-0001_LU.pem",
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": "/etc/eudiw/pid-issuer/cert/PID-DS-0001_LU_cert.der",
            "loa": "http://eidas.europa.eu/LoA/high",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_jwt_vc_json",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "eidasnode",
            "dynamic_R2": cfgserv.service_url + "eidasnode/dynamic_R2",
        },
    }
