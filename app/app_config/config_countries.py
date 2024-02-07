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
        "CW": {
            "name": "nodeEU",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=CW",
            "pid_mdoc_privkey": '/etc/eudiw/pid-issuer/privkey/PID-DS-0001_EU.pem',
            #"pid_mdoc_privkey": 'app\certs\PID-DS-0001_EU.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes,
            "pid_mdoc_cert": '/etc/eudiw/pid-issuer/cert/PID-DS-0001_EU_cert.der',
            "loa": "http://eidas.europa.eu/LoA/high",
            "mdl_url": "",
        },
        formCountry: {
            "name": "FormEU",
            "pid_url": cfgserv.service_url  + "pid/form",
            "pid_mdoc_privkey": '/etc/eudiw/pid-issuer/privkey/PID-DS-0001_UT.pem',
            #"pid_mdoc_privkey": 'app\certs\PID-DS-0001_UT.pem',

            "pid_mdoc_privkey_passwd": None,  # None or bytes         
            "pid_mdoc_cert": '/etc/eudiw/pid-issuer/cert/PID-DS-0001_UT_cert.der',
            "mdl_url": cfgserv.service_url  + "V04/mdl/form",
            "qeaa_func": cfgserv.service_url  + "V04/qeaa/form",
            "un_distinguishing_sign":"FC",
            "pid_url_oidc": cfgserv.service_url  + "V04/form"
         },
         "PT": {
            "name": "Portugal",
            "pid_url_oidc": "https://preprod.autenticacao.gov.pt/oauth/askauthorization?redirect_uri=" + cfgserv.service_url  + "cmd/redirect&client_id=6285415231191573957&response_type=token&scope=http://interop.gov.pt/MDC/Cidadao/NomeApelido http://interop.gov.pt/MDC/Cidadao/NomeProprio http://interop.gov.pt/MDC/Cidadao/DataNascimento http://interop.gov.pt/MDC/Cidadao/NIC",
            "pid_mdoc_privkey": '/etc/eudiw/pid-issuer/privkey/PID-DS-0001_PT.pem',
            #"pid_mdoc_privkey": 'app\certs\PID-DS-0001_PT.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": '/etc/eudiw/pid-issuer/cert/PID-DS-0001_PT_cert.der',
            "mdl_url": "https://preprod.autenticacao.gov.pt/oauth/askauthorization?redirect_uri=" + cfgserv.service_url  + "cmd/redirectmdl&client_id=6285415231191573957&response_type=token&scope=http://interop.gov.pt/MDC/Cidadao/DataNascimento http://interop.gov.pt/MDC/Cidadao/NIF http://interop.gov.pt/IMTT/Cidadao/NomeApelido http://interop.gov.pt/IMTT/Cidadao/NomeProprio http://interop.gov.pt/IMTT/Cidadao/EntidadeEmissora http://interop.gov.pt/IMTT/Cidadao/NoCarta http://interop.gov.pt/DadosCC/Cidadao/Foto http://interop.gov.pt/IMTT/Cidadao/Categorias http://interop.gov.pt/IMTT/Cidadao/LocalNascimento",
            "qeaa_func": "https://preprod.autenticacao.gov.pt/oauth/askauthorization?redirect_uri="+ cfgserv.service_url + "V04/qeaa/redirectqeaa&client_id=6285415231191573957&response_type=token&scope=http://interop.gov.pt/SCAP/FAF",
            "un_distinguishing_sign":"P"
        },

#        "PT": {
#            "name": "Portugal",
#            "pid_url": "https://preprod.autenticacao.gov.pt/oauth/askauthorization?redirect_uri=" + cfgserv.service_url  + "cmd/redirect&client_id=12345678910&response_type=token&scope=http://interop.gov.pt/MDC/Cidadao/NomeApelido http://interop.gov.pt/MDC/Cidadao/NomeProprio http://interop.gov.pt/MDC/Cidadao/DataNascimento http://interop.gov.pt/MDC/Cidadao/NIC",
#            "pid_mdoc_privkey": 'app/certs/PID-DS-0001_PT.pem',
#            "pid_mdoc_privkey_passwd": None,  # None or bytes
#            "mdl_url": "https://preprod.autenticacao.gov.pt/oauth/askauthorization?redirect_uri=" + cfgserv.service_url  + "cmd/redirectmdl&client_id=12345678910&response_type=token&scope=http://interop.gov.pt/MDC/Cidadao/DataNascimento http://interop.gov.pt/MDC/Cidadao/NIF http://interop.gov.pt/IMTT/Cidadao/NomeApelido http://interop.gov.pt/IMTT/Cidadao/NomeProprio http://interop.gov.pt/IMTT/Cidadao/EntidadeEmissora http://interop.gov.pt/IMTT/Cidadao/NoCarta http://interop.gov.pt/DadosCC/Cidadao/Foto http://interop.gov.pt/IMTT/Cidadao/Categorias http://interop.gov.pt/IMTT/Cidadao/LocalNascimento",
#            "qeaa_func": "https://preprod.autenticacao.gov.pt/oauth/askauthorization?redirect_uri="+ cfgserv.service_url + "qeaa/redirectqeaa&client_id=12345678910&response_type=token&scope=http://interop.gov.pt/SCAP/FAF",
#            "un_distinguishing_sign":"P"
#        },
        "EE": {
            "name": "Estonia",
            "pid_url_oidc": "https://tara-test.ria.ee/oidc/authorize?redirect_uri=" + urlReturnEE + "&scope=openid&state=hkMVY7vjuN7xyLl5&response_type=code&client_id=eu_europa_ec_eudiw_pid_provider_1_ppr",
            "pid_mdoc_privkey": '/etc/eudiw/pid-issuer/privkey/PID-DS-0001_EE.pem',
            #"pid_mdoc_privkey": 'app\certs\PID-DS-0001_EE.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": '/etc/eudiw/pid-issuer/cert/PID-DS-0001_EE_cert.der',
            "mdl_url": "",
        },
        "CZ": {
            "name": "Czechia",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=CZ",
            "pid_mdoc_privkey": '/etc/eudiw/pid-issuer/privkey/PID-DS-0001_CZ.pem',
            #"pid_mdoc_privkey": 'app\certs\PID-DS-0001_CZ.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes          
            "pid_mdoc_cert": '/etc/eudiw/pid-issuer/cert/PID-DS-0001_CZ_cert.der',
            "loa": "http://eidas.europa.eu/LoA/high",
            "mdl_url": "",
        },
        "":{
            
        }
    }