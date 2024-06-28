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


This pid_func.py file contains PID related auxiliary functions.
"""
import datetime
from app_config.config_service import ConfService as cfgserv
from misc import calculate_age


def format_pid_data(dict):
    """Formats PID data, from the format received from the eIDAS node, into the format expected by the CBOR formatter (route formatter/cbor)

    Keyword arguments:
    dict -- dictionary with PID data received from the eIDAS node
    country -- PID issuing country

    Return: dictionary in the format expected by the CBOR formatter (route formatter/cbor)
    """
    birthdate = dict["birth_date"]
    today = datetime.date.today()
    expiry = today + datetime.timedelta(days=cfgserv.pid_validity)
    pdata = {
        "family_name": dict["family_name"],
        "given_name": dict["given_name"],
        "birth_date": birthdate,
        "age_over_18": True if calculate_age(birthdate) >= 18 else False,
        "issuance_date": today.strftime("%Y-%m-%d"),
        "expiry_date": expiry.strftime("%Y-%m-%d"),
        "issuing_authority": cfgserv.pid_issuing_authority,
        "issuing_country": dict["issuing_country"],
    }

    return pdata


def format_sd_jwt_pid_data(dict):
    """Formats PID data, from the format received from the eIDAS node, into the format expected by the SD-JWT formatter (route formatter/sd-jwt)

    Keyword arguments:
    dict -- dictionary with PID data received from the eIDAS node
    country -- PID issuing country

    Return: dictionary in the format expected by the SD-JWT formatter (route formatter/sd-jwt)
    """
    birthdate = dict["birth_date"]
    today = datetime.date.today()
    expiry = today + datetime.timedelta(days=cfgserv.pid_validity)
    pdata = {
        "evidence": [
            {
                "type": "eu.europa.ec.eudi.pid.1",
                "source": {
                    "organization_name": cfgserv.pid_issuing_authority,
                    "organization_id": cfgserv.pid_organization_id,
                    "country_code": dict["issuing_country"],
                },
            }
        ],
        "claims": {
            "eu.europa.ec.eudi.pid.1": {
                "family_name": dict["family_name"],
                "given_name": dict["given_name"],
                "birth_date": birthdate,
                "age_over_18": True if calculate_age(birthdate) >= 18 else False,
                "issuance_date": today.strftime("%Y-%m-%d"),
                "expiry_date": expiry.strftime("%Y-%m-%d"),
                "issuing_authority": cfgserv.pid_issuing_authority,
                "issuing_country": dict["issuing_country"],
            }
        },
    }

    return pdata
