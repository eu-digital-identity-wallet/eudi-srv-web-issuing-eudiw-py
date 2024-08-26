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
import datetime
import json
from flask import session
from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries
from misc import calculate_age, getMandatoryAttributes
from redirect_func import json_post
import base64
from flask import session
from app_config.config_service import ConfService as cfgserv
from misc import calculate_age
from redirect_func import json_post
from app import oidc_metadata


def dynamic_formatter(format, doctype, form_data, device_publickey):

    if doctype == "org.iso.18013.5.1.mDL":
        un_distinguishing_sign = cfgcountries.supported_countries[session["country"]][
            "un_distinguishing_sign"
        ]
    else:
        un_distinguishing_sign = ""

    data = formatter(dict(form_data), un_distinguishing_sign, doctype, format)

    if format == "mso_mdoc":
        url = cfgserv.service_url + "formatter/cbor"

    elif format == "vc+sd-jwt":
        url = cfgserv.service_url + "formatter/sd-jwt"

    r = json_post(
        url,
        {
            "version": session["version"],
            "country": session["country"],
            "doctype": doctype,
            "device_publickey": device_publickey,
            "data": data,
        },
    ).json()

    if not r["error_code"] == 0:
        return "Error"

    if format == "mso_mdoc":
        mdoc = bytes(r["mdoc"], "utf-8")
        credential = mdoc.decode("utf-8")
    elif format == "vc+sd-jwt":
        credential = r["sd-jwt"]

    return credential


def formatter(data, un_distinguishing_sign, doctype, format):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    today = datetime.date.today()

    for request in credentialsSupported:
        if (
            credentialsSupported[request]["format"] == "mso_mdoc"
            and credentialsSupported[request]["scope"] == doctype
        ):
            doctype_config = cfgserv.config_doctype[doctype]

            expiry = today + datetime.timedelta(days=doctype_config["validity"])

            namescapes = credentialsSupported[request]["claims"]

            if format == "mso_mdoc":
                for namescape in namescapes:
                    attributes_req = getMandatoryAttributes(
                        credentialsSupported[request]["claims"][namescape]
                    )
                    pdata = {namescape: {}}

            elif format == "vc+sd-jwt":
                pdata = {
                    "evidence": [
                        {
                            "type": doctype,
                            "source": {
                                "organization_name": doctype_config[
                                    "organization_name"
                                ],
                                "organization_id": doctype_config["organization_id"],
                                "country_code": data["issuing_country"],
                            },
                        }
                    ],
                    "claims": {},
                }

                for namescape in namescapes:
                    attributes_req = getMandatoryAttributes(
                        credentialsSupported[request]["claims"][namescape]
                    )
                    pdata["claims"] = {namescape: {}}

            # add optional age_over_18 to mdl
            if doctype == "org.iso.18013.5.1.mDL":
                attributes_req.append("age_over_18")

            if "age_over_18" in attributes_req and "birth_date" in data:
                data.update(
                    {
                        "age_over_18": (
                            True if calculate_age(data["birth_date"]) >= 18 else False
                        )
                    }
                )

            data.update({"un_distinguishing_sign": un_distinguishing_sign})

            data.update({"issuance_date": today.strftime("%Y-%m-%d")})
            data.update({"issue_date": today.strftime("%Y-%m-%d")})
            data.update({"expiry_date": expiry.strftime("%Y-%m-%d")})
            data.update({"issuing_authority": doctype_config["issuing_authority"]})
            if "credential_type" in doctype_config:
                data.update({"credential_type":doctype_config["credential_type"] })
            

            if "driving_privileges" in attributes_req:
                json_priv = json.loads(data["driving_privileges"])
                data.update({"driving_privileges": json_priv})

            if format == "mso_mdoc":
                for attribute in attributes_req:
                    pdata[namescape].update({attribute: data[attribute]})

            elif format == "vc+sd-jwt":
                for attribute in attributes_req:
                    pdata["claims"][namescape].update({attribute: data[attribute]})

                for attribute in attributes_req:
                    pdata["claims"][namescape].update({attribute: data[attribute]})

            return pdata
