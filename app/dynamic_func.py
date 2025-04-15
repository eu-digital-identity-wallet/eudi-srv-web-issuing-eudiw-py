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
from misc import calculate_age, getIssuerFilledAttributes, getMandatoryAttributes, getOptionalAttributes
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
    print("\ndynamic_func data: ", data)
    
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
                    #print("\nNamespace: ", namescape)
                    attributes_req = getMandatoryAttributes(
                        credentialsSupported[request]["claims"][namescape]
                    )

                    #print("\nattributes_req: ", attributes_req)
                    attributes_req2 = getOptionalAttributes(
                        credentialsSupported[request]["claims"][namescape]
                    )

                    #print("\nattributes_req2: ", attributes_req2)
                    issuer_claims = getIssuerFilledAttributes(credentialsSupported[request]["claims"][namescape])                    

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

                    attributes_req2 = getOptionalAttributes(
                        credentialsSupported[request]["claims"][namescape]
                    )

                    issuer_claims = getIssuerFilledAttributes(credentialsSupported[request]["claims"][namescape])

                    pdata["claims"] = {namescape: {}}

            # add optional age_over_18 to mdl
            """ if doctype == "org.iso.18013.5.1.mDL" or doctype == "eu.europa.ec.eudi.pid.1":
                attributes_req.update({"age_over_18":"bool"}) """

            if ("age_over_18" in issuer_claims) and "birth_date" in data:
                data.update(
                    {
                        "age_over_18": (
                            True if calculate_age(data["birth_date"]) >= 18 else False
                        )
                    }
                )
            
            if "un_distinguishing_sign" in issuer_claims:
                data.update({"un_distinguishing_sign": un_distinguishing_sign})

            if "issuance_date" in issuer_claims:
                data.update({"issuance_date": today.strftime("%Y-%m-%d")})

            if "issue_date" in issuer_claims: 
                data.update({"issue_date": today.strftime("%Y-%m-%d")})
            if "expiry_date" in issuer_claims:
                data.update({"expiry_date": expiry.strftime("%Y-%m-%d")})

            if "issuing_authority" in issuer_claims:
                data.update({"issuing_authority": doctype_config["issuing_authority"]})

            if "issuing_authority_unicode" in issuer_claims:
                data.update({"issuing_authority_unicode": doctype_config["issuing_authority"]})

            if "credential_type" in issuer_claims:
                data.update({"credential_type":doctype_config["credential_type"] })
                attributes_req.update({"credential_type":""})
            
            """ attributes_req.update({
                "expiry_date":"",
                "issuing_authority":"",
                "issuing_country":"",
            })

            if doctype == "org.iso.18013.5.1.mDL":
                attributes_req.update({
                "issue_date":"",
                "un_distinguishing_sign":"",
                })
            else:
                attributes_req.update({
                "issuance_date":"",
                }) """

            if "at_least_one_of" in attributes_req:
                attributes_req.pop("at_least_one_of")

            if "driving_privileges" in attributes_req:
                json_priv = json.loads(data["driving_privileges"])
                data.update({"driving_privileges": json_priv})
            
            if "places_of_work" in attributes_req and not isinstance(data["places_of_work"],list):
                json_priv = json.loads(data["places_of_work"])
                data.update({"places_of_work": json_priv})
            
            if "legislation" in attributes_req and not isinstance(data["legislation"],list):
                json_priv = json.loads(data["legislation"])
                data.update({"legislation": json_priv})
            
            if "employment_details" in attributes_req and not isinstance(data["employment_details"],list):
                json_priv = json.loads(data["employment_details"])
                data.update({"employment_details": json_priv})

            
            if "competent_institution" in attributes_req and not isinstance(data["competent_institution"],list):
                json_priv = json.loads(data["competent_institution"])
                data.update({"competent_institution": json_priv})

            if "credential_holder" in attributes_req and isinstance(data["credential_holder"],list):
                data.update({"credential_holder": data["credential_holder"][0]})

            if "credential_holder" in attributes_req2 and isinstance(data["credential_holder"],list):
                data.update({"credential_holder": data["credential_holder"][0]})

            if "subject" in attributes_req and isinstance(data["subject"],list):
                data.update({"subject": data["subject"][0]})

            if "subject" in attributes_req2 and isinstance(data["subject"],list):
                data.update({"subject": data["subject"][0]})

            if "competent_institution" in attributes_req and isinstance(data["competent_institution"],list):
                data.update({"competent_institution": data["competent_institution"][0]})

            if "competent_institution" in attributes_req2 and isinstance(data["competent_institution"],list):
                data.update({"competent_institution": data["competent_institution"][0]})

            if "legislation" in attributes_req and isinstance(data["legislation"],list):
                data.update({"legislation": data["legislation"][0]})

            if "legislation" in attributes_req2 and isinstance(data["legislation"],list):
                data.update({"legislation": data["legislation"][0]})
            
            if "at_least_one_of" in attributes_req2:
                        attributes_req2.pop("at_least_one_of")
            
            if "credential_holder" in attributes_req2 and not isinstance(data["credential_holder"],list):
                json_priv = json.loads(data["credential_holder"])
                data.update({"credential_holder": json_priv})

            if "subject" in attributes_req2 and not isinstance(data["subject"],list):
                json_priv = json.loads(data["subject"])
                data.update({"subject": json_priv})

            if "age_in_years" in data and isinstance(data["age_in_years"], str):
                data.update({"age_in_years": int(data["age_in_years"])})

            if "age_birth_year" in data and isinstance(data["age_birth_year"], str):
                data.update({"age_birth_year": int(data["age_birth_year"])})

            if format == "mso_mdoc":
                for attribute in attributes_req:
                    pdata[namescape].update({attribute: data[attribute]})

                for attribute in attributes_req2:
                    if attribute in data:
                        pdata[namescape].update({attribute: data[attribute]})

                for attribute in issuer_claims:
                    if attribute in data:
                        pdata[namescape].update({attribute: data[attribute]})
                
                #print("\npdata_namespace: ", pdata[namescape])
                

            elif format == "vc+sd-jwt":
                for attribute in attributes_req:
                    pdata["claims"][namescape].update({attribute: data[attribute]})

                for attribute in attributes_req2:
                    if attribute in data:
                        pdata["claims"][namescape].update({attribute: data[attribute]})

                for attribute in issuer_claims:
                    if attribute in data:
                        pdata["claims"][namescape].update({attribute: data[attribute]})


            return pdata
