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
        un_distinguishing_sign = cfgcountries.supported_countries[session["country"]]["un_distinguishing_sign"]
    else:
        un_distinguishing_sign = ""

    doctype_config=cfgserv.config_doctype[doctype]

    if format== "mso_mdoc":

        data=dynamic_mdoc_formatter(dict(form_data), un_distinguishing_sign, doctype)


        r = json_post(
            cfgserv.service_url + "formatter/cbor",
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

        mdoc = bytes(r["mdoc"], "utf-8")
        ciphertext = mdoc.decode("utf-8")

        return ciphertext

    elif format=="vc+sd-jwt":

        data= dynamic_sd_jwt_formatter(dict(form_data), un_distinguishing_sign, doctype)

        r1 = json_post(
        cfgserv.service_url + "formatter/sd-jwt",
        {
            "version": session["version"],
            "country": session["country"],
            "doctype": doctype,
            "device_publickey": device_publickey,
            "data": data,
        },
        ).json()

        if not r1["error_code"] == 0:
            return "Error"

        sd_jwt = r1["sd-jwt"]

        return sd_jwt


def dynamic_mdoc_formatter(data, un_distinguishing_sign, doctype):

    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    today = datetime.date.today()


    for request in credentialsSupported:
        if credentialsSupported[request]["format"] == "mso_mdoc" and credentialsSupported[request]["scope"]== doctype:

            doctype_config=cfgserv.config_doctype[doctype]

            expiry = today + datetime.timedelta(days=doctype_config["validity"])

            namescapes = credentialsSupported[request]["claims"]
            for namescape in namescapes:
                attributes_req = getMandatoryAttributes(
                        credentialsSupported[request]["claims"][namescape]
                    )
                pdata ={namescape:{}}

                # add optional age_over_18 to mdl
                if doctype == "org.iso.18013.5.1.mDL":
                    attributes_req.append("age_over_18")

                if "age_over_18" in attributes_req and "birth_date" in data:
                    data.update({"age_over_18": True if calculate_age(data["birth_date"]) >= 18 else False})

                data.update({"un_distinguishing_sign": un_distinguishing_sign})

                data.update({"issuance_date":today.strftime("%Y-%m-%d")})
                data.update({"issue_date":today.strftime("%Y-%m-%d")})
                data.update({"expiry_date":expiry.strftime("%Y-%m-%d")})
                data.update({"issuing_authority":doctype_config["issuing_authority"]})
                
                if "user_pseudonym" in data:
                    # Convert UUID to bytes
                    uuid_bytes = data["user_pseudonym"].encode('utf-8')

                    # Encode bytes to base64url without padding
                    encoded_data = base64.urlsafe_b64encode(uuid_bytes).rstrip(b'=')
                    data["user_pseudonym"] = encoded_data.decode('utf-8')
                
                if "driving_privileges" in attributes_req:
                    json_priv = json.loads(data["driving_privileges"])
                    data.update({"driving_privileges":json_priv})
                    
                for attribute in attributes_req:
                    pdata[namescape].update({attribute:data[attribute]})

                

            return pdata

def dynamic_sd_jwt_formatter(data, un_distinguishing_sign, doctype):
    """Formats MDL data, from the format received from the eIDAS node, into the format expected by the SD-JWT formatter (route formatter/sd-jwt)
    Keyword arguments:
    dict -- dictionary with MDL data received from the eIDAS node
    country -- MDL issuing country
    Return: dictionary in the format expected by the SD-JWT formatter (route formatter/sd-jwt)
    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    today = datetime.date.today()


    for request in credentialsSupported:
        if credentialsSupported[request]["format"] == "mso_mdoc" and credentialsSupported[request]["scope"]== doctype:
            doctype_config=cfgserv.config_doctype[doctype]

            expiry = today + datetime.timedelta(days=doctype_config["validity"])

            namescapes = credentialsSupported[request]["claims"]
            pdata = {
                    "evidence": [
                        {
                            "type": doctype,
                            "source": {
                                "organization_name": doctype_config["organization_name"],
                                "organization_id": doctype_config["organization_id"],
                                "country_code": data["issuing_country"],
                            },
                        }
                    ],
                    "claims": {

                    }
                }
            
            for namescape in namescapes:
                attributes_req = getMandatoryAttributes(
                        credentialsSupported[request]["claims"][namescape]
                    )
                pdata["claims"]= {
                    namescape:{

                    }
                }

                # add optional age_over_18 to mdl
                if doctype == "org.iso.18013.5.1.mDL":
                    attributes_req.append("age_over_18")
                
                if "age_over_18" in attributes_req and "birth_date" in data:
                    data.update({"age_over_18": True if calculate_age(data["birth_date"]) >= 18 else False})

                data.update({"un_distinguishing_sign": un_distinguishing_sign})

                data.update({"issuance_date":today.strftime("%Y-%m-%d")})
                data.update({"issue_date":today.strftime("%Y-%m-%d")})
                data.update({"expiry_date":expiry.strftime("%Y-%m-%d")})
                data.update({"issuing_authority":doctype_config["issuing_authority"]})

                if "driving_privileges" in attributes_req:
                    json_priv = json.loads(data["driving_privileges"])
                    data.update({"driving_privileges":json_priv})
                    
                for attribute in attributes_req:
                    pdata["claims"][namescape].update({attribute:data[attribute]})


                for attribute in attributes_req:
                    pdata["claims"][namescape].update({attribute:data[attribute]})

            return pdata