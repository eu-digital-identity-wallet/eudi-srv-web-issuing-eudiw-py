import json

from app import CONFIGURATION
import requests

def setup_oid4vp_verifier_requests(dcql_query, request_uri_method, response_redirect_uri):
    intended_use_id = CONFIGURATION["intended_use_id"]
    registration_certificate = CONFIGURATION["registration_certificate_jwt"]

    common_payload = {
        "type": "vp_token",
        "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
        "request_uri_method": request_uri_method,
        "dcql_query": dcql_query,
    }

    if registration_certificate:
        common_payload.update({"registration_certificate": registration_certificate})
    else:
        common_payload.update({"intended_use_id": intended_use_id})

    payload_cross_device = json.dumps(common_payload)

    common_payload.update({"wallet_response_redirect_uri_template": response_redirect_uri})
    payload_same_device = json.dumps(common_payload)

    url = CONFIGURATION["dynamic_presentation_url"]
    headers = {"Content-Type": "application/json"}

    response_cross = requests.request("POST", url, headers=headers, data=payload_cross_device).json()
    response_same = requests.request("POST", url, headers=headers, data=payload_same_device).json()

    return response_cross, response_same