# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
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

import json

from app import CONFIGURATION
import requests

def oid4vp_verifier_requests(dcql_query, response_redirect_uri):
    intended_use_id = CONFIGURATION.get("intended_use_id")
    registration_certificate = CONFIGURATION.get("registration_certificate_jwt")

    common_payload = {
        "type": "vp_token",
        "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
        "request_uri_method": "get",
        "dcql_query": dcql_query,
    }

    if not registration_certificate and not intended_use_id:
        raise ValueError(
            "At least one of 'intended_use_id' or 'registration_certificate_jwt' "
            "must be defined in the configuration file."
        )
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