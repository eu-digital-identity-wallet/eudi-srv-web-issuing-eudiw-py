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
This manages necessary data and it's removal 

"""

import json
import threading
from datetime import datetime

from .app_config.config_service import ConfService as cfgservice
import requests


parRequests = {}
transaction_codes={}
deferredRequests = {}
oid4vp_requests = {}
form_dynamic_data = {}
session_ids = {}


def getSessionId_requestUri(target_request_uri):
    matching_session_id = None
    for session_id, session_data in session_ids.items():
        if session_data["request_uri"] == target_request_uri:
            matching_session_id = session_id
            break
    
    return matching_session_id

def getSessionId_authCode(target_authCode):
    matching_session_id = None
    for session_id, session_data in session_ids.items():
        if session_data["auth_code"] == target_authCode:
            matching_session_id = session_id
            break
    
    return matching_session_id

################################################
## To be moved to a file with scheduled jobs

scheduler_call = 3600  # scheduled periodic job will be called every scheduler_call seconds (should be 300; 30 for debug)


def clear_par():
    """Function to clear parRequests"""
    now = int(datetime.timestamp(datetime.now()))
    print("Job scheduled: clear_par() at " + str(now))

    for uri in parRequests.copy():
        expire_time = parRequests[uri]["expires"]
        if now > expire_time:
            parRequests.pop(uri)
            print(
                "Job scheduled: clear_par: "
                + uri
                + " eliminated. "
                + str(now)
                + " > "
                + str(expire_time)
            )
        else:
            print(
                "Job scheduled: clear_par: "
                + uri
                + " not eliminated. "
                + str(now)
                + " < "
                + str(expire_time)
            )

    for req in deferredRequests.copy():
            
            if datetime.now() > deferredRequests[req]["expires"]:
                deferredRequests.pop(req)
            else:
                request_data = json.loads(deferredRequests[req]["data"])
                request_data.update({"transaction_id": req})
                request_data = json.dumps(request_data)
                request_headers = deferredRequests[req]["headers"]

                response = requests.post(cfgservice.service_url+"credential", data=request_data, headers=request_headers)
                response_data = response.json()

                if response.status_code == 200:
                    if "credential" in response_data or "credential_responses" in response_data:
                        deferredRequests.pop(req)
    
    for code in transaction_codes.copy():
        if datetime.now() > transaction_codes[code]["expires"]:
            cfgservice.logger_info.info("Current transaction_codes:\n" + str(transaction_codes))
            cfgservice.logger_info.info("Removing tx_code for code: " + str(code))
            transaction_codes.pop(code)
    
    for id in oid4vp_requests.copy():
        if datetime.now() > oid4vp_requests[id]["expires"]:
            cfgservice.logger_info.info("Current oid4vp_requests:\n" + str(oid4vp_requests))
            cfgservice.logger_info.info("Removing oid4vp_requests with id: " + str(id))
            oid4vp_requests.pop(id)


    """Function to clear app.config['data']"""
    aux = []

    for unique_id, dados in form_dynamic_data.items():
        timestamp = datetime.fromtimestamp(dados.get("timestamp", 0))
        diff = datetime.now() - timestamp
        if diff.total_seconds() > (
            cfgservice.max_time_data * 60
        ):  # minutes * 60 seconds -> data is deleted after being saved for 1 minute
            aux.append(unique_id)

    for unique_id in aux:
        del form_dynamic_data[unique_id]

    if aux:
        print(f"Entries {aux} eliminated.")

def run_scheduler():
    print("Run scheduler.")
    threading.Timer(scheduler_call, run_scheduler).start()
    clear_par()


run_scheduler()
