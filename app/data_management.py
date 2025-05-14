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
credential_offer_references = {}

def getSessionId_requestUri(target_request_uri):
    matching_session_id = None
    for session_id, session_data in session_ids.items():
        
        if "request_uri" in session_data and session_data["request_uri"] == target_request_uri:
            matching_session_id = session_id
            break
    
    return matching_session_id

def getSessionId_authCode(target_authCode):
    matching_session_id = None
    for session_id, session_data in session_ids.items():
        if "auth_code" in session_data and session_data["auth_code"] == target_authCode:
            matching_session_id = session_id
            break
    
    return matching_session_id

def getSessionId_accessToken(target_accessToken):
    matching_session_id = None
    for session_id, session_data in session_ids.items():
        if "access_token" in session_data and session_data["access_token"] == target_accessToken:
            matching_session_id = session_id
            break
    
    return matching_session_id

################################################
## To be moved to a file with scheduled jobs

scheduler_call = 30  # scheduled periodic job will be called every scheduler_call seconds (should be 300; 30 for debug)


def clear_par():
    """Function to clear parRequests"""
    now = int(datetime.timestamp(datetime.now()))
    #print("Job scheduled: clear_par() at " + str(now))
    #print("Job scheduled: clear_par() at " + str(now))

    for uri in parRequests.copy():
        expire_time = parRequests[uri]["expires"]
        if now > expire_time:
            parRequests.pop(uri)
            """ print(
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
            ) """

    """ for req in deferredRequests.copy():
            
            if datetime.now() > deferredRequests[req]["expires"]:
                deferredRequests.pop(req)
            else:
                request_data = json.loads(deferredRequests[req]["data"])
                print("\ndata: ", request_data)
                request_data.update({"transaction_id": req})
                print("\ntransaction_id: ", req)
                request_data = json.dumps(request_data)
                print("\ndata2: ", request_data)
                request_headers = deferredRequests[req]["headers"]
                print("\nheaders: ", request_headers)

                response = requests.post(cfgservice.service_url+"credential", data=request_data, headers=request_headers)
                print("\nresponse", response.text)
                response_data = response.json()

                if response.status_code == 200:
                    if "credentials" in response_data or "encrypted_response" in response_data and not "decrypted_transaction_id" in response_data:
                        deferredRequests.pop(req) """
    
    for code in transaction_codes.copy():
        if datetime.now() > transaction_codes[code]["expires"]:
            #cfgservice.logger_info.info("Current transaction_codes:\n" + str(transaction_codes))
            cfgservice.app_logger.info("Removing tx_code for code: " + str(code))
            transaction_codes.pop(code)
    
    for id in oid4vp_requests.copy():
        if datetime.now() > oid4vp_requests[id]["expires"]:
            #cfgservice.logger_info.info("Current oid4vp_requests:\n" + str(oid4vp_requests))
            cfgservice.app_logger.info("Removing oid4vp_requests with id: " + str(id))
            oid4vp_requests.pop(id)
    
    for id in session_ids.copy():
        if datetime.now() > session_ids[id]["expires"]:
            cfgservice.app_logger.info("Removing session id: " + str(id))
            session_ids.pop(id)

    for id in form_dynamic_data.copy():
        if datetime.now() > form_dynamic_data[id]["expires"]:
            cfgservice.app_logger.info("Removing form id: " + str(id))
            form_dynamic_data.pop(id)
    
    for id in credential_offer_references.copy():
        if datetime.now() > credential_offer_references[id]["expires"]:
            cfgservice.app_logger.info("Removing credential reference id: " + str(id))
            credential_offer_references.pop(id)

def run_scheduler():
    #print("Run scheduler.")
    threading.Timer(scheduler_call, run_scheduler).start()
    clear_par()


run_scheduler()
