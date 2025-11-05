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
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from app_config.config_service import ConfService as cfgservice
import requests
from app import session_manager

credential_offer_references = {}
revocation_requests = {}

################################################
## To be moved to a file with scheduled jobs

scheduler_call = 300  # scheduled periodic job will be called every scheduler_call seconds (should be 300; 30 for debug)


def clear_par():
    for id in credential_offer_references.copy():
        if datetime.now() > credential_offer_references[id]["expires"]:
            cfgservice.app_logger.info("Removing credential reference id: " + str(id))
            credential_offer_references.pop(id)

    for id in revocation_requests.copy():
        if datetime.now() > revocation_requests[id]["expires"]:
            cfgservice.app_logger.info("Removing revpcatopm reference id: " + str(id))
            revocation_requests.pop(id)

    session_manager.clean_expired_sessions()
