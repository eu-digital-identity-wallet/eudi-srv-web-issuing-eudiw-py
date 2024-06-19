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

from .config_service import ConfService as cfgserv

class ConfService:
    # Country Selection URLs

    country_redirect = {
        # "org.iso.18013.5.1.mDL openid": "https://preprod.issuer.eudiw.dev/V04/mdl",
        "org.iso.18013.5.1.mDL openid": "https://127.0.0.1:5000/V04/mdl",
        # "eu.europa.ec.eudiw.pid.1 openid": "https://preprod.issuer.eudiw.dev/V04/pid",
        "eu.europa.ec.eudiw.pid.1 openid": "https://127.0.0.1:5000/V04/pid",
        "eu.europa.ec.eudiw.qeaa.1 openid": "https://preprod.issuer.eudiw.dev/V04/qeaa",
        "dynamic": cfgserv.service_url + "auth_choice",
    }

    # Credential URLs

    credential_urls = {
        "org.iso.18013.5.1.mDL.PT": "https://preprod.issuer.eudiw.dev/cmd/mdl_R2?user_id=",
        "org.iso.18013.5.1.mDL.FC": "https://preprod.issuer.eudiw.dev/V04/mdl/form_R2?user_id=",
        "eu.europa.ec.eudiw.pid.1.PT": "https://preprod.issuer.eudiw.dev/cmd/R2?user_id=",
        "eu.europa.ec.eudiw.pid.1.EE": "https://preprod.issuer.eudiw.dev/tara/R2?user_id=",
        "eu.europa.ec.eudiw.pid.1.CW": "https://preprod.issuer.eudiw.dev/eidasnode/eidasR2?user_id=",
        # "eu.europa.ec.eudiw.pid.1.FC": "https://preprod.issuer.eudiw.dev/V04/form_R2?user_id=",
        "eu.europa.ec.eudiw.pid.1.FC": "https://127.0.0.1:5000/V04/form_R2?user_id=",
        "eu.europa.ec.eudiw.qeaa.1.PT": "https://preprod.issuer.eudiw.dev/V04/qeaa/R2?user_id=",
        "eu.europa.ec.eudiw.qeaa.1.FC": "https://preprod.issuer.eudiw.dev/V04/qeaa/form_R2?user_id=",
        "dynamic": cfgserv.service_url + "dynamic/dynamic_R2",
    }
