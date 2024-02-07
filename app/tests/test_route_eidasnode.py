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
import requests 
import main_pytest

ENDPOINTeidasnode_lightRequest = main_pytest.ENDPOINT_route_lightRequest
ENDPOINTeidasnode_lightResponse = main_pytest.ENDPOINT_route_lightResponse

# Route Eidas Node
# /eidasnode/lightrequest

def test_eidasnode_lightRequest():
    url = main_pytest.ENDPOINT + ENDPOINTeidasnode_lightRequest + "?country=PT"
    response= requests.get(url, verify=False)
    assert response.text == "Missing mandatory lightrequest eidasnode fields."


#   no mandatory atributes
#   no country
 
def test_eidasnode_lightRequest_noCountry():
    url = main_pytest.ENDPOINT + ENDPOINTeidasnode_lightRequest
    response= requests.get(url, verify=False)
    assert response.text == "Error 301: Missing mandatory lightrequest eidasnode fields."


# Route Eidas Node
# /eidasnode/lightresponse

def test_eidasnode_lightResponse():
    url = main_pytest.ENDPOINT + ENDPOINTeidasnode_lightResponse
    response= requests.post(url, verify=False)
    assert response.text == "Error 302: Missing mandatory lightresponse eidasnode fields."









