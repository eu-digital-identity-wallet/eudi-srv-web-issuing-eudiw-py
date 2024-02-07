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

ENDPOINT = main_pytest.ENDPOINT
ENDPOINT_ptcmd = main_pytest.ENDPOINT_ptcmd


# Route pt cmd
# /cmd/redirect

#   no attributes
def test_route_pt_cmd():
    url = "https://127.0.0.1:4430/cmd/redirect"

    response= requests.get(url, verify=False)
    
    assert response.text == "Error 501: Missing mandatory IdP fields"

#   wrong atributes
def test_route_pt_cmd_error404():
    url = ENDPOINT + ENDPOINT_ptcmd + "?code=sadadsada&scope=dasdadasd&state=dadasda"
    response= requests.get(url, verify=False)
    
    assert response.text == "Error 501: Missing mandatory IdP fields"

#   Missing field: code
def test_route_pt_cmd_noCode():
    url = ENDPOINT + ENDPOINT_ptcmd + "?scope=dasdadasd&state=dadasda"
    response= requests.get(url, verify=False)
    
    assert response.text == "Error 501: Missing mandatory IdP fields"

#   Missing field: scope
def test_route_pt_cmd_noScope():
    url = ENDPOINT + ENDPOINT_ptcmd + "?code=sadadsada&state=dadasda"
    response= requests.get(url, verify=False)
    
    assert response.text == "Error 501: Missing mandatory IdP fields"

#   Missing field: state
def test_route_pt_cmd_noState():
    url = ENDPOINT + ENDPOINT_ptcmd + "?code=sadadsada&scope=dasdadasd"
    response= requests.get(url, verify=False)
    
    assert response.text == "Error 501: Missing mandatory IdP fields"