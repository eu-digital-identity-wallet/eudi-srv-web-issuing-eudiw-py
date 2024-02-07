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

ENDPOINTtara = main_pytest.ENDPOINT_route_ee_tara


# Route ee tara
# /tara/redirect

#   expired acess_token
def test_ee_tara():
    url = main_pytest.ENDPOINT + ENDPOINTtara + "?code=BOiFe_z-aMpJvhPjeJZWZZ3GUkaDe_A34Fc7syLC7fw.v8UcdXdksdKiZx8zk3zWvL38lhFKnVPPP1Rt2CW0c3Y&scope=openid&state=hkMVY7vjuN7xyLl5"
    response= requests.get(url, verify=False)
    assert response.text == "Error 502: Missing mandatory EE fields."


#   no mandatory atributes
#   no code 
def test_ee_tara_noCode():
    url = main_pytest.ENDPOINT + ENDPOINTtara + "?scope=openid&state=hkMVY7vjuN7xyLl5"
    response= requests.get(url, verify=False)
    assert response.text == "Error 502: Missing mandatory EE fields."
    

#    no scope 
def test_ee_tara_noScope():
    url = main_pytest.ENDPOINT + ENDPOINTtara + "?code=BOiFe_z-aMpJvhPjeJZWZZ3GUkaDe_A34Fc7syLC7fw.v8UcdXdksdKiZx8zk3zWvL38lhFKnVPPP1Rt2CW0c3Y&state=hkMVY7vjuN7xyLl5"
    response= requests.get(url, verify=False)
    assert response.text == "Error 502: Missing mandatory EE fields."
    
#   no state 
def test_ee_tara_noState():
    url = main_pytest.ENDPOINT + ENDPOINTtara + "?code=BOiFe_z-aMpJvhPjeJZWZZ3GUkaDe_A34Fc7syLC7fw.v8UcdXdksdKiZx8zk3zWvL38lhFKnVPPP1Rt2CW0c3Y&scope=openid"
    response= requests.get(url, verify=False)
    assert response.text == "Error 502: Missing mandatory EE fields."









