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
import subprocess
import sys

#           ENDPOINT
ENDPOINT = "https://127.0.0.1:4430/"
#ENDPOINT = "https://preprod.issuer.eudiw.dev/"


#           test_route_pid
ENDPOINT_route_pid_pid = ENDPOINT + "pid" #pid
ENDPOINT_route_pid_pidtest = ENDPOINT + "pid/getpidtest" #pid/getpidtest

#           test_route_formatter
ENDPOINT_route_formatter = ENDPOINT + "formatter/cbor" #formatter/cbor

#           test_route_ee_tara
ENDPOINT_route_ee_tara = "tara/redirect"

#           test_route_eidasnode
ENDPOINT_route_lightRequest = "eidasnode/lightrequest"
ENDPOINT_route_lightResponse = "eidasnode/lightresponse"

#           test_route_pt_cmd
ENDPOINT_ptcmd = "cmd/redirect"

#   If you want the report in HTML, put                             option = 0.
#   If you want just the report to print on the terminal, put       option = 1.


def run_tests(): 
    if len(sys.argv) > 1:
        # The first argument (sys.argv[1]) is the value you will pass on the command line.
        option = int(sys.argv[1])
    else:
        # Default value if no argument is provided
        option = 0

    #generate a html file with the report
    if (option == 0):
        subprocess.run(['pytest', '--html=reportPytest.html'])

    #print the summary on the terminal
    elif (option == 1):
        terminalprint()
    

#print the summary on terminal
def terminalprint():
    test_route_pid = subprocess.run(['pytest', 'test_route_pid.py'], capture_output=True, text=True)
    print("\n\n----------------> Results test in route_pid: <----------------\n\n")
    print(test_route_pid.stdout)
    
    test_route_formatter = subprocess.run(['pytest', 'test_route_formatter.py'], capture_output=True, text=True)
    print("\n\n----------------> Results test in route_formatter: <----------------\n\n")
    print(test_route_formatter.stdout)

    test_route_ee_tara = subprocess.run(['pytest', 'test_route_ee_tara.py'], capture_output=True, text=True)
    print("\n\n----------------> Results test in route_ee_tara: <----------------\n\n")
    print(test_route_ee_tara.stdout)

    test_route_eidasnode = subprocess.run(['pytest', 'test_route_eidasnode.py'], capture_output=True, text=True)
    print("\n\n----------------> Results test in route_eidasnode: <----------------\n\n")
    print(test_route_eidasnode.stdout)

    test_route_pt_cmd = subprocess.run(['pytest', 'test_route_pt_cmd.py'], capture_output=True, text=True)
    print("\n\n----------------> Results test in route_pt_cmd: <----------------\n\n")
    print(test_route_pt_cmd.stdout)


if __name__ == "__main__":
    run_tests()