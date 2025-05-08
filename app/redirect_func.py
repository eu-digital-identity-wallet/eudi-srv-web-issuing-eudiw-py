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
The PID Issuer Web service is a component of the PID Provider backend. 
Its main goal is to issue the PID and MDL in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This redirect_func.py file manages the redirection of the flow.
"""
import requests
import urllib.parse
from flask import redirect, session

from app_config.config_service import ConfService as cfgserv


def redirect_getpid_or_mdl(version, returnURL, error_num: int, l):
    """Redirect to the returnURL, with error error_num, when the request was made to route pid/getpid or to route mdl/getmdl.

    Keyword arguments:
    + version -- API version
    + returnURL -- URL to redirect
    + error_num -- error number (integer)
    + l -- list with pair of (return fields, value), if the value is not empty/default)

    Return: Redirect to returnURL with error
    """
    rlist = {}
    for field in cfgserv.getpid_or_mdl_response_field[version]:
        rlist[field] = ""
    rlist["error"] = str(error_num)
    if str(error_num) in cfgserv.error_list.keys():
        rlist["error_str"] = cfgserv.error_list[str(error_num)]
    else:
        rlist["error_str"] = cfgserv.error_list["-1"]
    for r, v in l:
        rlist[r] = v

    return redirect(url_get(returnURL, rlist))


def url_get(url_path: str, args: dict):
    """Returns the URL for a HTTP GET query

    Keyword arguments:
    + url_path -- URL without the GET parameters
    + args -- dictionary of parameters (key: value)

    Return: URL for a HTTP GET query
    """
    return url_path + "?" + urllib.parse.urlencode(args)


def json_post(url_path: str, json: dict):
    """Executes the HTTP POST to url_path with json payload

    Keyword arguments:
    + url_path -- URL to POST
    + json -- json payload dictionary (key: value)

    Return: Returns the answer to the HTTP POST
    """
    return requests.post(
        url_path, json=json, headers={"Content-Type": "application/json"}
    )
