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


This validate.py file includes different validation functions.
"""

import datetime

from typing import List
from werkzeug import datastructures
from cryptography.hazmat.primitives import serialization


# Log
# from app_config.config_service import ConfService as log


def validate_mandatory_args(
    args: datastructures.ImmutableMultiDict[str, str], mandlist: List[str]
):
    """Validate mandatory query arguments.
    Verify if all the members of mandlist have a value in args

    Keyword arguments:
    + args -- list of query arguments
    + mandlist -- list of strings that need to have a value in args

    Return: Return tuple (bool, List[str]).
    + If all the mandlist elements have a value in args, return (true, []).
    + If there are mandlist elements that have not a value in args, return (false, l), where l is the list of all mandlist elements that have no value in args.
    """
    l = []
    b = True

    for m in mandlist:
        if args.get(m) is None:
            b = False
            l.append(m)
    return (b, l)


def is_valid_pem_public_key(pem_key):
    """Validate if device public key is in PEM format
    Keyword arguments:
    + pem_key- device public key from /mdl or /pid

    Return: Return True or return value.
    + If pem_key have the correct format , return True.
    + If pem_key have the incorrect format, return False
    """
    try:
        # Attempts to load the public key in PEM format
        public_key = serialization.load_pem_public_key(pem_key, backend=None)
        return True
    except Exception as e:
        return False


def validate_date_format(date):
    """Validate if date is in the correct format
    Return: Return True or return value.
    + If date have the correct format , return True.
    + If date have the incorrect format, return False
    """
    try:
        datetime.datetime.strptime(date, "%Y-%m-%d")
        return True
    except ValueError:
        return False
