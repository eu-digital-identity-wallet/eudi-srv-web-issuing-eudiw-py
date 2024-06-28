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


This boot_validate.py file includes different validation functions.
"""

from typing import List
from werkzeug import datastructures
from cryptography import x509


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


def validate_cert_algo(certificate, lalgo):
    """Validate if certificate algorithm and curve is in the list (lalgo) of supported algorithms

    Keyword arguments:
    + certificate -- certificate in PEM format
    + lalgo -- list of supported algorithms

    Return: (b, algo, curve), where
    + b is True if the certificate algorithm is in the list (lalgo) of supported algorithms, and false otherwise;
    + algo is the certificate algoritm name
    + curve is the public key curve name
    """
    try:
        cert = x509.load_pem_x509_certificate(certificate)
    except Exception as e:
        return (False, str(e), "unknown")
    algname = cert.signature_algorithm_oid._name
    curvname = cert.public_key().curve.name

    if algname not in lalgo:  # validate certificate algorithm
        return (False, algname, curvname)
    if curvname not in lalgo[algname]:  # validate public key curve
        return (False, algname, curvname)

    return (True, algname, curvname)
