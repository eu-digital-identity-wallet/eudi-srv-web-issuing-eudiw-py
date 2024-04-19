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

ENDPOINT = main_pytest.ENDPOINT_route_formatter

# Route Formatter
# /formatter/cbor

payload={
       "version":"0.1",
        "country":"PT",
        "doctype":"eu.europa.ec.eudiw.pid.1",
        "device_publickey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFOElFUUJqNENaZDNZaWZYbmpxUmx0SUlpSkQ2VwpoWkV4RWtQVWdQUnkvWXd1ZUZzSk42UGVod3F0dlUxRnoyMG5XOVpjVUxLem9LaVdnaGlOeTM4NTBBPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t",
        "data":{
            "eu.europa.ec.eudiw.pid.1":{
                "family_name": "Garcia", 
                "given_name": "javier", 
                "birth_date": "1965-01-01", 
                "age_over_18": True, 
                "unique_id": "86b73c6c-7542-4923-a986-97d2cdf7f07a",
                "issuance_date": "2023-07-19",
                "expiry_date": "2023-08-19",
                "issuing_authority": "Bundes...",
                "issuing_country": "DE"
            }
        }
}

#           Tests WORKING

#   status_code == 200
def test_cbor_formatter_statusCode_200():

    response= requests.post(ENDPOINT, json=payload, verify=False)
    assert response.status_code == 200

#   return error code = 0, everything is working
def test_cbor_formatter_errorCode_0():

    response= requests.post(ENDPOINT, json=payload, verify=False)

    assert response.json()["error_code"] == 0

            
#                       Test of ERRORS
#   -> Error 401 - missing some mandatory fields - version / country / doctype / data
#   -> Empty mdoc in case the error code is different from 0
#   -> ERROR MESSAGE = Missing mandatory formatter fields.

#   Missing field: version
def test_cbor_formatter_error_401():

    payload_401_V={
        "country":"PT",
        "doctype": "org.iso.18013.5.1.mDL",
        "data": {
            "org.iso.18013.5.1": {
                "birth_date": "13-12-2000",
                "birth_place": "Lisboa",
                "document_number": "18923",
                "driving_privileges": [
                    {
                    "ExpiryDate": "2099-12-31",
                    "IssueDate": "2000-01-01",
                    "Restriction": [],
                    "Type": "B"
                    }
                ],
                "expiry_date": "Fri, 25 Aug 2023 10:15:53 GMT",
                "family_name": "Lima",
                "given_name": "João",
                "issue_date": "Wed, 26 Jul 2023 10:15:53 GMT",
                "issuing_authority": "IMTT-Lisboa",
                "issuing_country": "PT",
                "portrait": "/9j/4AAQSkZJRgABAQAAAQAB...",
                "un_distinguishing_sign": "P"
            }
        }
    }
    
    response= requests.post(ENDPOINT, json=payload_401_V, verify=False)
    
    assert response.json()["error_code"] == 401
    assert response.json()["error_message"] == "Missing mandatory formatter fields."
    assert response.json()["mdoc"] == ''


#   Missing field: country
def test_cbor_formatter_error_401_country():

    payload_401_C = {
        "version":"0.2",
        "doctype": "org.iso.18013.5.1.mDL",
        "data": {
            "org.iso.18013.5.1": {
                "birth_date": "13-12-2000",
                "birth_place": "Lisboa",
                "document_number": "18923",
                "driving_privileges": [
                    {
                    "ExpiryDate": "2099-12-31",
                    "IssueDate": "2000-01-01",
                    "Restriction": [],
                    "Type": "B"
                    }
                ],
                "expiry_date": "2024-12-31",
                "family_name": "Lima",
                "given_name": "João",
                "issue_date": "2024-01-01",
                "issuing_authority": "IMTT-Lisboa",
                "issuing_country": "PT",
                "portrait": "/9j/4AAQSkZJRgABAQAAAQAB...",
                "un_distinguishing_sign": "P"
            }
        }
    }
    
    response= requests.post(ENDPOINT, json=payload_401_C, verify=False)
    
    assert response.json()["error_code"] == 401
    assert response.json()["error_message"] == "Missing mandatory formatter fields."
    assert response.json()["mdoc"] == ''

#   Missing field: doctype
def test_cbor_formatter_error_401_doctype():

    payload_401_D = {
        "version":"0.2",
        "country":"PT",
        "data": {
            "org.iso.18013.5.1": {
                "birth_date": "13-12-2000",
                "birth_place": "Lisboa",
                "document_number": "18923",
                "driving_privileges": [
                    {
                    "ExpiryDate": "2099-12-31",
                    "IssueDate": "2000-01-01",
                    "Restriction": [],
                    "Type": "B"
                    }
                ],
                "expiry_date": "2024-12-31",
                "family_name": "Lima",
                "given_name": "João",
                "issue_date": "2024-01-01",
                "issuing_authority": "IMTT-Lisboa",
                "issuing_country": "PT",
                "portrait": "/9j/4AAQSkZJRgABAQAAAQAB...",
                "un_distinguishing_sign": "P"
            }
        }
    }
    
    response= requests.post(ENDPOINT, json=payload_401_D, verify=False)
    
    assert response.json()["error_code"] == 401
    assert response.json()["error_message"] == "Missing mandatory formatter fields."
    assert response.json()["mdoc"] == ''

#   expiry_date is not in the correct format
def test_cbor_formatter_error_306_date_formatting():

    payload_306_D = {
        "version":"0.2",
        "country":"PT",
        "device_publickey": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFOElFUUJqNENaZDNZaWZYbmpxUmx0SUlpSkQ2VwpoWkV4RWtQVWdQUnkvWXd1ZUZzSk42UGVod3F0dlUxRnoyMG5XOVpjVUxLem9LaVdnaGlOeTM4NTBBPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t",
        "data": {
            "org.iso.18013.5.1": {
                "birth_date": "13-12-2000",
                "birth_place": "Lisboa",
                "document_number": "18923",
                "driving_privileges": [
                    {
                    "ExpiryDate": "2099-12-31",
                    "IssueDate": "2000-01-01",
                    "Restriction": [],
                    "Type": "B"
                    }
                ],
                "expiry_date": "Fri, 25 Aug 2023 10:15:53 GMT",
                "family_name": "Lima",
                "given_name": "João",
                "issue_date": "2024-01-01",
                "issuing_authority": "IMTT-Lisboa",
                "issuing_country": "PT",
                "portrait": "/9j/4AAQSkZJRgABAQAAAQAB...",
                "un_distinguishing_sign": "P"
            }
        }
    }
    
    response= requests.post(ENDPOINT, json=payload_306_D, verify=False)
    
    assert response.json()["error_code"] == 306
    assert response.json()["error_message"] == "Date is not in the correct format. Should be YYYY-MM-DD."
    assert response.json()["mdoc"] == ''

#   Missing field: data
def test_cbor_formatter_error_401_data():

    payload_401_Data = {
        "version":"0.2",
        "country":"PT",
        "doctype": "org.iso.18013.5.1.mDL"
    }
    
    response= requests.post(ENDPOINT, json=payload_401_Data, verify=False)
    
    assert response.json()["error_code"] == 401
    assert response.json()["error_message"] == "Missing mandatory formatter fields."
    assert response.json()["mdoc"] == ''


#   "error_code": 13 -> wrong version
#   "version" != "o.2" -> wrong
def test_cbor_formatter_error_13():
    payload_13=	{   
    "version":"error",
    "country":"PT",
    "doctype":"eu.europa.ec.eudiw.pid.1",
    "device_publickey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFOElFUUJqNENaZDNZaWZYbmpxUmx0SUlpSkQ2VwpoWkV4RWtQVWdQUnkvWXd1ZUZzSk42UGVod3F0dlUxRnoyMG5XOVpjVUxLem9LaVdnaGlOeTM4NTBBPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t",
    "data":{
        "eu.europa.ec.eudiw.pid.1":{
            "family_name": "Garcia", 
            "given_name": "javier", 
            "birth_date": "1965-01-01", 
            "age_over_18": True, 
            "unique_id": "86b73c6c-7542-4923-a986-97d2cdf7f07a",
            "issuance_date": "2023-07-19",
            "expiry_date": "2023-08-19",
            "issuing_authority": "Bundes...",
            "issuing_country": "DE"
        }
    }
}

    response= requests.post(ENDPOINT, json=payload_13, verify=False)
    
    assert response.json()["error_code"] == 13
    assert response.json()["error_message"] == "Version is not supported."
    assert response.json()["mdoc"] == ''


#   "error_code": 102 -> unsupported country introduced
#   "country" != CW / PT / EE / CZ -> error 102

def test_cbor_formatter_error_102():
    payload_102={   
    "version":"0.1",
    "country":"err",
    "doctype":"eu.europa.ec.eudiw.pid.1",
    "device_publickey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFOElFUUJqNENaZDNZaWZYbmpxUmx0SUlpSkQ2VwpoWkV4RWtQVWdQUnkvWXd1ZUZzSk42UGVod3F0dlUxRnoyMG5XOVpjVUxLem9LaVdnaGlOeTM4NTBBPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t",
    "data":{
        "eu.europa.ec.eudiw.pid.1":{
            "family_name": "Garcia", 
            "given_name": "javier", 
            "birth_date": "1965-01-01", 
            "age_over_18": True, 
            "unique_id": "86b73c6c-7542-4923-a986-97d2cdf7f07a",
            "issuance_date": "2023-07-19",
            "expiry_date": "2023-08-19",
            "issuing_authority": "Bundes...",
            "issuing_country": "DE"
        }
    }
}

    response= requests.post(ENDPOINT, json=payload_102, verify=False)
    
    assert response.json()["error_code"] == 102
    assert response.json()["error_message"] == "Country is not supported."
    assert response.json()["mdoc"] == ''





