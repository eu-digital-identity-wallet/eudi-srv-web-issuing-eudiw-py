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
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This config_service.py contains configuration data for the PID Issuer Web service. 

NOTE: You should only change it if you understand what you're doing.
"""

import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
import os


class ConfService:
    # ------------------------------------------------------------------------------------------------
    # PID issuer service URL
    # service_url = "https://preprod.issuer.eudiw.dev:4443/"
    service_url = os.getenv("SERVICE_URL", "https://issuer.eudiw.dev/")
    # service_url = "https://127.0.0.1:5000/"
    # service_url = os.getenv("SERVICE_URL","https://dev.issuer.eudiw.dev/")

    wallet_test_url = "https://tester.issuer.eudiw.dev/"

    revocation_service_url = "https://issuer.eudiw.dev/token_status_list/take"

    # ---------------------------------------------------------------------------
    trusted_CAs_path = "/etc/eudiw/pid-issuer/cert/"

    # ------------------------------------------------------------------------------------------------
    # eIDAS Node base href (used in lightrequest)
    eidasnode_url = os.getenv(
        "EIDAS_NODE_URL", "https://preprod.issuer.eudiw.dev/EidasNode/"
    )

    # Number of Tries for login in eidas node
    eidasnode_retry = 3

    # openid endpoint in case of eidas node login error
    eidasnode_openid_error_endpoint = service_url + "error_redirect"

    # eIDAS node connector endpoint (for lightrequest)
    eidasnode_lightToken_connectorEndpoint = (
        service_url + "EidasNode/SpecificConnectorRequest"
    )

    # eIDAS node PID attributes
    eidasnode_pid_attributes = ["CurrentFamilyName", "CurrentGivenName", "DateOfBirth"]

    # ------------------------------------------------------------------------------------------------
    # OpenID endpoints

    OpenID_first_endpoint = service_url + "verify/user"
    # OpenID_first_endpoint = "https://preprod.issuer.eudiw.dev:4443/verify/user"
    # OpenID_first_endpoint = "https://127.0.0.1:5000/verify/user"

    # Deferred endpoint expiry time (minutes)
    deffered_expiry = 60

    # transaction code expiry time (minutes)
    tx_code_expiry = 60

    # Form data expiry time (minutes)
    form_expiry = 60

    # ------------------------------------------------------------------------------------------------
    # PID namespace
    pid_namespace = "eu.europa.ec.eudi.pid.1"

    # PID doctype
    pid_doctype = "eu.europa.ec.eudi.pid.1"

    # PID validity in days
    pid_validity = 90

    # PID issuing Authority
    pid_issuing_authority = "Test PID issuer"

    # PID Organization ID
    pid_organization_id = "EUDI Wallet Reference Implementation"

    # mDL namespace
    mdl_namespace = "org.iso.18013.5.1"

    # mDLdoctype
    mdl_doctype = "org.iso.18013.5.1.mDL"

    # mDL validity in days
    mdl_validity = 7

    # MDL issuing Authority
    mdl_issuing_authority = "Test MDL issuer"

    # QEAA namespace
    qeaa_namespace = "eu.europa.ec.eudiw.qeaa.1"

    # QEAA validity in days
    qeaa_validity = 90

    # QEAA issuing Authority
    qeaa_issuing_authority = "Test QEAA issuer"

    # QEAA doctype
    qeaa_doctype = "eu.europa.ec.eudiw.qeaa.1"

    # OIDC4VC URL for initial page
    oidc = service_url + ".well-known/openid-credential-issuer"
    # oidc = "https://preprod.issuer.eudiw.dev:4443/.well-known/openid-credential-issuer"

    # ------------------------------------------------------------------------------------------------
    # current version
    current_version = "0.6"

    # IANA registered claims
    Registered_claims = {
        "birth_date": "birthdate",
        "age_over_18": "age_equal_or_over.18",
        "family_name_birth": "birth_family_name",
        "given_name_birth": "birth_given_name",
        "nationality": "nationalities",
        "birth_place": "place_of_birth.locality",
        "birth_country": "place_of_birth.country",
        "birth_state": "place_of_birth.region",
        "birth_city": "place_of_birth.locality",
        "resident_address": "address.formatted",
        "resident_country": "address.country",
        "resident_state": "address.region",
        "resident_city": "address.locality",
        "resident_postal_code": "address.postal_code",
        "resident_street": "address.street_address",
        "resident_house_number": "address.house_number",
    }
    # route /pid/getpid response fields per API version
    getpid_or_mdl_response_field = {
        "0.1": [
            "mdoc",
            "mdoc_nonce",
            "mdoc_authTag",
            "mdoc_ciphertextPubKey",
            "sd_jwt",
            "error",
            "error_str",
        ],  # doesn't cipher the returned mdoc
        "0.2": [
            "mdoc",
            "mdoc_nonce",
            "mdoc_authTag",
            "mdoc_ciphertextPubKey",
            "sd_jwt",
            "error",
            "error_str",
        ],
        "0.3": [
            "mdoc",
            "nonce",
            "authTag",
            "ciphertextPubKey",
            "sd_jwt",
            "error",
            "error_str",
        ],
        "0.4": [
            "mdoc",
            "nonce",
            "authTag",
            "ciphertextPubKey",
            "sd_jwt",
            "error",
            "error_str",
        ],
        "0.5": [
            "mdoc",
            "nonce",
            "authTag",
            "ciphertextPubKey",
            "sd_jwt",
            "error",
            "error_str",
        ],
        "0.6": [
            "mdoc",
            "nonce",
            "authTag",
            "ciphertextPubKey",
            "sd_jwt",
            "error",
            "error_str",
        ],
    }

    document_mappings = {
        "eu.europa.ec.eudi.pid.1": {
            "fields": ["CurrentGivenName", "CurrentFamilyName", "DateOfBirth"],
            "formatting_functions": {
                "mso_mdoc": {"formatting_function": "pid_mdoc"},
                "vc+sd-jwt": {"formatting_function": "pid_sd_jwt"},
            },
        },
        "eu.europa.ec.eudiw.qeaa.1": {
            "formatting_functions": {
                "mso_mdoc": {"formatting_function": "qeaa_18_mdoc"},
                "vc+sd-jwt": {"formatting_function": "qeaa_18_sd_jwt"},
            },
        },
        "eu.europa.ec.eudi.pseudonym.1": {
            "fields": ["user_pseudonym"],
            "formatting_functions": {
                "mso_mdoc": {"formatting_function": "pseudonym_mdoc"},
                "vc+sd-jwt": {"formatting_function": "pseudonym_mdoc_sd_jwt"},
            },
        },
        "org.iso.18013.5.1.mDL": {
            "fields": [
                "CurrentGivenName",
                "CurrentFamilyName",
                "DateOfBirth",
                "IssuingAuthority",
                "DocumentNumber",
                "Portrait",
                "DrivingPrivileges",
            ],
            "formatting_functions": {
                "mso_mdoc": {"formatting_function": "mdl_mdoc"},
                "vc+sd-jwt": {"formatting_function": "mdl_sd_jwt"},
            },
        },
    }

    common_name = {
        "eu.europa.ec.eudi.pid.1": "National ID",
        "org.iso.18013.5.1.mDL": "Driving License",
        "eu.europa.ec.eudi.pseudonym.age_over_18.1": "Age Verification ",
    }

    config_doctype = {
        "eu.europa.ec.eudi.pid.1": {
            "issuing_authority": pid_issuing_authority,
            "organization_id": pid_organization_id,
            "validity": pid_validity,
            "organization_name": pid_issuing_authority,
            "namespace": pid_namespace,
        },
        "eu.europa.ec.eudiw.qeaa.1": {
            "issuing_authority": qeaa_issuing_authority,
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": qeaa_issuing_authority,
            "namespace": qeaa_namespace,
        },
        "org.iso.18013.5.1.mDL": {
            "issuing_authority": mdl_issuing_authority,
            "organization_id": pid_organization_id,
            "validity": mdl_validity,
            "organization_name": mdl_issuing_authority,
            "namespace": mdl_namespace,
        },
        "eu.europa.ec.eudi.pseudonym.age_over_18.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.pseudonym.age_over_18.1",
        },
        "eu.europa.ec.eudi.pseudonym.age_over_18.deferred_endpoint": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.pseudonym.age_over_18.deferred_endpoint",
        },
        "eu.europa.ec.eudi.loyalty.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.loyalty.1",
        },
        "teste": {
            "issuing_authority": "Test EUDIW Issuer",
            "organization_id": pid_organization_id,
            "validity": pid_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "teste",
        },
        "org.iso.23220.2.photoid.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "org.iso.23220.photoid.1",
        },
        "eu.europa.ec.eudi.por.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.por.1",
        },
        "eu.europa.ec.eudi.iban.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.iban.1",
            "credential_type": "IBAN",
        },
        "eu.europa.ec.eudi.hiid.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.hiid.1",
        },
        "eu.europa.ec.eudi.tax.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.tax.1",
            "credential_type": "Tax Number",
        },
        "eu.europa.ec.eudi.msisdn.1": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "eu.europa.ec.eudi.msisdn.1",
            "credential_type": "MSISDN",
        },
        "org.iso.18013.5.1.reservation": {
            "issuing_authority": "Test QEAA issuer",
            "organization_id": pid_organization_id,
            "validity": qeaa_validity,
            "organization_name": "Test QEAA issuer",
            "namespace": "org.iso.18013.5.reservation.1",
        }
    }

    auth_method_supported_credencials = {
        "PID_login": [
            "eu.europa.ec.eudi.pseudonym_over18_mdoc",
            "eu.europa.ec.eudi.pseudonym_over18_mdoc_deferred_endpoint",
            "eu.europa.ec.eudi.por_mdoc",
            "eu.europa.ec.eudi.iban_mdoc",
            "eu.europa.ec.eudi.hiid_mdoc",
            "eu.europa.ec.eudi.tax_mdoc",
            "eu.europa.ec.eudi.msisdn_mdoc",
        ],
        "country_selection": [
            "eu.europa.ec.eudi.loyalty_mdoc",
            "eu.europa.ec.eudi.mdl_mdoc",
            "eu.europa.ec.eudi.pid_jwt_vc_json",
            "eu.europa.ec.eudi.pid_mdoc",
            "eu.europa.ec.eudi.pseudonym_over18_mdoc",
            "eu.europa.ec.eudi.pseudonym_over18_mdoc_deferred_endpoint",
            "eu.europa.ec.eudi.photoid",
            "eu.europa.ec.eudi.por_mdoc",
            "eu.europa.ec.eudi.iban_mdoc",
            "eu.europa.ec.eudi.hiid_mdoc",
            "eu.europa.ec.eudi.tax_mdoc",
            "eu.europa.ec.eudi.msisdn_mdoc",
            "eu.europa.ec.eudi.ehic_mdoc",
        ],
    }

    # eudi_openid4vp_url = "dev.verifier-backend.eudiw.dev"
    dynamic_presentation_url = os.getenv(
        "DYNAMIC_PRESENTATION_URL",
        "https://verifier-backend.eudiw.dev/ui/presentations/",
    )
    dynamic_issuing = {
        "eu.europa.ec.eudi.pseudonym_over18_mdoc": {
            "eu.europa.ec.eudi.pid.1": {"eu.europa.ec.eudi.pid.1": ["age_over_18"]}
        },
        "eu.europa.ec.eudi.pseudonym_over18_mdoc_deferred_endpoint": {
            "eu.europa.ec.eudi.pid.1": {"eu.europa.ec.eudi.pid.1": ["age_over_18"]}
        },
        "eu.europa.ec.eudi.por_mdoc": {
            "eu.europa.ec.eudi.pid.1": {
                "eu.europa.ec.eudi.pid.1": [
                    "family_name",
                    "given_name",
                    "birth_date",
                    "age_over_18",
                    "issuing_authority",
                    "issuing_country",
                ]
            }
        },
        "eu.europa.ec.eudi.iban_mdoc": {
            "eu.europa.ec.eudi.pid.1": {
                "eu.europa.ec.eudi.pid.1": [
                    "family_name",
                    "given_name",
                    "birth_date",
                    "age_over_18",
                    "issuing_authority",
                    "issuing_country",
                ]
            }
        },
        "eu.europa.ec.eudi.hiid_mdoc": {
            "eu.europa.ec.eudi.pid.1": {
                "eu.europa.ec.eudi.pid.1": [
                    "family_name",
                    "given_name",
                    "birth_date",
                    "age_over_18",
                    "issuing_authority",
                    "issuing_country",
                ]
            }
        },
        "eu.europa.ec.eudi.tax_mdoc": {
            "eu.europa.ec.eudi.pid.1": {
                "eu.europa.ec.eudi.pid.1": [
                    "family_name",
                    "given_name",
                    "birth_date",
                    "age_over_18",
                    "issuing_authority",
                    "issuing_country",
                ]
            }
        },
        "eu.europa.ec.eudi.msisdn_mdoc": {
            "eu.europa.ec.eudi.pid.1": {
                "eu.europa.ec.eudi.pid.1": [
                    "family_name",
                    "given_name",
                    "birth_date",
                    "age_over_18",
                    "issuing_authority",
                    "issuing_country",
                ]
            }
        },
    }

    # Supported certificate algorithms and curves
    cert_algo_list = {"ecdsa-with-SHA256": ["secp256r1"]}

    # ------------------------------------------------------------------------------------------------
    # Error list (error number, error string)
    error_list = {
        "-1": "Error undefined. Please contact PID Provider backend support.",
        "0": "No error.",
        "11": "Query with no returnURL.",
        "12": "Query with no version.",
        "13": "Version is not supported.",
        "14": "URL not well formed.",
        "15": "Query with no device_publickey",
        "16": "The device_publickey is not in the correct format",
        "101": "Missing mandatory pid/getpid fields.",
        "102": "Country is not supported.",
        "103": "Certificate not correctly encoded.",
        "104": "Certificate algorithm or curve not supported.",
        "301": "Missing mandatory lightrequest eidasnode fields.",
        "302": "Missing mandatory lightresponse eidasnode fields.",
        "303": "Error obtaining attributes.",
        "304": "PID attribute(s) missing.",
        "305": "Certificate not available.",
        "306": "Date is not in the correct format. Should be YYYY-MM-DD.",
        "401": "Missing mandatory formatter fields.",
        "501": "Missing mandatory IdP fields",
    }

    # ------------------------------------------------------------------------------------------------
    # Sample data

    sample_data = {
        "family_name": "Sample_Family_Name",
        "given_name": "Sample_Given_name",
        "birth_date": "1111-11-11",
        "document_number": "document_number",
        "portrait": "_9j_4AAQSkZJRgABAQIAJQAlAAD_4QBiRXhpZgAATU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAMAAAITAAMAAAABAAEAAAAAAAAAAAAlAAAAAQAAACUAAAAB_9sAQwADAgICAgIDAgICAwMDAwQGBAQEBAQIBgYFBgkICgoJCAkJCgwPDAoLDgsJCQ0RDQ4PEBAREAoMEhMSEBMPEBAQ_8AACwgBsQFoAQERAP_EAB4AAQABBAMBAQAAAAAAAAAAAAABAgcICQMEBgoF_8QASRAAAQMDAwMCBQAHBAYGCwAAAQACAwQFEQYHEgghMQlBEyJRYXEUIzJCUoGRFWJyshgzOHWCwhZDobHR8CQlJjQ1REaFs8PU_9oACAEBAAA_ANqL_ZSPClERERERERERERERERERERERERERERUv9vypHhSiIiIiIiIi4Q93_k5I_Psvy7_qiw6Vtk961LfaG1W-mbzmqq2pZTwsbj9oveQGjse5IH3Vir16hnRpYq6S31u_thfNE7DjSRVNXFn7SQxPa4fgrqD1J-iR_wCxvxbj_wDa7gP_ANC_E1f6pPRhpaifUUu51VqCpa3Io7RZqt8z_wAOljZEP-J4Vuz60HS04fq9GbnfztND_wD2LyJ9bDa4ainp27M6pdYW5-BXfp8H6U_s0_NT44M7kj_Wu8L8mq9bvTUdZPHQ9Pd1nphK4QSS6jjje6MeHOYKd3B31bycB7OXYqfW30T-kUYpNi72ad7miqfLeImvYD5MYbE4Px93NVwZ_WQ6WYqlsAse4UzBHHI-aC1Uvw2lzWuMeX1IcXMyWO-XBcxxa4tw53vtLeqP0YanjgbNunPY6mVveC6WesiLHfwue2N0Y_Iesk9F670luLYabVWhtTW--WirGYauhnbLE7_ibnv9shejRERERERERERUv9vypHhSiIiIiIijIX5V6vtu07bKq9Xy501voKCB9TU1NRK2KGGJgy973uOGtaO5JIA8Ela5t5vWY0pp7UE9j2W0B_0opaaV0ZutxqX00VRxdjMUQHMtJ_ZLi0keWrEDfD1N-pzeCpMNs1M3RVoc3j-gWF5j5fd8zsyH-RasbNS7n7k6ypP7P1buHqS90jZPitguN1nqYw_-INkcRnv5XmCSexPhEySMEnAQEjwSnJx8uP8AVTyd_Ef6pyd3-Y9_Pfyge8Yw89vHfwo5O-pVydpuoPenZKsM-1m4d3sTXSfEkpoJS6CQ_V0Tg5hP5C2JdNnrERzPp9MdS1mFO48YxqK0U5c0Euxymp25-UDuXMz_AIXLZbpTWGntb2Ci1TpC_Ul5s9yiZNSV1FM2aCVjs9w9p748HuDkY_aBC_fyFKIiIiIiIiKl_t-VI8KURERERRkfVdK43KitlHLcLhcKekpIGfFlmnlDGMZ_E5xIDR9z2WIPUJ6oPTxs02W1aSvTNf6gAcBTWWpa-lheOwEtSAYwM-zC4_XitPu8PUzvPvdqC63vWuvr1LT3Ob4ptcddIyiiZz5RxthDuBDfqRlWlyfGShJPknsiIiIiIiZP1VTXuJ7uJ8nz9fKvv0zdXe7_AEwaghuGjL1UVFikmDq6xVUhdSVLB-3huPkecftNwR75W7jpv6v9nOp2xCs0BqNkd7hjY64WKsIiraJ3FvLLCf1rORAD4-QPIAlrsht9GOLhnPnwqh4UoiIiIiIipf7flSPClERERFB8K12_m_m33Ttt_Xbg7hXcU9NSjFNSxvBqK6Y_sxRM8kl2AfZoBJ-UFaZOsT1B9fdVdJT6Uo7QNK6UpZnSuoYKovfWOPYGd_ytOG_ugYysRnPz4Kjk7OeRz9cqEREREREREU83YI5HBxkZ8r9vSurNS6HvtLqXSN7rbNdaJwkgq6SZ0U0Z98EHJB75Hus_Omz1dtyNJV9Hp7qApRqqxktjddKSJkdxp2-73BoDJh3OR8rhjsVte2z3R0JvFouh17ttqilvlkr2coqmne5pYWn5mPY4B0cjT-0x7Q4HsQAvYZb9VUiIiIiIipf7flSPClERERF4vdXdLR-zWgLzuVr28C32ayUxnne7HKR2QGRRtP7Ukji1jWeSXADHcrQj1k9WN16rtxo9WSWR1ms1ugNLbaAzukw3k4mR_fjzcCMhoAGBhY85I8EoiIiIiIiIiIiZOMZU8nYI5HBOSMq-nS71abldK-sf7b0VXGostdLH_a1kmcTTVjB5IHlkgGeLx3GRnK3v9P3UJt51Jbe0e4e3V1E8M2I62ieQKi3VAALoZmeWuwcg-HN4ubkOBN0g5rhkFVIiIiIiKl_t-VI8KURERF1pKhkeXukwG-SQcAfnOMDySfZaS_U96vnb27iO2m0TdXS6K0hUPY-SneTDX1wy18vbs5rAXNaT7lx-iwU5HOcnP1RERERERERERERE5H6lXn6Yep3X_S3uFHrjRtQailnaIbpapXEQ3CnySQ7HhwJPF3kZOFvq6c-oHRPUttbQboaFndHT1DjTV1HKQZrfWMDTJBJjsDhzHA-C17XeCALroiIiIiKl_t-VI8KURERFrd9UPreOgbTV9O21l1lh1LdIf_aC4U7-JoqRzDmna7yJXjHI-zPl8uHHT2ZHZJ8E-VSiIiIiIiIiIiIiIp5OHhx_qspegrq6uvSzueyS4zSz6K1G-OmvlKCeMBzgVTR_EweR7sJ_hC36W250d2oKa522qZU0tZEyeGVjgQ-N4Ba4Y7EEEH-a7yIiIiIqX-35UjwpRERF1KqshoKeWsq52xQQsdJJI92A1gBJJz2wACST9F81fUHraPcXfLXWuKOsdWU13vlZUU0_f9ZAJSI3j6Dg1uPsrbIiIiIiIiIiIiIiIiqD3e3t2W5n0jepiu3J23r9kNVVj57toWJklrnleC6W2PPFsZ9_1TsN_wALox4C2GoiIiIipf7flSPClEREWIXqi7nXvbDpJv79P1bqWr1VXU2nDO1-HMhna90wb75dFDI37CRx8gLQq4nx7fRQiIiIiIiIiIiIiIiIskugzqEh6dOoexasulVwsN2YbPeXPGGx00zwBIT7CNwZJgecFfQZSVcVZBHVU0okgmjbJG9juTS0jIcD75BBXaRERERUv9vypHhSiIiLU960u7sNZdNE7JUTnl1vEl-uAz8vKRpjhbjxkN59_wC-tXCIiIiIiIiIiIiIiIiKQ5w8OI9_K3--nJv1Qb5dNFha74kd60bHFpy6xySc3ySQwsMdQCe_GVhae_hwkb4asqkREREVL_b8qR4UoiIi0ber-T_pcTDPjT9v_wArlhAiIiIiIiIiIiIiIiIiLZF6K2sqm3bua60BLWsbRXqwxXFkLnY-JPTzhgLR9fhzSE_YLcKCD4KlERERUv8Ab8qR4UoiIi0besAT_pczdv8A6ft_-VywgRERERERERERERERERFkF0Kbnt2m6p9Bamq68UlBUXFtrrpSwvAgqmmEjiO-fmAz7eV9EDMeGuOCBj8fUELmREREVL_b8qR4UoiIi0besAR_pcz-f_gFv_yuWECIiIiIiIiIiIiIiIiIuSnnnp5o56eZ8UsTg-N7HFrmuB7EEeCPqvpd6fNbU24uymiNb0tQ6Vl4sVJUF7hhxcY2h-e5-bkDkexJHsrjoiIiKl_t-VI8KURERaNvV_8A9rmb_cFD_lcsIERERERERERERERERERS3yt43pBatOoekdljfE9h0xqS4Wscz2c14jqwQP3R_wClHt9QSs4URERFS_2_KkeFKIiItG_rAf7XE3-4Lf8A5XLB9EREREREREREREREREUt8ra56I2pbu-3bqaPkqy61001rucFO5o4x1ErZ45XNI8l7IYgQfHwxj95bS0RERFS_wBvypHhSiIiLRt6wP8Atcz_AO4Lf_lcsIERERERERERERERERERFnr6P-5dZo_qRr9BTOlFHrWzTQFpIDG1FMfixyHIySGiZgwcD4hJBwt17Hl2Sexb7LkRERFS_wBvypHhSiIiLRr6vzg7q7qG_Sw2_wDyuWEKIiIiIiIiIiIiIiIiIivn0WsrH9V21kdDK5lQdSUgif27Hlj7_ugjB8ecr6MYuOMg5JXIiIiKl_t-VI8KURERaPPWAs90o-rJ1yrKb4dJcNP0MlI_OfitZljj9sODv6LBpEREREREREREREREREUs7nus7PR_0db9RdU1XfK0P-PprTNXcKZjQCHufJDTkkEfuiY4wQeWM5GVu2jAGcBcqIiIqX-35UjwpRERFqP9aPb7UrtYaI3WdC-SwutxsImAbiOpEks7Wu7_ALzXOI9vkJ-gWsh3lQiIiIiIiIiIiIiIiIiePC2ieiDSRS3_AHZrJG_rIqO0RNz44vdUk_z-Qf1W2PAHgBSiIiKl_t-VI8KURERWL6zNoX759NeudvKWNz7jVW8VttDSGn9LpntnhZyPYB74-DneQyRxHcBfOpU00tLNLS1EL4pYnFj2PbhzXNJBBHsRggj6hdZERERERERERERERERFLO57rc_6RPT7rLanbbUe5etKCe3P18-hNto5QGyspIGyubM8cst-IZsNaW8uLWu8Pw3YQiIiIqX-35UjwpRERFQ4E9wF85_Wnt8NsOqLcPTA5_o5vU1fAX45cKhxmyAA0EfOQrFIiIiIiIiIiIiIiIiIsjegzYSk6g-o7T-kr1QipsNuD7vd2ui5xyU0OCI3jk3DZH8WE_3sL6EaKip7fTx0lJTxwwQMEcUcbA1kbAMBrQOwAHsF2kRERFS_2_KkeFKIiIi1k-sXsTopmhbX1B0VK-n1I250tkqnxn9XUwvjmcC8e7gWAAjvjstRqIiIiIiIiIiIiIiIilvlbjfRy2Obpba6_wC-N7tL4rtq2sdbrbLKzBFsgwS6M8eY-JOXB2SQ4QRkeDy2NIiIiIqX-35UjwpREREWC3rE9-keFzB41Zbs_YfBqP8AxC0gIiIiIiIiIiIiIiIiLnhiknkZFDGXyvcGMa1uSSTjGPckkAL6Ydi9GUG3uzuitFW6mZTwWeyUdKyMBw_ZhAcfm-YuJJJJ-quAiIiIipf7flSPClERERYl-qHpm36i6K9d1FYzMtlkt1ypHgf6uVtXDGSfryjke37cs-y0FoiIiIiIiIiIiIiIiK4Ow9hfqbenQ1iihfUPrL_QRtibL8IuAnaXfNxcBgAlfS5R05p4Y4md2MYG-AM4XbRERERQfClERERFb3ffbOi3k2e1jtfXSNjZqW01FCyYjPwZXsJilx_ceI3_AH4r5r77Y67TF_uenbxTiGutVTNRVUJIPw54nFj2_fi9p7-4H3X5KIiIiIiIiIiIiIiIr9dDFrmuvVttfTR0z5gb_A9_BpdxY0OcSePsMd19FYYAckDKrRERERQfClERERFQWM847LS96q3STHtNrob6aPa5untZ1z23Cla04orgWhxdk_uSnk4f3g77LX2iIiIiIiIiIiIiIiLMn0pdNVd-6wtP18dHLNTWW319dUzMYS2AfAc1hcT7F7w38kLe991KIiIiKD4UoiIiIitl1B7PWDfzZ7U21WoImGG-0T46ebGTTVbfnhmb_eY9rHAe4aQfK-dndXarWGzeuLpoDXVofQ3S1zGN7T-zKzlhsjCezmOHcH-q8UiIiIiIiIiIiIiIi28-jVsXd9M6Q1PvjqG200LNVCG22OQg_pDqWCWQ1Du4-WN8oiDcH5jCSewbnZeiIiIiKD4UoiIiIipLW-cDP1WM3Wt0d6V6p9vKqCKjp6LWtuhfNZLqWcXte1ufgSEd3Rv_AGT9CQR4WhbXOhdV7dalrtI61sFVaLvbZnQVFNUx8CHtPzY7fMMjsQfBC82iIiIiIiIiIiIiniVeDpp6dNY9S26FDt5o63Okg-Iye7V3Lgyhow4fEkc8hwacZDflcS7AHIEr6ItDaMsW32kbNofTVFHS2uyUkVFSQsYGhkbGtaOw7A4BP816VEREREVLlUiIiIiIoIGMYC1_-rxsW7XGxdHutp-0RyXLQ9aJa98UQ-K-glAjc4kDJEbxGe_YNLz7BaWfooREREREREREREWXPQP0TWzq-uOrTqXUlysVo05TU_GroIWPLqmV5wwh4wRwY8nHcdvqtvvTD0nbYdK2k59N6Ahq6mpuErJ7ldKx4dU1r2tIbkNHFrACSGtwASSr48W-eI_opRERERFS_wBlI8KURERERFbLqVsdZqTp13S0_bKX49dc9F3ukp4g3JfNJQzNjAH15FuF81JZjAIGRn-ePbHsuJEREREREREREU4JOMZJ-i33emLs6_aTpS0_UV1G6C76xml1JWtkbgtbNxbC0Z74-BHCeJ8Oc_6lZcYClERERERUv9vypHhSiIiIiIuGeJskT43NBDuxBGc5-q-fT1CNjrPsJ1Mag0tpkBtmurI71RQj_wCXZPnlCPbDXB2PoCPosaERERERERERERXS6Z9tZd2N-ND6CZQ_pUN0vNM2qjdEXsNO14fKHY8NMbXD7ZX0l0dHS0VLFQUcbIqeCMRxxsHZrQMAD6DHsu2iIiIiIipd5VSIiIiIiKl4JHZakvWk23qKfWOht1aWif8AAuFFPZ6uYMOBNG7mxpI9-D8DPY4K1juUIiIiIiIiIiKWraT6NOw1PUyao6h73SB76Od2nbKHju2Qsa-qlwfB4uiZn7ye4W10AY8KUREREREUHwpRERERERQfCtpv1svpDf7a29bWaxpA-hu1M5kE7Wgy0VQ1v6qeP-F7H4IJ7HBa7IJB-cjcHQ2ottNZ3nQOrrf-h3ixVj6KqiI8PaT3b_E09iCfYheaREREREREREX6thsVx1LeqDTtlo31NwuVVHR0sDG4dLK9wa1v5LnAfQdyvo86Y9nLfsLsZo_a6kDDNZrcxtbM1hb8ask_W1EmD7Oke4_YYH7qut4ClERERERFB8KURERERERUPaMf9q0K-qjRUVF1lapdQwxxuqqOhnqOAA5SfBA5Ox5PFre5WIiIiIiIiIiIizw9I7Y-TcPfup3JuNGySy6EpvjfrO7X1s7XMhb_ACDXv_4R9Vu0Y1oaAGgZyfH18rkRERERERFB8KURERERERUv_ZXz_wDqaVUtR1na9bIf9Q-kiZn-EU0axZRERERERERFLfK3VejltxX6V6crvrq4xiNutb26aiBHd9LSj4HxPtmUTAD-4D7rPweApRERERERFB8KURERERERUuWgD1NKSak6ztePnaR-kPpZWZ_hNOwD_KsWERERERERERSzOe2P5r6CPTe1nYdYdHugWWGl_RW2WkfaaqI4z-lQv_WPwPZznF_fueWfdZPDwpRERERERFB8KURERERERQfC0V-rdaZbb1gXKpdG4suFkoKhri3AJw5uAffHEZ_KwsRERERERERFLW8jhbwPSF0ZeNL9KEt-uTWti1XqSsulE0F2RA1kVOC4FvYmSnkPbII4n3KzmHhSiIiIiIiKD4UoiIiIiIih3L2AK1uesD073DWOhrPv5pqkM8-kmmivLGNy4UEjsxz9jjDHkBxAzxeD4BWnx_Y9lCIiIiIiIiAE-AvZbVbc3zdncKw7c6ZhL7jqCsjpISA1wY1x-aQ5LQA0Bzjlzezce6-krbLQdn2v2909t3p-PhbtN22ntlODyyY4WBuXF3ck4Jz9yvWIiIiIiIiKk9m91UiIiIiIiIvyNQWW1als9dp6-UEVbbrnBLSVdPMzMcsUjC2RjgfGWkj-a-errJ6arn0y72XfRP6LUO0_VPNbp-rkaT-kUb3EtbyPZz4-7HD3wD7qwhGCoRERERERFysaScNHc4x9TnwAB7rbp6UHR3XaNtMfUxr-kkp7re4Hw6ft09O5j4KR5HKrfybyDpACGYwOB5ZcHgN2Vsj4jw3I98LkREREREREUO8KURERERERFxujBdkBv9PvlWK6t-lrSPVTttVaPvcjKK9UbXzWW6tj5voqotIHJo7ujPy8m5yQAW9wFoK3a2h1zstru5bdbgWV1BeLbIWOaPmjmZjLZYXjtJG4fMHDtg9w0gtb4VERERERFW1vI4wM59x5P0wFsY9OD0-nbmVUW9u9llqYNMUE7HWW0VVM-M3aQAOFQ5r2t5Uw5ANIyHu5AEBpzuGpqSnpYWQU8TI44wGsYxoDWgYwAB48D-i5lwzzfBjMjwQ0dj38D6rmBBGQpRERERERUuVSIiIiIiIijAVBjjznH8ljH1vdG2neq_b6aGgNDbtcWmNz7FdZmu4Oe05dTTFmXfDfhwyA4sc4O4u4lrtD2tdBam241Pc9F67sdVZr3Z5TT1VFURkOa5pGSHDIcO-Q4ZY5uHNJBbnzCIiIiIuwyB0rmxxMLnyENYGjJJzjx5yfYBbKPT-9NS5alr6bePqJ05PQWanl5WfTlbCY5q9zXYM1RG7Do48ggMe0OeByxxLCduNPSU1LDHTUsLI4omNZHG1oDWNHgADsAO2AudF1bhEJ6OaPxyaueP8AZH4VaIiIiIiKD4QeFKIiIiIiIiKkxtOcjOexWJXXL0O6b6qtKS3myCltmv7PD_6qub_ljq2gl36LUOaCSwjs1xBLCQ75hyadGWtdC6o261PcdFa209VWe-WyZ1PVUdUwtkicDnIPhwx3Dh8jm_M0kEFebREREXttsdo9w949U0-i9sdIVt_vFV-xDTsDWN7HLnyPIZG3AOXOcACOxW4Xo49MbQexX6Jrndea36y1q10dRCGwk0FqkDW4bE13eV4eXfrHNHgYazB5Z1NiYzw3_wA_-QFWiLp3OobSUM1S5pIY3OFXR1LKqmjqIs8XDK7KIiIiIiKD4QeFKIiIiIiIiIqTGwnJHdYzdXHRDtj1W2eSpu0LLJrOkpzBbL7TNPJuSHNZOwdpo8g9vLQ5xDgVpH376cN0um3WMujNzLCynlIzS19MXS0VczyHwykAkZyMENcMfM0ZVqkRF-9pbROrNcXKKyaM0vc75cJjxjpbdSSVEr_P7rAT7fRbD-nD0etYXusotT9RV5prNaXRxyiwW2V0lbLzbksnlDeEHAkAhpkLiHAOaAHO2f7VbN7Z7J6dZpbbDRtvsFC3HJtNCBJMck8pHkc5CMnu4nyV7oxsJyR7Y_kqkRF-de43SW2ZjScubxwps0TobdFER-x8o-4X6CIiIiIiKD4QeFKIiIiIiIiIi43MZ_C0kHOCPfOf-9eK3R2o0DvNpOo0XuLp6kvNpqSCIphng8HLZGOxlrh7YWqff30e917Dfam47AVtv1RZJBzgt1dWx0tbCP4echEcn55NKsHffTa61tPUba2v2IuErC7iGUNyoa2TH14QTOd_2L0GjvSy6ydUy0Ir9urdp2lrT3qrxeKdn6O36viidJNn-6Iy77LL_an0X9urLURXHeDcm5akDTGXUFppv0GD_Vu5tdI5z5HjmQWubwOAAR3Kz_0FtbtxtfQOoNA6Ls9hhkH600dGyF0p793uABd5Pn6r1oA84GVJa0jBaMeMYUoiIutVBrgIyc8jlc7I2xtDGjAHYKpERERERFS_2VSIiIiIiIiIoyPqqeQHknzjv2yfosMerP1Ldr-m67zaFsloqNXa0pJWsrbfE91NBQsc3kHSTFjg52MYY1pJzklowHYEW31O-qPWe5tulr7pSGy3K4w07rHQUkbIy172scyN0hB5HmOPxHgZxlwGVmlon1Dat9caPU2i77bqP9NjoKesvVAaKOsncSGmLk4S_NxyOTGj5mtPFxIWVO3m_Wgdw6iO2W2udS18jMtpKgcXH7NPh5_C89v31S6F6cG09fuhbrrQ2SsIihukFO-eJ0zskR8WNc4HDfcYXk9p_UI6Wt4LrFZNP7iQUFzmkbBDT3WN1G6aR_Li2P4oaXE474BA7K7Otd7dr9t7tb7Nr3Wtt09U3iRsFA64yNhjqZXfstY4kNJ-2c_de6jmbIxpjfyyAflPYg-D79vwVzoiIqSTnHsfP2XWj5SzlxGGtHFq7Q8KUREREREUHwpRERERERERUOe0ZyccV0prrRR1LaH9JidVvYZGU4lAkcwEAuAzkgZ84UVdBHXiN8kkzPhP5sDJC0h31OPP-HwrNdQ_R1sn1L0Ubdw9Mxi60w5U91ocQVjPlxxdI0ZkZ_dcMfZYfV3QppDYrU9tr6WzsFNDHIyKseBUMrHcg6N7zICWSMyRluMg9uQ-Zemm0YZHucyjfLG45A98E5Bz-e671m0XdLTXNuVrlfTzMla6J0bhlp5ec_w_fysgyNE9Quga_afeK00VYKyE07hI9g-K8tLRLA4jkyUcsg8QR9Fp561uirVXSdq1tRHI-7aLvNRP_Y9wawh0QD3EU84ycPEfD5s4d3cOP7Kyz6It_wDbrqy2nl6P-peKnuFwgphDYq2Zz3T1ELIwQRMQ4MqI8AtJdykJwR2Oe3sr1Kbj9Bu8svSt1TX9120Y94n09qh8j5P0allLhFK4nlJ8BxaWmMjMLmuPJzBk7N7bdKO60cFxttdFWU1UxssE1O8PjkjcAWua4EhwI75HbAPgr9FERcbwS1wB8qpjA1vHAVSIiIiIiIoPhSiIiIiIiIoz3wsaetTrD050nbdRXiWjbdtVXxz6axWwkiN8gALpp3js2KMFpIBDnOIa3A5Obpig6vt9nb6WzqEu-uK65altVS18bZZCynfS_E5vozGwgNgfgsLB4BGDyaCt7fT_ANQOh-orQFt15oe4NkZUs_XUriBNSy4AfE8cjxcwnDs59iOQc1xuuCPYffuuncbXQXWjkt9xpYqiCVvF8cgyC3_xVotS7P01kY64Wdsk9FG0l0HlzIwc_wAxj38q1N5raekklbA0kRDPYHt9sH3Xgq_VNypK_wCJQz_Alxhk4Hzxj7B3n-avJovXmi9-NLVWym7Vtprq25Uj4pWzs5R1LQcA8v3ZM9wR3WofrD6a9Q9HO99LRWO51X9mTPbedNXYEfFjEcmWjkDkyRu4DkQ390-5V1d-N-f9Nnpbtd7vNhfJujtrXRw3F9BTiT-0rdMw86oNYDJGwGPLwQGB2HZ-YNbz-m71rXjYvXNFsvuHeJ36AvtSYKaOdhkNprZX4D2ZIdHE97svGCATyw353HddHMyoa2SKUPYQCHNdnIPf27dx3BC7CIoPhSiIiIiIiIoPhSiIiIiIiKD4XndRajmoHCgtdM-orZewAHyxD-In3_Cxz3B6OND7t6hq9TboWAX-5V8UURfXSOPwmxhwAiHIBgBe5zgMciQT4WEG4fpOXG06irRp3XE9Nb5WE0UdVSfFfE4Pb2Lw5vNoYSOzeQI5HsDn9PoWqdebJ6m1PtFqGOvt1609Utq3Rl7H0dSyY_DjkiOA8tcGD-72w4NcHAbQdu9yqLWtC0VLBS3AOLHRcgQ8t8lufZe4B9vB_qqXxh4ILWkHyCPKsHvft1Pb4KjVVjaXQPDnVEAzyDych39eyw43C1zaND22ovl9uUVFBE0yEzYa9zAPPEnOT44jk4n9kFYma162b2auKr2ypqy1V1LURVEVbO5rXtLC7kx0eXZGC0ghzSMHOVfffzeK19dXRIdezUcVFuDtNcIJ71SjLWzUs36kyw4zzDvkPEkEOa4eMcrlenJ0M610Vp2Xdrcdz7XU6rpGMpbO8YmhpefJskzfLZHHDhH5DcBwDiQ3LbXvRbsVuLaain1HoW0VlwqHtlkrn0zWTOewAMcXs_WEYABHL2-y49kbxqva69Q7F63NZX2-jo2u05fpxI7lTxlsZpKiVwwZWggtdyy5pII5NJdkKHeD7H7qpERERERERERUuUjwpRERERERUPaXsLQ4j7grgp7fS0vzRRAPPfk7uf6rscV0LpaYLpCY5gAR2Y4DuFiP1PbOUWltaaf3qs9DM6RwfY7t-h07nvkE5DYJZQHD5GPBbni7HPPysa4ho-5VX6RDLRu4SR4EQhdwIz57lZH6B1z_AG7Rspbm9jatrMveHDB-xx4K9uD9e2fGCutXUdNXU0tFWRMkhnHGRjh5B8fzz3_K0keqBt1U7cbhWm0Ptc8lNI2eeiujiXNkgJaTEfbmHZJHjzhYPOc_JHJ3bHv9PC2U-jztJqW56s1huNX2uJ2kn28WOYyO5ionJZJwDAD-yOJcTjGQAPPHbpFTwxwtihaAwM4tbjtj6YXKY2kEAYz9F5_VulKHVFtdTTt-HNH88Ew8xSfULq6Mu1wbG_TuocC50AwXAYE8X7rx9Tjz916nLs-FWiIiIiIiIiKl_spHhSiIiIiIiKMBSowfqvxdU6coNVWCv07XtBhuETo3nGcEtwHfkEAg_ZYn26xXDQl-msN2gIkp5CwF2eTmt_ex44kYcD58hfvamrqegsT6p1RiWHlIwDLMOHjBH1X73T_1N2fXlSNKXi6U0lyc-RlJUtfls72OLHxHsAHNeOGM5LwW-V39-t_aPbyGutc1bFQVVG01LpZZOLGRBpPxeZ7YbguJOAOBBI-bOInWXeouqzovuO49rt8kGodt70aW-UrYHu5RxOLDM3IB-E6N7Zg4FzQ1xwTjksC-k3pV1t1Vbix6V09G6js1Fxmvd2czLKSE9-Lc9nSu7ho_Lj2AX0A7cbb6O2p0ZbNCaHssFss9ogEFPDG3j2Hklx7ucTlxd5JJPuvW4HjClUkDzgdvC_MuNmiqqmK5RH4dVB3ZJ9R_Cft9l3YJXyN_WDi8ftN_h_n7rsIiIiIiIiIipf7flSPClEREREREREUcW5zjurC70X-x2_dHQmiX2urqrxreWppqZ8FOHsp2UzPiPmmPJpbGAex75JwvH9RmnnaC25rtUagmdFZ6KJ1RVPow97qYNbycSA3Lm8QQMd8rSnrjdJzt1arXm11TX2FrHOdTSh7mTlzub5HuaXODS573HA-VpwQFslgvtn64emHSu5d6t0N01VpCWGh1FR8S7408JAZUcPl-U8g_95gD3Ak91cTpg6drTSaH3O2baKqm05q23_BdTtbxjpjIz4buBHcuyS8vdl3doPFvEDJjp86e9uOm_Q8eiNu7WYIHETVVTJl0tVNxa1z3P9yeOQB27lXUDGNxxYBjsMDwqkRU8fupwPOApRERERERERFS_wBvypHhSiIiIiIiIijIXE57I2Oke_i1uS4k9gB5OT7LGbYvWOm9-9_debqWuOtmodBudo2gnnje2CSUPL6qWHm0ZLXMYwu9-IPuOX6HVVufbLJpQ6ZLppZq95iayGN0oyGucS4gfKz5S3m75cuxnl2WgnWNqo7Lqm8Wukke9lDcqqlIbFxY1rJS1hB5OzyDc_b2yrrdL3VTrDpgv13r7NRtu1qvVukpqu1TPLKeaXAEUj_lJzGQR2-p-gW-zY-Ww3XazTOptOvMtDqK20t5hlexzC9tREJWkBwBxh3YFvurghjB4aB49voqkRERERERERERERQfClEREREREREXXMxbOIPhvy5vLljsD9FwXO20t3oKi2V8ZdBUxvjkDXFp4Hz3C8PT6Q0ztNo8WDbPRQt9NM88o7ZSPc8y8cCWV2C-RxIAdJIS45ySsO-qay71DQt0u2ituNU3-7syKWlprJU1L-T3NbyDGMJeG5JIA7gLWTF0l9WV7ufw3dO2576qrkc901Xpiuja5zgS4vlkiABPfJc4ZJ-qyzsXp7a10L0xul1FoK7XDcfcu7Wu2QQ0Vtmq3aYoHTtMstV8Np4AYDnjsAAAXHBW2bQGnrLpDR9n0hpygkorVp6jhtFFC9paWwUzBCwDPzEAMADj3d5XqERERERERERERERFB8KURERERERERUDwPypb4_mf-9daf_3ln-GT_KFVL5f_AIz_APjU_wDWf8X_ADKlnhv5b_yLl_6w_wCP_lXKiIiIiIiIiIiIiIv_2Q==",
        "driving_privileges": '[{"vehicle_category_code": "AM", "issue_date": "1212-12-12", "expiry_date": "2200-02-01"}]',
        "IssueDate1": "1212-12-12",
        "ExpiryDate1": "2200-02-01",
        "NumberCategories": "1",
        "version": "0.4",
        "issuing_country": "FC",
        "issuing_authority": "Test MDL issuer",
        "timestamp": 1718112634,
    }

    qr_png = "app/static/images/eulogo.png"

    # First image option in mdl form. Format: base64 JPEG
    portrait1 = "_9j_4AAQSkZJRgABAQIAJQAlAAD_4QBiRXhpZgAATU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAMAAAITAAMAAAABAAEAAAAAAAAAAAAlAAAAAQAAACUAAAAB_9sAQwADAgICAgIDAgICAwMDAwQGBAQEBAQIBgYFBgkICgoJCAkJCgwPDAoLDgsJCQ0RDQ4PEBAREAoMEhMSEBMPEBAQ_8AACwgBsQFoAQERAP_EAB4AAQABBAMBAQAAAAAAAAAAAAABAgcICQMEBgoF_8QASRAAAQMDAwMCBQAHBAYGCwAAAQACAwQFEQYHEgghMQlBEyJRYXEUIzJCUoGRFWJyshgzOHWCwhZDobHR8CQlJjQ1REaFs8PU_9oACAEBAAA_ANqL_ZSPClERERERERERERERERERERERERERERUv9vypHhSiIiIiIiIi4Q93_k5I_Psvy7_qiw6Vtk961LfaG1W-mbzmqq2pZTwsbj9oveQGjse5IH3Vir16hnRpYq6S31u_thfNE7DjSRVNXFn7SQxPa4fgrqD1J-iR_wCxvxbj_wDa7gP_ANC_E1f6pPRhpaifUUu51VqCpa3Io7RZqt8z_wAOljZEP-J4Vuz60HS04fq9GbnfztND_wD2LyJ9bDa4ainp27M6pdYW5-BXfp8H6U_s0_NT44M7kj_Wu8L8mq9bvTUdZPHQ9Pd1nphK4QSS6jjje6MeHOYKd3B31bycB7OXYqfW30T-kUYpNi72ad7miqfLeImvYD5MYbE4Px93NVwZ_WQ6WYqlsAse4UzBHHI-aC1Uvw2lzWuMeX1IcXMyWO-XBcxxa4tw53vtLeqP0YanjgbNunPY6mVveC6WesiLHfwue2N0Y_Iesk9F670luLYabVWhtTW--WirGYauhnbLE7_ibnv9shejRERERERERERUv9vypHhSiIiIiIijIX5V6vtu07bKq9Xy501voKCB9TU1NRK2KGGJgy973uOGtaO5JIA8Ela5t5vWY0pp7UE9j2W0B_0opaaV0ZutxqX00VRxdjMUQHMtJ_ZLi0keWrEDfD1N-pzeCpMNs1M3RVoc3j-gWF5j5fd8zsyH-RasbNS7n7k6ypP7P1buHqS90jZPitguN1nqYw_-INkcRnv5XmCSexPhEySMEnAQEjwSnJx8uP8AVTyd_Ef6pyd3-Y9_Pfyge8Yw89vHfwo5O-pVydpuoPenZKsM-1m4d3sTXSfEkpoJS6CQ_V0Tg5hP5C2JdNnrERzPp9MdS1mFO48YxqK0U5c0Euxymp25-UDuXMz_AIXLZbpTWGntb2Ci1TpC_Ul5s9yiZNSV1FM2aCVjs9w9p748HuDkY_aBC_fyFKIiIiIiIiKl_t-VI8KURERERRkfVdK43KitlHLcLhcKekpIGfFlmnlDGMZ_E5xIDR9z2WIPUJ6oPTxs02W1aSvTNf6gAcBTWWpa-lheOwEtSAYwM-zC4_XitPu8PUzvPvdqC63vWuvr1LT3Ob4ptcddIyiiZz5RxthDuBDfqRlWlyfGShJPknsiIiIiIiZP1VTXuJ7uJ8nz9fKvv0zdXe7_AEwaghuGjL1UVFikmDq6xVUhdSVLB-3huPkecftNwR75W7jpv6v9nOp2xCs0BqNkd7hjY64WKsIiraJ3FvLLCf1rORAD4-QPIAlrsht9GOLhnPnwqh4UoiIiIiIipf7flSPClERERFB8K12_m_m33Ttt_Xbg7hXcU9NSjFNSxvBqK6Y_sxRM8kl2AfZoBJ-UFaZOsT1B9fdVdJT6Uo7QNK6UpZnSuoYKovfWOPYGd_ytOG_ugYysRnPz4Kjk7OeRz9cqEREREREREU83YI5HBxkZ8r9vSurNS6HvtLqXSN7rbNdaJwkgq6SZ0U0Z98EHJB75Hus_Omz1dtyNJV9Hp7qApRqqxktjddKSJkdxp2-73BoDJh3OR8rhjsVte2z3R0JvFouh17ttqilvlkr2coqmne5pYWn5mPY4B0cjT-0x7Q4HsQAvYZb9VUiIiIiIipf7flSPClERERF4vdXdLR-zWgLzuVr28C32ayUxnne7HKR2QGRRtP7Ukji1jWeSXADHcrQj1k9WN16rtxo9WSWR1ms1ugNLbaAzukw3k4mR_fjzcCMhoAGBhY85I8EoiIiIiIiIiIiZOMZU8nYI5HBOSMq-nS71abldK-sf7b0VXGostdLH_a1kmcTTVjB5IHlkgGeLx3GRnK3v9P3UJt51Jbe0e4e3V1E8M2I62ieQKi3VAALoZmeWuwcg-HN4ubkOBN0g5rhkFVIiIiIiKl_t-VI8KURERF1pKhkeXukwG-SQcAfnOMDySfZaS_U96vnb27iO2m0TdXS6K0hUPY-SneTDX1wy18vbs5rAXNaT7lx-iwU5HOcnP1RERERERERERERE5H6lXn6Yep3X_S3uFHrjRtQailnaIbpapXEQ3CnySQ7HhwJPF3kZOFvq6c-oHRPUttbQboaFndHT1DjTV1HKQZrfWMDTJBJjsDhzHA-C17XeCALroiIiIiKl_t-VI8KURERFrd9UPreOgbTV9O21l1lh1LdIf_aC4U7-JoqRzDmna7yJXjHI-zPl8uHHT2ZHZJ8E-VSiIiIiIiIiIiIiIp5OHhx_qspegrq6uvSzueyS4zSz6K1G-OmvlKCeMBzgVTR_EweR7sJ_hC36W250d2oKa522qZU0tZEyeGVjgQ-N4Ba4Y7EEEH-a7yIiIiIqX-35UjwpRERF1KqshoKeWsq52xQQsdJJI92A1gBJJz2wACST9F81fUHraPcXfLXWuKOsdWU13vlZUU0_f9ZAJSI3j6Dg1uPsrbIiIiIiIiIiIiIiIiqD3e3t2W5n0jepiu3J23r9kNVVj57toWJklrnleC6W2PPFsZ9_1TsN_wALox4C2GoiIiIipf7flSPClEREWIXqi7nXvbDpJv79P1bqWr1VXU2nDO1-HMhna90wb75dFDI37CRx8gLQq4nx7fRQiIiIiIiIiIiIiIiIskugzqEh6dOoexasulVwsN2YbPeXPGGx00zwBIT7CNwZJgecFfQZSVcVZBHVU0okgmjbJG9juTS0jIcD75BBXaRERERUv9vypHhSiIiLU960u7sNZdNE7JUTnl1vEl-uAz8vKRpjhbjxkN59_wC-tXCIiIiIiIiIiIiIiIiKQ5w8OI9_K3--nJv1Qb5dNFha74kd60bHFpy6xySc3ySQwsMdQCe_GVhae_hwkb4asqkREREVL_b8qR4UoiIi0ber-T_pcTDPjT9v_wArlhAiIiIiIiIiIiIiIiIiLZF6K2sqm3bua60BLWsbRXqwxXFkLnY-JPTzhgLR9fhzSE_YLcKCD4KlERERUv8Ab8qR4UoiIi0besAT_pczdv8A6ft_-VywgRERERERERERERERERFkF0Kbnt2m6p9Bamq68UlBUXFtrrpSwvAgqmmEjiO-fmAz7eV9EDMeGuOCBj8fUELmREREVL_b8qR4UoiIi0besAR_pcz-f_gFv_yuWECIiIiIiIiIiIiIiIiIuSnnnp5o56eZ8UsTg-N7HFrmuB7EEeCPqvpd6fNbU24uymiNb0tQ6Vl4sVJUF7hhxcY2h-e5-bkDkexJHsrjoiIiKl_t-VI8KURERaNvV_8A9rmb_cFD_lcsIERERERERERERERERERS3yt43pBatOoekdljfE9h0xqS4Wscz2c14jqwQP3R_wClHt9QSs4URERFS_2_KkeFKIiItG_rAf7XE3-4Lf8A5XLB9EREREREREREREREREUt8ra56I2pbu-3bqaPkqy61001rucFO5o4x1ErZ45XNI8l7IYgQfHwxj95bS0RERFS_wBvypHhSiIiLRt6wP8Atcz_AO4Lf_lcsIERERERERERERERERERFnr6P-5dZo_qRr9BTOlFHrWzTQFpIDG1FMfixyHIySGiZgwcD4hJBwt17Hl2Sexb7LkRERFS_wBvypHhSiIiLRr6vzg7q7qG_Sw2_wDyuWEKIiIiIiIiIiIiIiIiIivn0WsrH9V21kdDK5lQdSUgif27Hlj7_ugjB8ecr6MYuOMg5JXIiIiKl_t-VI8KURERaPPWAs90o-rJ1yrKb4dJcNP0MlI_OfitZljj9sODv6LBpEREREREREREREREREUs7nus7PR_0db9RdU1XfK0P-PprTNXcKZjQCHufJDTkkEfuiY4wQeWM5GVu2jAGcBcqIiIqX-35UjwpRERFqP9aPb7UrtYaI3WdC-SwutxsImAbiOpEks7Wu7_ALzXOI9vkJ-gWsh3lQiIiIiIiIiIiIiIiIiePC2ieiDSRS3_AHZrJG_rIqO0RNz44vdUk_z-Qf1W2PAHgBSiIiKl_t-VI8KURERWL6zNoX759NeudvKWNz7jVW8VttDSGn9LpntnhZyPYB74-DneQyRxHcBfOpU00tLNLS1EL4pYnFj2PbhzXNJBBHsRggj6hdZERERERERERERERERFLO57rc_6RPT7rLanbbUe5etKCe3P18-hNto5QGyspIGyubM8cst-IZsNaW8uLWu8Pw3YQiIiIqX-35UjwpRERFQ4E9wF85_Wnt8NsOqLcPTA5_o5vU1fAX45cKhxmyAA0EfOQrFIiIiIiIiIiIiIiIiIsjegzYSk6g-o7T-kr1QipsNuD7vd2ui5xyU0OCI3jk3DZH8WE_3sL6EaKip7fTx0lJTxwwQMEcUcbA1kbAMBrQOwAHsF2kRERFS_2_KkeFKIiIi1k-sXsTopmhbX1B0VK-n1I250tkqnxn9XUwvjmcC8e7gWAAjvjstRqIiIiIiIiIiIiIiIilvlbjfRy2Obpba6_wC-N7tL4rtq2sdbrbLKzBFsgwS6M8eY-JOXB2SQ4QRkeDy2NIiIiIqX-35UjwpREREWC3rE9-keFzB41Zbs_YfBqP8AxC0gIiIiIiIiIiIiIiIiLnhiknkZFDGXyvcGMa1uSSTjGPckkAL6Ydi9GUG3uzuitFW6mZTwWeyUdKyMBw_ZhAcfm-YuJJJJ-quAiIiIipf7flSPClERERYl-qHpm36i6K9d1FYzMtlkt1ypHgf6uVtXDGSfryjke37cs-y0FoiIiIiIiIiIiIiIiK4Ow9hfqbenQ1iihfUPrL_QRtibL8IuAnaXfNxcBgAlfS5R05p4Y4md2MYG-AM4XbRERERQfClERERFb3ffbOi3k2e1jtfXSNjZqW01FCyYjPwZXsJilx_ceI3_AH4r5r77Y67TF_uenbxTiGutVTNRVUJIPw54nFj2_fi9p7-4H3X5KIiIiIiIiIiIiIiIr9dDFrmuvVttfTR0z5gb_A9_BpdxY0OcSePsMd19FYYAckDKrRERERQfClERERFQWM847LS96q3STHtNrob6aPa5untZ1z23Cla04orgWhxdk_uSnk4f3g77LX2iIiIiIiIiIiIiIiLMn0pdNVd-6wtP18dHLNTWW319dUzMYS2AfAc1hcT7F7w38kLe991KIiIiKD4UoiIiIitl1B7PWDfzZ7U21WoImGG-0T46ebGTTVbfnhmb_eY9rHAe4aQfK-dndXarWGzeuLpoDXVofQ3S1zGN7T-zKzlhsjCezmOHcH-q8UiIiIiIiIiIiIiIi28-jVsXd9M6Q1PvjqG200LNVCG22OQg_pDqWCWQ1Du4-WN8oiDcH5jCSewbnZeiIiIiKD4UoiIiIipLW-cDP1WM3Wt0d6V6p9vKqCKjp6LWtuhfNZLqWcXte1ufgSEd3Rv_AGT9CQR4WhbXOhdV7dalrtI61sFVaLvbZnQVFNUx8CHtPzY7fMMjsQfBC82iIiIiIiIiIiIiniVeDpp6dNY9S26FDt5o63Okg-Iye7V3Lgyhow4fEkc8hwacZDflcS7AHIEr6ItDaMsW32kbNofTVFHS2uyUkVFSQsYGhkbGtaOw7A4BP816VEREREVLlUiIiIiIoIGMYC1_-rxsW7XGxdHutp-0RyXLQ9aJa98UQ-K-glAjc4kDJEbxGe_YNLz7BaWfooREREREREREREWXPQP0TWzq-uOrTqXUlysVo05TU_GroIWPLqmV5wwh4wRwY8nHcdvqtvvTD0nbYdK2k59N6Ahq6mpuErJ7ldKx4dU1r2tIbkNHFrACSGtwASSr48W-eI_opRERERFS_wBlI8KURERERFbLqVsdZqTp13S0_bKX49dc9F3ukp4g3JfNJQzNjAH15FuF81JZjAIGRn-ePbHsuJEREREREREREU4JOMZJ-i33emLs6_aTpS0_UV1G6C76xml1JWtkbgtbNxbC0Z74-BHCeJ8Oc_6lZcYClERERERUv9vypHhSiIiIiIuGeJskT43NBDuxBGc5-q-fT1CNjrPsJ1Mag0tpkBtmurI71RQj_wCXZPnlCPbDXB2PoCPosaERERERERERERXS6Z9tZd2N-ND6CZQ_pUN0vNM2qjdEXsNO14fKHY8NMbXD7ZX0l0dHS0VLFQUcbIqeCMRxxsHZrQMAD6DHsu2iIiIiIipd5VSIiIiIiKl4JHZakvWk23qKfWOht1aWif8AAuFFPZ6uYMOBNG7mxpI9-D8DPY4K1juUIiIiIiIiIiKWraT6NOw1PUyao6h73SB76Od2nbKHju2Qsa-qlwfB4uiZn7ye4W10AY8KUREREREUHwpRERERERQfCtpv1svpDf7a29bWaxpA-hu1M5kE7Wgy0VQ1v6qeP-F7H4IJ7HBa7IJB-cjcHQ2ottNZ3nQOrrf-h3ixVj6KqiI8PaT3b_E09iCfYheaREREREREREX6thsVx1LeqDTtlo31NwuVVHR0sDG4dLK9wa1v5LnAfQdyvo86Y9nLfsLsZo_a6kDDNZrcxtbM1hb8ask_W1EmD7Oke4_YYH7qut4ClERERERFB8KURERERERUPaMf9q0K-qjRUVF1lapdQwxxuqqOhnqOAA5SfBA5Ox5PFre5WIiIiIiIiIiIizw9I7Y-TcPfup3JuNGySy6EpvjfrO7X1s7XMhb_ACDXv_4R9Vu0Y1oaAGgZyfH18rkRERERERFB8KURERERERUv_ZXz_wDqaVUtR1na9bIf9Q-kiZn-EU0axZRERERERERFLfK3VejltxX6V6crvrq4xiNutb26aiBHd9LSj4HxPtmUTAD-4D7rPweApRERERERFB8KURERERERUuWgD1NKSak6ztePnaR-kPpZWZ_hNOwD_KsWERERERERERSzOe2P5r6CPTe1nYdYdHugWWGl_RW2WkfaaqI4z-lQv_WPwPZznF_fueWfdZPDwpRERERERFB8KURERERERQfC0V-rdaZbb1gXKpdG4suFkoKhri3AJw5uAffHEZ_KwsRERERERERFLW8jhbwPSF0ZeNL9KEt-uTWti1XqSsulE0F2RA1kVOC4FvYmSnkPbII4n3KzmHhSiIiIiIiKD4UoiIiIiIih3L2AK1uesD073DWOhrPv5pqkM8-kmmivLGNy4UEjsxz9jjDHkBxAzxeD4BWnx_Y9lCIiIiIiIiAE-AvZbVbc3zdncKw7c6ZhL7jqCsjpISA1wY1x-aQ5LQA0Bzjlzezce6-krbLQdn2v2909t3p-PhbtN22ntlODyyY4WBuXF3ck4Jz9yvWIiIiIiIiKk9m91UiIiIiIiIvyNQWW1als9dp6-UEVbbrnBLSVdPMzMcsUjC2RjgfGWkj-a-errJ6arn0y72XfRP6LUO0_VPNbp-rkaT-kUb3EtbyPZz4-7HD3wD7qwhGCoRERERERFysaScNHc4x9TnwAB7rbp6UHR3XaNtMfUxr-kkp7re4Hw6ft09O5j4KR5HKrfybyDpACGYwOB5ZcHgN2Vsj4jw3I98LkREREREREUO8KURERERERFxujBdkBv9PvlWK6t-lrSPVTttVaPvcjKK9UbXzWW6tj5voqotIHJo7ujPy8m5yQAW9wFoK3a2h1zstru5bdbgWV1BeLbIWOaPmjmZjLZYXjtJG4fMHDtg9w0gtb4VERERERFW1vI4wM59x5P0wFsY9OD0-nbmVUW9u9llqYNMUE7HWW0VVM-M3aQAOFQ5r2t5Uw5ANIyHu5AEBpzuGpqSnpYWQU8TI44wGsYxoDWgYwAB48D-i5lwzzfBjMjwQ0dj38D6rmBBGQpRERERERUuVSIiIiIiIijAVBjjznH8ljH1vdG2neq_b6aGgNDbtcWmNz7FdZmu4Oe05dTTFmXfDfhwyA4sc4O4u4lrtD2tdBam241Pc9F67sdVZr3Z5TT1VFURkOa5pGSHDIcO-Q4ZY5uHNJBbnzCIiIiIuwyB0rmxxMLnyENYGjJJzjx5yfYBbKPT-9NS5alr6bePqJ05PQWanl5WfTlbCY5q9zXYM1RG7Do48ggMe0OeByxxLCduNPSU1LDHTUsLI4omNZHG1oDWNHgADsAO2AudF1bhEJ6OaPxyaueP8AZH4VaIiIiIiKD4QeFKIiIiIiIiKkxtOcjOexWJXXL0O6b6qtKS3myCltmv7PD_6qub_ljq2gl36LUOaCSwjs1xBLCQ75hyadGWtdC6o261PcdFa209VWe-WyZ1PVUdUwtkicDnIPhwx3Dh8jm_M0kEFebREREXttsdo9w949U0-i9sdIVt_vFV-xDTsDWN7HLnyPIZG3AOXOcACOxW4Xo49MbQexX6Jrndea36y1q10dRCGwk0FqkDW4bE13eV4eXfrHNHgYazB5Z1NiYzw3_wA_-QFWiLp3OobSUM1S5pIY3OFXR1LKqmjqIs8XDK7KIiIiIiKD4QeFKIiIiIiIiIqTGwnJHdYzdXHRDtj1W2eSpu0LLJrOkpzBbL7TNPJuSHNZOwdpo8g9vLQ5xDgVpH376cN0um3WMujNzLCynlIzS19MXS0VczyHwykAkZyMENcMfM0ZVqkRF-9pbROrNcXKKyaM0vc75cJjxjpbdSSVEr_P7rAT7fRbD-nD0etYXusotT9RV5prNaXRxyiwW2V0lbLzbksnlDeEHAkAhpkLiHAOaAHO2f7VbN7Z7J6dZpbbDRtvsFC3HJtNCBJMck8pHkc5CMnu4nyV7oxsJyR7Y_kqkRF-de43SW2ZjScubxwps0TobdFER-x8o-4X6CIiIiIiKD4QeFKIiIiIiIiIi43MZ_C0kHOCPfOf-9eK3R2o0DvNpOo0XuLp6kvNpqSCIphng8HLZGOxlrh7YWqff30e917Dfam47AVtv1RZJBzgt1dWx0tbCP4echEcn55NKsHffTa61tPUba2v2IuErC7iGUNyoa2TH14QTOd_2L0GjvSy6ydUy0Ir9urdp2lrT3qrxeKdn6O36viidJNn-6Iy77LL_an0X9urLURXHeDcm5akDTGXUFppv0GD_Vu5tdI5z5HjmQWubwOAAR3Kz_0FtbtxtfQOoNA6Ls9hhkH600dGyF0p793uABd5Pn6r1oA84GVJa0jBaMeMYUoiIutVBrgIyc8jlc7I2xtDGjAHYKpERERERFS_2VSIiIiIiIiIoyPqqeQHknzjv2yfosMerP1Ldr-m67zaFsloqNXa0pJWsrbfE91NBQsc3kHSTFjg52MYY1pJzklowHYEW31O-qPWe5tulr7pSGy3K4w07rHQUkbIy172scyN0hB5HmOPxHgZxlwGVmlon1Dat9caPU2i77bqP9NjoKesvVAaKOsncSGmLk4S_NxyOTGj5mtPFxIWVO3m_Wgdw6iO2W2udS18jMtpKgcXH7NPh5_C89v31S6F6cG09fuhbrrQ2SsIihukFO-eJ0zskR8WNc4HDfcYXk9p_UI6Wt4LrFZNP7iQUFzmkbBDT3WN1G6aR_Li2P4oaXE474BA7K7Otd7dr9t7tb7Nr3Wtt09U3iRsFA64yNhjqZXfstY4kNJ-2c_de6jmbIxpjfyyAflPYg-D79vwVzoiIqSTnHsfP2XWj5SzlxGGtHFq7Q8KUREREREUHwpRERERERERUOe0ZyccV0prrRR1LaH9JidVvYZGU4lAkcwEAuAzkgZ84UVdBHXiN8kkzPhP5sDJC0h31OPP-HwrNdQ_R1sn1L0Ubdw9Mxi60w5U91ocQVjPlxxdI0ZkZ_dcMfZYfV3QppDYrU9tr6WzsFNDHIyKseBUMrHcg6N7zICWSMyRluMg9uQ-Zemm0YZHucyjfLG45A98E5Bz-e671m0XdLTXNuVrlfTzMla6J0bhlp5ec_w_fysgyNE9Quga_afeK00VYKyE07hI9g-K8tLRLA4jkyUcsg8QR9Fp561uirVXSdq1tRHI-7aLvNRP_Y9wawh0QD3EU84ycPEfD5s4d3cOP7Kyz6It_wDbrqy2nl6P-peKnuFwgphDYq2Zz3T1ELIwQRMQ4MqI8AtJdykJwR2Oe3sr1Kbj9Bu8svSt1TX9120Y94n09qh8j5P0allLhFK4nlJ8BxaWmMjMLmuPJzBk7N7bdKO60cFxttdFWU1UxssE1O8PjkjcAWua4EhwI75HbAPgr9FERcbwS1wB8qpjA1vHAVSIiIiIiIoPhSiIiIiIiIoz3wsaetTrD050nbdRXiWjbdtVXxz6axWwkiN8gALpp3js2KMFpIBDnOIa3A5Obpig6vt9nb6WzqEu-uK65altVS18bZZCynfS_E5vozGwgNgfgsLB4BGDyaCt7fT_ANQOh-orQFt15oe4NkZUs_XUriBNSy4AfE8cjxcwnDs59iOQc1xuuCPYffuuncbXQXWjkt9xpYqiCVvF8cgyC3_xVotS7P01kY64Wdsk9FG0l0HlzIwc_wAxj38q1N5raekklbA0kRDPYHt9sH3Xgq_VNypK_wCJQz_Alxhk4Hzxj7B3n-avJovXmi9-NLVWym7Vtprq25Uj4pWzs5R1LQcA8v3ZM9wR3WofrD6a9Q9HO99LRWO51X9mTPbedNXYEfFjEcmWjkDkyRu4DkQ390-5V1d-N-f9Nnpbtd7vNhfJujtrXRw3F9BTiT-0rdMw86oNYDJGwGPLwQGB2HZ-YNbz-m71rXjYvXNFsvuHeJ36AvtSYKaOdhkNprZX4D2ZIdHE97svGCATyw353HddHMyoa2SKUPYQCHNdnIPf27dx3BC7CIoPhSiIiIiIiIoPhSiIiIiIiKD4XndRajmoHCgtdM-orZewAHyxD-In3_Cxz3B6OND7t6hq9TboWAX-5V8UURfXSOPwmxhwAiHIBgBe5zgMciQT4WEG4fpOXG06irRp3XE9Nb5WE0UdVSfFfE4Pb2Lw5vNoYSOzeQI5HsDn9PoWqdebJ6m1PtFqGOvt1609Utq3Rl7H0dSyY_DjkiOA8tcGD-72w4NcHAbQdu9yqLWtC0VLBS3AOLHRcgQ8t8lufZe4B9vB_qqXxh4ILWkHyCPKsHvft1Pb4KjVVjaXQPDnVEAzyDych39eyw43C1zaND22ovl9uUVFBE0yEzYa9zAPPEnOT44jk4n9kFYma162b2auKr2ypqy1V1LURVEVbO5rXtLC7kx0eXZGC0ghzSMHOVfffzeK19dXRIdezUcVFuDtNcIJ71SjLWzUs36kyw4zzDvkPEkEOa4eMcrlenJ0M610Vp2Xdrcdz7XU6rpGMpbO8YmhpefJskzfLZHHDhH5DcBwDiQ3LbXvRbsVuLaain1HoW0VlwqHtlkrn0zWTOewAMcXs_WEYABHL2-y49kbxqva69Q7F63NZX2-jo2u05fpxI7lTxlsZpKiVwwZWggtdyy5pII5NJdkKHeD7H7qpERERERERERUuUjwpRERERERUPaXsLQ4j7grgp7fS0vzRRAPPfk7uf6rscV0LpaYLpCY5gAR2Y4DuFiP1PbOUWltaaf3qs9DM6RwfY7t-h07nvkE5DYJZQHD5GPBbni7HPPysa4ho-5VX6RDLRu4SR4EQhdwIz57lZH6B1z_AG7Rspbm9jatrMveHDB-xx4K9uD9e2fGCutXUdNXU0tFWRMkhnHGRjh5B8fzz3_K0keqBt1U7cbhWm0Ptc8lNI2eeiujiXNkgJaTEfbmHZJHjzhYPOc_JHJ3bHv9PC2U-jztJqW56s1huNX2uJ2kn28WOYyO5ionJZJwDAD-yOJcTjGQAPPHbpFTwxwtihaAwM4tbjtj6YXKY2kEAYz9F5_VulKHVFtdTTt-HNH88Ew8xSfULq6Mu1wbG_TuocC50AwXAYE8X7rx9Tjz916nLs-FWiIiIiIiIiKl_spHhSiIiIiIiKMBSowfqvxdU6coNVWCv07XtBhuETo3nGcEtwHfkEAg_ZYn26xXDQl-msN2gIkp5CwF2eTmt_ex44kYcD58hfvamrqegsT6p1RiWHlIwDLMOHjBH1X73T_1N2fXlSNKXi6U0lyc-RlJUtfls72OLHxHsAHNeOGM5LwW-V39-t_aPbyGutc1bFQVVG01LpZZOLGRBpPxeZ7YbguJOAOBBI-bOInWXeouqzovuO49rt8kGodt70aW-UrYHu5RxOLDM3IB-E6N7Zg4FzQ1xwTjksC-k3pV1t1Vbix6V09G6js1Fxmvd2czLKSE9-Lc9nSu7ho_Lj2AX0A7cbb6O2p0ZbNCaHssFss9ogEFPDG3j2Hklx7ucTlxd5JJPuvW4HjClUkDzgdvC_MuNmiqqmK5RH4dVB3ZJ9R_Cft9l3YJXyN_WDi8ftN_h_n7rsIiIiIiIiIipf7flSPClEREREREREUcW5zjurC70X-x2_dHQmiX2urqrxreWppqZ8FOHsp2UzPiPmmPJpbGAex75JwvH9RmnnaC25rtUagmdFZ6KJ1RVPow97qYNbycSA3Lm8QQMd8rSnrjdJzt1arXm11TX2FrHOdTSh7mTlzub5HuaXODS573HA-VpwQFslgvtn64emHSu5d6t0N01VpCWGh1FR8S7408JAZUcPl-U8g_95gD3Ak91cTpg6drTSaH3O2baKqm05q23_BdTtbxjpjIz4buBHcuyS8vdl3doPFvEDJjp86e9uOm_Q8eiNu7WYIHETVVTJl0tVNxa1z3P9yeOQB27lXUDGNxxYBjsMDwqkRU8fupwPOApRERERERERFS_wBvypHhSiIiIiIiIijIXE57I2Oke_i1uS4k9gB5OT7LGbYvWOm9-9_debqWuOtmodBudo2gnnje2CSUPL6qWHm0ZLXMYwu9-IPuOX6HVVufbLJpQ6ZLppZq95iayGN0oyGucS4gfKz5S3m75cuxnl2WgnWNqo7Lqm8Wukke9lDcqqlIbFxY1rJS1hB5OzyDc_b2yrrdL3VTrDpgv13r7NRtu1qvVukpqu1TPLKeaXAEUj_lJzGQR2-p-gW-zY-Ww3XazTOptOvMtDqK20t5hlexzC9tREJWkBwBxh3YFvurghjB4aB49voqkRERERERERERERQfClEREREREREXXMxbOIPhvy5vLljsD9FwXO20t3oKi2V8ZdBUxvjkDXFp4Hz3C8PT6Q0ztNo8WDbPRQt9NM88o7ZSPc8y8cCWV2C-RxIAdJIS45ySsO-qay71DQt0u2ituNU3-7syKWlprJU1L-T3NbyDGMJeG5JIA7gLWTF0l9WV7ufw3dO2576qrkc901Xpiuja5zgS4vlkiABPfJc4ZJ-qyzsXp7a10L0xul1FoK7XDcfcu7Wu2QQ0Vtmq3aYoHTtMstV8Np4AYDnjsAAAXHBW2bQGnrLpDR9n0hpygkorVp6jhtFFC9paWwUzBCwDPzEAMADj3d5XqERERERERERERERFB8KURERERERERUDwPypb4_mf-9daf_3ln-GT_KFVL5f_AIz_APjU_wDWf8X_ADKlnhv5b_yLl_6w_wCP_lXKiIiIiIiIiIiIiIv_2Q=="

    # Second image option in mdl form. Format: base64 JPEG
    portrait2 = "_9j_4AAQSkZJRgABAQAAAAAAAAD_4QBiRXhpZgAATU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAEAAAITAAMAAAABAAEAAAAAAAAAAAAAAAAAAQAAAAAAAAAB_9sAQwADAgICAgIDAgICAwMDAwQGBAQEBAQIBgYFBgkICgoJCAkJCgwPDAoLDgsJCQ0RDQ4PEBAREAoMEhMSEBMPEBAQ_8AACwgA6gDXAQERAP_EAB4AAQACAgIDAQAAAAAAAAAAAAAHCQgKBQYBAwQC_8QARxAAAQMDAwIEBAMDBwgLAAAAAQIDBAAFBgcIERIhCRMxQRQiUWEjMnEVQoEWFyRSYoKRGDNDY3KhorEZRFNXc5WjwcLR1P_aAAgBAQAAPwC1OlKUpSlKjXXzcPpXtrwV_PtVMgEGIOpuHDZAcmXF8DkMx2uR1rPbuSEpB5WpKeSKftxviw7htXJkyz6YTlabYusrbaRbHObo82ewU7M46m1e48jy-nnjqVxzWH-UZ7nWbv8AxWaZpfr-9zz5l0uL0pXP15cUTXZdP9w2uulcqPK081cyyxfDKCkMRbq8IyuPZbBUWnE_2VJI-1Zk4h40evdl0_k4_lOBYzkeUpbS3ByFalxUA8d1yYjQ6Hlk8n8JTCR2-X64uan7zd0Or896ZmmtWTqZd5HwFvmqgQkp55AEeP0Nnj06lAq49SaiyBluVWqebrbMmu0OaTyZLE1xt3n69aSD_vrIbRPxG91-ik5n4fUmbltoQoF205Q6u4NLT9EurV57XA9AhwJ59QfSrddoG_TSXdvblWy1BeN5tCZ82djc55KnFIA-Z6K5wBIaB7EgJWn95CQUqVkxSlKUpSlKUpSlKVG24XXzBNtell11U1Al9MOEAzDhtqAfuMxYPlRWQfVaulR-iUpWs8JSojXv3FbitR9zepE3UbUW5Fx1wlq329pR-FtkXnlLDCT6AepV6qVypXJNRhSlKUpXK4pleSYNkduy_EL1LtF6tMhMqFNiuFDrDqT2Ukj_AAI9CCQeQavs2Db1LPu206cYvfw8DUHGm22r_AQOlEhJ7ImsD_s1kEKT6tr5SflU2peU9KUpSlKUpSlKUqhrxON0srcFr1MxPH7mpzCMAddtNsbbUC1LmJVxKmdvzdS0-Wg8keW0lSeCtXOHlKUpSlKVI23vXPL9uWrVh1Zwx1SpVpf4lQy6UNXCGrs9FcIB-Vafcg9KglYHUkVsgaeZ7jWqWC2LUXDp3xdlyKAzcYTpHCvLcSCEqH7q090qSe6VAg9xXYqUpSlKUpSlKVj3v013Xt62w5bmdun_AAt-uTIsNhWFhKxPlBSUuI59VNNh18Djv5Na7dKUpSlKUpVv3gt66Kv-n2U7f7zP65eKyf23Zm1rHV8BJVw-2hPr0tyOFk_WX6-gqyqlKUpSlKUpSlVAeNVrGu9aj4bodbZZMTGoCr5ckIXylUyUShlCx7KbZbKh9pNVrUpSlKUpSlZEeH9rEvRPdjgmSSJTjNqu80Y9dgkgJVGmcNBSyf3G3Sy8eO_4Xv6HYgpSlKUpSlKUr8rWhtCnHFBKUglSieAB9TWtPub1Wc1v3AZ5qn55ej369PuQVFJSRBbPlRUkHvyGG2gfuPaoxpSlKUpSlKVsqbWdVxrft4wHVBySh-Ze7KwbitA4T8e0CzKAB9AH23QP0qVKUpSlKUpSlQVvk1OVpFtP1KzGPIWzNNmctcFbZ4WiTMUmK2tP3Qp4L_RBPtWuZSlKUpSlKUpVyXgranLyDRPMdLJkxbsjEL4idGQrsGoc5slKE9u4D0eQo-pBc-hFWLUpSlKUpSlKrh8bHUIWfRzBNNGJK23slv71zdSgnhceEz0lKvt5ktpQB9Sjn2qnWlKUpSlKUpSs6vB01EOKbqn8MkS1IjZtj0yE2z-6uVH6ZTaj90tMyAP9s_arvqUpSlKUpSlUt-NLmL943H4xhqH0qiY7ijLvR7okyZDynPf3bbj1X3SlKUpSlKUpUwbPczf0_wB0uleUMPJaSzlVvjSFq9BGkPJYf_8ASdcrZIpSlKUpSlKVr7eJjf15Dvb1Lf8AOK24ciDAaHPIQGYEdCgPp86Vn9SaxgpSlKUpSlKUr3wJ0u2To9ygPqYlRHUPsOp9UOJIUlQ-4IBraXtc5q6W2Jc2f83LYbfR_srSFD_nX1UpSlKUpSla2e766vXndVq_OfcCz_Le9MIUBwC21MdbR_wITUR0pSlKUpSlKUrZt0EvIyPQvTrIQQRdMTtEwEHkfiQ2l_8AyrvdKUpSlKUpWsPrJf4uVavZxlEKQl-PeMkuc9l1CgpLiHZTi0qBHYghQPNdPpSlKUpSlKUpWx3slvbOQbRdIZ7DiVpaxG3QSUnkdUdlLCh-oLRH8Km2lKUpSlKVjzvi3P41ti0NvV9fu7LeW3uI_bsWgBQL781aOkPBHr5TPUHFqPA7JTz1LQDru0pSlKUpSlKUpVxHg5bkrFkGl8zbbf7ixGv-KypE-xMrUEGbbpC1POpb5PK3Gn1PKUOB8jzfAPSsiyClKUpSlKwQ8WLWncDoZgWB5Tozmj-N2qddZdtvciOw0t5x9bKXIiApxCilPS1LJ6eOSE_SqZM3z7ONSr-7lOoWXXfJLu8kIXNukxyS90AkhAUskhA5PCRwBz2ArgaUpSlKUpSlKUr6bZdLlZbjGu9muMmBOhupejSorymnmXEnlK0LSQUqB7gg8irKfC33KbrtWtwUXA8o1Tu-TYZbLLMn3lq88S3EtpSG2CmSsF0Oee416rPUkL5B9RbtSlKUpSo_160VxHcNpPkGkmaoWLffI4SiQ1_nYchCgtmQ3_aQ4lKuPRQBSrlKiDr0biNuOp22TUCTgOpVmWwrqWu3XJpJMO6RweA8w4fzDgp5SfmQTwoA1F1KUpSlKUpSlKVzGHYblWoOT27C8JsE29Xy7PCPCgQ2i468vgnsB7AAqJPZKQSSACavr8P_AGcR9pWljzN_cYl51lKmpeQSWlBTbAQD5UNpXuhvqWSr95a1nnpCQMpaUpSlKUrqupOlunesGLyML1Ow-2ZHZpPdUWcyFhC-CA42rsptwAnhaClQ57EVgFq74Kemd9ku3LRjVC7YqpalL_Zt3ji5RR9ENuBTbraR9Vl01jHlPg67ubEXFWV7CckQCegQLwtpahz25ElpoA8e3Uf1NR1K8MnfJEV0u6ESVH_VX21uD_gkmviX4cG9lB4Ogd2P6T4R_wCT1Y9X-xXfF77ccZyCA5CulolvQZsVzjrYkNLKHG1cduUqSQf0r4aUpSuwaf6f5hqnmNswDALG9eMgvLqmYMJpaEKeWEKWR1LISAEpUSSQAAanr_o1N7__AHDXD_za3f8A6K_Tfhob4XVBKdB5oJ_rXi2pH-JkV27FvCT3o5A4EXbD8fxpJPHXdL_GcAH1_opePH8OayF0v8ESUXWJetGtjSWwPx7fi8IqUo_2ZckDj-Mc8_arANBdrGhm2q1uW_SXBottkyUBEy6PqMifLA47OPr5V08gHoT0oB7hIqWaUpSlKUpSlKUrXP34MWaPvD1absIaEY5LJWvyuOPiFcKkc8e_nFzn781A9KUpWYXhOfsj_LYxT9peX8R-zbt-z-r1-I-Dc56fv5Pnfw5q-alKUpSlKUpSlKUpSsbt728nFNpOmr05LsW4Z1emHGsbsyz1dTvHHxT6QQRHbPc9wVkBCSCSpOvvf79d8pvtyyfIZ7s66XeW9PnSneOt-Q6srccVx7qUok_rXwUpSldp0t1KyrR7UOwan4TKRHveOTW50RTiSptZT2U24AQVNrSVIUARylShyOea2Jdsu5PAN0emEHUbB5KWniEsXa1OOBUi1zOnlbLnpyPdC-AFp4IA7gS1SlKUpSlKUpSlKVEG7TW-87c9AMq1gsGJpyKdY2mQ1EcdLbSVPPIZS86U_MW0KcClJTwSBxykErTrx6q6rZ7rXnVy1G1JyB-8Xy6OdTrznZLaB-VptA7NtpHZKE8AD-NdSpSlKUqUdu24_U_bFqAxn-md2DLpCWrhb5HKodyj88ll9AI5HrwoEKSe6SDWxHovqG_q3pJh-qEjHnbEvK7LEvH7OcfD5jpfaS4lIcAHWnhQIV0pJBBKUnkDulKUpSlKUpSlK8EgAkngD1NUs7v_ABWdXtQr9fMA0LuSMNw-NKfhIvFudKrndWkLUgPJkcD4ZtYCVpDQDg93CDxWYmwm_p3XeH7P00zW8ybjNaYu-E3KZKUXHgFoK47nJ7ktsyWAlXfu16kg1SVkVgu-J5Bc8Wv8NcS6WaY9b5sdf5mZDSyhxB49wpJH8K4-lKUpSu_6AaTXLXTWjDtJbYHgvJbqzEfcZ462IoPXJeHPb8NlDrnv-T0NW5-Ldq1ddG9u2JYRp7fZGO3G_wB-jtR1W-QuO-1AgN-afJWhQUjpe-D7g9h296hLYj4pWpd-1AxjQ_X4RL_GyCY1abdk3AjzWJDhKWUSQkeW-lSy22FAIWCoqUpwntbHSlKUpSlKVAm4je_t22zMvRc_zRuXkCEdTeO2gJlXFZ45AUgEJZBHcF5SAfYn0qr3cF4s-4fWB97GNIY383NjlqMdv9mLMi8SQrlIBldILRPKSAwlC0nt1qrOvXrIp-y7w6HbPNvjr-ZSbMiw_GvzFrflX249SpkhLqyVrWkuS30kknhoew7UU1Z34IupQiZfqPpDLlqIudvi5DBZP5UqjuFiQQf6yhIj9vo329DXR_F12vT9OdXBuAxu3k4tnziUXFTaflhXlKPnSQB2D6EeaCSSVh_nj5ea_KUpSlKuF8InaHMwPGXtzOe2_wAq8ZXCEbGIzqCFxrWshS5RB_ef6UdB45DSeQSHuBAHjQ6kDI9wmNacxZKHI2G48l15APJamTXC4tJ-n4LUU_3qr_hTZltmMXG3ynY0qK6l5h5pZQtpxJBSpKh3BBAII9CKvR1qv173XeHhC1s03vE605jbbKzmFvl2eU6xJh3OElaLgyytopX1dImsp44JJT29qwz27eMTq9gio1g15sjWfWVJCDc4wREuzKefU8AMyOB6BQQo-pcNWf6B7sNCNytrE3SrOok2chsOSrPK_o9yijtz1x1fMUgnjrR1IJ9FGpepSlKVGGvW5TRvbXjH8p9WswjWwPJWYNvbPmz7gpPHKY7APUvgqSCrshPUOpSQeaqO3O-LHrhrEuZjOkgd02xRwqb8yG_1XiW3yQFOSQB5HICT0M8KSSoFxwVg1IkSJch2VKfcefeWpxxxxRUtayeSpRPcknuSaye8NfRoazbuMQiTYyXrTiSlZXcgTx8kRSSwOP3gZS4ySk9ikq9fQ5E-NTrOb3qJh2hVrmFUXGoSr5dW0LBSZkn5GULHqFNsoUofaV7-1atZDeH9qmdIt3OneQvvrbgXO5CwTwlQCVMzkmOFL5_dQ4426f8Aw_f0q_nVDTPDNY8CvOmuoNnbudhvscx5TCuxHcKQ4hX7jiFBK0qHdKkgj0rX33ebRtQNpWoz2M5FHen43cHFu4_f0NEMXCOD-VRHZD6AQHGyeQeCOUKSowRSlKVYD4cPh4ztarpA1u1nsq2NPYLoftltko4VkDyT2JSf-qpI-Yns4R0jkdRF0rbbbLaWmm0oQhISlKRwEgegA9hWtfus1POsu47UTUhuY3KiXe_SRb3m_wAq4LKvJin1PP4DTXf0J9OPSopq2_wV9ZWr1heb7fr1Jbdds76cgtbDqwouQ3-GpSEoP7iHUsqP3lH-Nc-6vRtegW4XONKkNKRBs90Wq2dSlKKre8A9FJUruo-S42FHv8wV3qM7Pebvj10i3uwXWZbLjCcD0aZDfUy-w4PRaFoIUlQ-oPNWFbX_ABgdSMEchYnuKtjmbWFJDQvkRKG7vFRx6rT2blAcJHfy191KK1ngG1_SbWXTHXPEmc30pzK35FaHSELciufiR3ekK8p9pXC2XAFAlC0pVwQeOCCe6UpWH-_DxAsX2o2n-R2JNRL_AKl3JjzI0BxRVHtbSh8siX0kHv6oaBClepKU8FVHuo-pmfau5dNzvUvKp-Q324K5emTHOTxySEISOEttp5PS2gJQkdgAK6zSrYvBBtmDtWPU28IvsZzMZUuFGctiiA8xbGkKUl9A45KXHnlpVwSAWW-eOR1Yd-I1pvrDhW6fMsk1Ytqg3l9yfuNiuTPK4sy3JIQw22vgfOy0GW1oPCkkA90qQpWMNftl56M83IjuradaUFoWhRSpCgeQQR3BB962XtuOqsbW_QnBtVWHWVuZDZo8iYGlBSG5qU-XKbBH9R9DqP7voPSuc1P0s0_1mwydp_qZjEO_WK4p4djSEnlKgD0uNrHCm3E8npWghQ9iKqV3K-DzqlhcyVkW3a5jNrCVFabPNebj3aKn-qFK6WZIHc8gtrPYBCj3OBmaae57pxdP2JqDhV8xqf34jXa3uxHFAepCXEgkdx3HbuK6_UlaVba9e9bpLLGlmlGRX9p8lKZjUQtQkkf15TvSwj-8sVZjtP8AB-x7D5sPOdzlzg5NcGFIfj4vAKjbmlg8gynT0qk_u8tBKW-QQoupVxVlEaNGhRmocOO2xHYQlppppAShtCRwlKUjsAAAABUO7ytVv5ltsOomoDMox50WzOw7c4nupM6URHjqA9-l15Cj9kk-gNa31Kzn8I3TXWG77k4Wp-G21TWHWCPKg5LcJHKI7zbzB6IqDwfMd8zyXelP5QhJUQCAruHjXWzB2ta8IvNmvEV3KJVgdi3yA0sFyOw06FRHXAPRTgefA579LKfbjmuilSFofr5qpt2zVjO9KcokWqcgpTJjklcWeyDyWZLJPS6g9_XuknqSUqAUL2NmW9fT7d5h63raluy5paGkqvePOO9S2geB8QwT3dYKiB1eqCQlYHKSvI6oi3W7grNtk0NyHVe5ttSZkNsRbPCcVwJtxd5Sw16glIPK18dw22sjuK1zMyzHJ9QcquubZpepF2vl6lLmT5sggredWeSe3AA9gkAJSAAAAAK4elK7VphqjnejWb23UTTfIpNlvtqc8xiSyeyk_vNuJPyuNqHZSFApUOxFXM6Hbg9vXid6Py9INY8bgQcxjtefOsvm9LjbyElKbla3lcrHHUeR3U31Kbc8xtXU7WRvJ2Uai7RMuSzdQ5esMurykWTImmilt09z8O-B2akBIJ6eeFAFSCQFBOOdXF-Cxq8ch0jy7Rm4y1uSsQuibpb0rKQEwZgPU2gDuQh9p1aifeQO_sLHaV6JkKFcI6olwiMyWF_maebC0K_UHsa4SNpzp7CkCXDwTHWHweQ61a2ErB_UJ5rsIASAlIAA7ACvNKrK8bLVpNuwnA9EoEvh-9T3chuKEOcKTHjpLTCVp90LcedUOe3VHB9QKqMrLvYx4feZ7rbs3l2TqmY7ppCfKJV0SgJfuS0nhUeGFAgnkFKnSChB5HClAprO7dhvV0g2I4DG257bbDaVZfb4Yjx4EYeZDx5Chz58tRJL0pfJWG1ErUVeY6eFJDtNeVZVkmcZHccvy-9S7vertIVKmzZbhW6-6o91KJ_wA9AAAOAK4qlK7lo9qzmWh2pFj1RwK4GJeLFJS-2CT5b7fo4w6AR1NuIKkKH0UeODwa2R9IdT8c1o0xxrVTEnCq15Nbmp7KFKSpbClDhxlZTyOttYW2oA8BSFCquPGw1ekXLPMH0OgSViHZbevIrghJHQ5KkLUywFD16m22nSPtJ9_as2lKUrk8YyjIsKyG35ZiV6mWi82p9MmFOhulp5h1PopKh3H_uCQe1Xu7SNRZ2-PaBKlbnNP7S_bbg7Js8x5Z8uNeY8cI5npSODGWlzqHUhQ6XWFONlv5Uooly5jGo2WXqNhcyXLx5q4yUWmRMSA-9DDqgwtwAJAWW-kq4SO5PYelZG-GprInRvdziMmbJSzacuK8UuKlJJ-SWUhg888JAlIjEqPYJCvT1GwLSlKUpWvf4jesH88u7jNbnFk-da8afGMW3t2DUMqQ6QfdKpBkLB-ixUYbbMc07zDXzAcU1YckIxO8X6JBufkO-UVIcWEpSpY4KG1LKErUCFJQVEEEAi4LxIdftQ9oehWMY_oLiECx2y-OOY-i9Rkobbx9LbSVMsR44T0hx1sPdC_RsML-UqUlSaOp06bc5si5XKY_Lly3VvyJD7hccecUSVLWo8lSiSSSe5Jr00pSlXCeCtrC_f9L8y0VucpS3cSuDd2tgWodocwKDjaB_VQ80pZ595P-Ff3iA51_OHvG1SvaXVLahXtVkaBJISmAhEQ9P0BUwpXbsSon35rHylKUrmMLxO8Z7mNiwXHm23Lrkdzi2mChxXSlUiQ6lpsE9-AVLHeroN9mY2DZjsQtehuCSfLn323tYXbVgJS6uP5XNwmLSOO60dYUpPo5KSeOKpHr2R5EiJIalxH3GX2VpcadbUUrQsHkKSR3BBHIIrZS2v6xxtftAsJ1YacbVJvdrb_aKUJ6Utz2iWpSAPYB5tzj6p4PoalKlKUqKd1OsbGgW3zONVVPIRLs1rWm2hSCoLuDxDMVJSO5T5zjfV9E9RPABNa17zrsh1b77q3HHFFa1rUSpSieSST6kmvzV6GEzYPiM-Hc7ZrjJZkZa9bFWyU66sBTGRQQlTTq1D8nmkMuK4_wBHII96o1mQ5lumP2-4RXosqK4pl9h5socacSeFIUk90qBBBB7givTSlKVmN4T2oqMC3gWm3ynwzByqy3O0SXFK4QhKGfi0qP8AeiJSP9r9axf1Pn3K66lZbc7yw4xcJl8nvy2nPzoeXIWpaVfcKJBrrNKUpXNYRmN-08zKx55i8oRrxj1wj3OC6RyEvsuBaOR7jlI5HuOR71djuVwnG_EU2N23UnTuCl7JIsI5DYWE8KeanNJKJltJ9SVdLjQHZJcQyr0AqjSlWteClril2Lmm3e7SlFxlQyqypWVH5D5bEtsE9gAr4ZYSPUrdVx6mrTqUpSqs_Gu1uSzBwrb1aZZDkhZym8oQojhtPWxEQeOygVfEqKT6Fts8ehqqOuQx6wXnK7_bMWx23uz7teZjNvgRGuOuRIdWENtp591KUkD7mrxczuuN-GTsPj2eyOxHsrTH-BhOBHIuORSklTsggjlTbfC1gK_0TCEc88VRhOnTbnNkXK5S35cuW6t-RIfcLjjriiSpa1HkqUSSST3JNemlKUrvmhd0yGy6qWS54rFdkXRn4nyG2uepXMZ1KuOP7JUazz8Rrw49QWdQrxrvoHi0vI7Pkkhc-92O3NF2bBmrPLrzLKfmeacWSshAUpClK-Xo4Ka3LxZbxj1yfs9_tMy2T4yul6LMYWy80eOeFIWApJ4I9RXx0pSlWMeDvuZOD6kXLbplFw6LLm6jPsZcUAmPd22_nbHbt57KAOSfzx2kpHLhqM_FI2xnQfX-RmuOwC1iOoy3rxC6E_JFn9QMyN69h1rDqRwAEvBKR8hrDOpX2ra0ydvm4DC9Vm3lph2m5IRdEJBV5lueBalJ6R-Y-UtZSO_C0pPHatk2PIYlx2pUV5DrLyEuNuIVylaSOQQR6givZSleqVKjQoz0yY-2wxHbU6664oJShCRyVEnsAACSa1tN1WtcrcJuAzPVZx5xUK63FbdqQsFPlW5kBqKnpP5T5SEKUBxytSzx3qJ6sn8HXa-cqzafuYyy3k2vFVuW3HEuJIS_clt8PPgeikstL6RyCOt7kEKaqGPE83N_5QO4SVjuPXAP4fp6XrLa-hQLcmV1D4yUDx36nEJbSQSkoYQocdRrD-lKUrlsXxHLM4u7eP4XjF2yC6PAqbg2uE7LkLAIBIbbSVH1Ht7irWPDZ8OTNdM8xY191-tLVsuMKM81YMdcWl15pbzamnJMoJJQn8Ja0paJUeVlSghSEg2dVwmU4Rhmc29VpzbEbLkEFaSlUa6wGpbSkn1BQ4lQI_hUB5x4b-y_PFl-foha7XI4IS7Y5Mi2hPP-rYWlo_xQagLNfBQ0JuqH3ME1RzPHn3AS0mcmNcY7SvbhAQyspH0LnJ-tQXmXgkaxW8dWA6yYhfAFdxdYsm2qKeD3HliQCeeOxIH3qGMr8KnetjLpELTWBkLIBJftN8hqSP7jzjbh_gk1FGSbOd1mJvKZvW3jPx0glTkWxSJbQH3cYStH--uhOWnUTS3ILdfJllvuMXi1y2ZsF-XCdiusyGlhba0-YkfMlSQR-lXY5BBxvxONhjU-3IhNZa5G-JjJ6wkW3JYiSFtE8nobd6lJ5PJDMlKuOeKownwJ1qnSbXdIT8OZDdXHkR5DZbdZdQSlSFpUAUqBBBBHIIIr0Vfx4YmtCtY9pWNM3CUHrxhK14rPPBBKY6UmMruST_RlsAq91JX-gywpSsOfFR16To3tfuWMWyWlu_6jLVjkRAUOtMNSOZrvB7lPk_hEj0VIQaodrtGl2m2U6wah4_pjhUMSb1kc5uDFSrnoQVH5nFkAlLaEhS1q4PCUqPtVzu7rUfF_D72V2fSLS6aIuQXKCcbx5YKUSCsp6p1zUEkcLHmKWVJ7B6Q124NUsY3p_nmYnjEMJv8AfDzxxbba9J7_AE_DSalDFtke7nMV9Fm275w39F3G1OW9B-4VJ8tJH3BqWcS8Jbejkqj-1cNsOMJ6gAu736OoKH14il4gfqAftUyYh4IWp81kKz3XPF7M6SeU2i2SLkkDnt3dVH9uPb_7qdcP8FjbpaFsyMwz_OMhcb4K2mn40KO79QUpaU4B-jgP3qe8I8O7ZlgXz2vQexXB08FTl7U9deo_XplLcQP0CQKnrHsYxrErei0Yrj1ss0FsAIi2-I3GaSB6AIbAA_wrk6UpSlKV4UlK0lC0hST2II5Br54dut9uS4m3wI8VLq_McDLSUBauAOo8DueABz9qxq122_6Dz7jdL_O0TwKRc57plS5ruNw1vyH3D1LcccLfUtalEkqJJJJJrB3WDSfSy2PThbdNMViBCCU-RZozfHr6cIFTN4QTLMKRrHb4bSGIrb9jcQw0kJbStQnBSgkdgSEpBPv0j6CrGqUqp_xj_wCmaz6VQJf48VFkmuJYc-ZsKVJbClBJ7ckJSCffpH0ridAtJNKby3GN30yxOd1NAn4myxneT_eQasX0T0P0WwpDeU4bpBhNhvSEqZTcbZj8SLKS2pI6kh1tsLCT7jng1KUyyWW4ymZtwtEKVIjpKWnno6FrbB9QlRHIB4HpX2AAAADgD0FeaUpSlK__2Q=="

    # ------------------------------------------------------------------------------------------------
    # LOGS

    log_dir = "/tmp/log"
    # log_dir = "../../log"
    log_file_info = "logs.log"

    backup_count = 7

    try:
        os.makedirs(log_dir)
    except FileExistsError:
        pass

    log_handler_info = TimedRotatingFileHandler(
        filename=f"{log_dir}/{log_file_info}",
        when="midnight",  # Rotation midnight
        interval=1,  # new file each day
        backupCount=backup_count,
    )

    log_handler_info.setFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")

    app_logger = logging.getLogger("app_logger")
    app_logger.addHandler(log_handler_info)
    app_logger.setLevel(logging.INFO)

    """  logger_error = logging.getLogger("error")
    logger_error.addHandler(log_handler_info)
    logger_error.setLevel(logging.INFO) """

    max_time_data = 5  # maximum minutes allowed for saved information
    schedule_check = 5  # minutes, where every x time the code runs to check the time the data was created
