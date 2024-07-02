# Batch Credential Request (Post)

**Endpoint**: <https://issuer.eudiw.dev/batch_credential> (or <https://localhost/batch_credential> if installed locally)

Header:

+ *Content-Type* - *application/json*
+ *Authorization* - *Bearer token*

Payload:

+ credential_requests - Required

![image](https://github.com/devisefutures/eudiw-issuer/assets/61158161/ae731034-2823-420d-9f8b-436c93d36952)

**Example Request:**
  
  header:
  ```
  'Content-Type': 'application/json',
  'Authorization': 'Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Ik1tWkhTQzE0UlhwNVRUQjVkMHR1UTE5a1FYVnJTVlZLUldKelVWSTVlREJ6UWkxd1ZuQXdVMGgyYncifQ.eyJzY29wZSI6ICJvcGVuaWQiLCAiYXVkIjogWyJJRCJdLCAianRpIjogImZiMGI3NzdmODk5ODQ2MjBiMjQwZjNhZjczNjFlYzU3IiwgImNsaWVudF9pZCI6ICJJRCIsICJzdWIiOiAiODQzZjFjN2FkMDRjYTAyYTY1ZWEzYTc0MWY2YjkzOGNjN2U2N2E3OGQ0ZmFhN2YwMDYyNWFkYTFkZTM2OTM1NiIsICJhY3IiOiAidXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6SW50ZXJuZXRQcm90b2NvbFBhc3N3b3JkIiwgInNpZCI6ICJaMEZCUVVGQlFtMWhSbEYwVFV0TVRYUnJkak5wVkRjdFRWOTFWa3RRUmtkcVptTjFhamxETUdKemMzUkpXV1ZzUTBoeFVHazNZbXhpVjNaV1QzZDVjbFJ0Wkd0bk16Qk9WekEwV0Y5T2NuRkZYMWg2UjFWSGFuWlhkV0V0UmkwdGRtcFZVbTl1YzFJM2MwdDFjVUoyVGs1RGMyNXlaRVpxWkhKa1MwSkJObWxpY1hSS1JFaEVkVXRMT1dOWFRYcFBWMHB1VlVSWE9UTjZVVUZMYmw5RFNGOXVMWEJaY1VwRFRrbGxYMnQzVURadlNra3dka1owZEd0Vk9VVkRVMGhzWlhwelREVnpiemRuYzFCTk16TTFjVEZoUTA0eGN6Um5SekU1UnpsZlJrYzBZMDFXU2tGbmJYUkxXV1ZOVjNGRk9VRkRVMVl5Y25KWWRuZFdlR2h4VVZBMGVUZHJWMWQzTW1vMFRWRndVa3RJZFdGc2QySTNMVkozWW5wTVpWb3pRbEU5UFE9PSIsICJ0b2tlbl9jbGFzcyI6ICJhY2Nlc3NfdG9rZW4iLCAiaXNzIjogImh0dHBzOi8vZGV2Lmlzc3Vlci5ldWRpdy5kZXYiLCAiaWF0IjogMTcxODExMzMzNCwgImV4cCI6IDE3MTgxMTY5MzR9.QA7er_vPCqQsXjP3BtL2uFT1tKYKqaV7RRd_rwcdBOOO_uniax2uwjsWp5m5TAXYjzhec_ioL3kmv2OmRSLhlg'
  ```

  payload:
  ```Json
  {
    "credential_requests": [
      {
        "format": "mso_mdoc",
        "doctype": "eu.europa.ec.eudi.pid.1",
        "proof": {
          "proof_type": "jwt",
          "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA"
        }
      },
      {
        "format": "vc+sd-jwt",
        "vct": "eu.europa.ec.eudi.mdl_jwt_vc_json",
        "proof": {
          "proof_type": "jwt",
          "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA"
        }
      },
      {
        "credential_identifier": "eu.europa.ec.eudiw.pid_jwt_vc_json",
        "proof": {
          "proof_type": "jwt",
          "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA"
        }
      }
    ]
  }
  ```

Response:

+ *c_nonce* - String containing a nonce
+ *c_nonce_expires_in* - Json integer denoting lifetime of c_nonce
+ *credential_responses* - Optional. Contains issued Credential
+ *notification_id* - Used by the Wallet to notify the Credential Issuer of certain events for issued Credentials. These events enable the Credential Issuer to take subsequent actions after issuance.
+ *transaction_id* - Optional, String identifying a Deferred Issuance transaction
