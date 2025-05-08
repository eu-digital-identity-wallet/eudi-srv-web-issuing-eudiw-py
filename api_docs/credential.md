# Credential Request (Post)

**Endpoint**: <https://issuer.eudiw.dev/credential> (or <https://localhost/credential> if installed locally)


Header:

+ *Content-Type* - *application/json*
+ *Authorization* - *Bearer token*

Payload:

+ *credential_configuration_id* - REQUIRED if a credential_identifiers parameter was not returned from the Token Response as part of the authorization_details parameter.
+ *proofs* - OPTIONAL. Object providing one or more proof of possessions of the cryptographic key material to which the issued Credential instances will be bound to. The proofs parameter MUST NOT be present if proof parameter is used. 
+ *credential_response_encryption* - OPTIONAL. Object containing information for encrypting the Credential Response. If this request element is not present, the corresponding credential response returned is not encrypted.
+ *proof* - OPTIONAL if proofs is used. Supported: JWT


**Example Requests:**
  
  header:
  ```
  'Content-Type': 'application/json',
  'Authorization': 'Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Ik1tWkhTQzE0UlhwNVRUQjVkMHR1UTE5a1FYVnJTVlZLUldKelVWSTVlREJ6UWkxd1ZuQXdVMGgyYncifQ.eyJzY29wZSI6ICJvcGVuaWQiLCAiYXVkIjogWyJJRCJdLCAianRpIjogImZiMGI3NzdmODk5ODQ2MjBiMjQwZjNhZjczNjFlYzU3IiwgImNsaWVudF9pZCI6ICJJRCIsICJzdWIiOiAiODQzZjFjN2FkMDRjYTAyYTY1ZWEzYTc0MWY2YjkzOGNjN2U2N2E3OGQ0ZmFhN2YwMDYyNWFkYTFkZTM2OTM1NiIsICJhY3IiOiAidXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6SW50ZXJuZXRQcm90b2NvbFBhc3N3b3JkIiwgInNpZCI6ICJaMEZCUVVGQlFtMWhSbEYwVFV0TVRYUnJkak5wVkRjdFRWOTFWa3RRUmtkcVptTjFhamxETUdKemMzUkpXV1ZzUTBoeFVHazNZbXhpVjNaV1QzZDVjbFJ0Wkd0bk16Qk9WekEwV0Y5T2NuRkZYMWg2UjFWSGFuWlhkV0V0UmkwdGRtcFZVbTl1YzFJM2MwdDFjVUoyVGs1RGMyNXlaRVpxWkhKa1MwSkJObWxpY1hSS1JFaEVkVXRMT1dOWFRYcFBWMHB1VlVSWE9UTjZVVUZMYmw5RFNGOXVMWEJaY1VwRFRrbGxYMnQzVURadlNra3dka1owZEd0Vk9VVkRVMGhzWlhwelREVnpiemRuYzFCTk16TTFjVEZoUTA0eGN6Um5SekU1UnpsZlJrYzBZMDFXU2tGbmJYUkxXV1ZOVjNGRk9VRkRVMVl5Y25KWWRuZFdlR2h4VVZBMGVUZHJWMWQzTW1vMFRWRndVa3RJZFdGc2QySTNMVkozWW5wTVpWb3pRbEU5UFE9PSIsICJ0b2tlbl9jbGFzcyI6ICJhY2Nlc3NfdG9rZW4iLCAiaXNzIjogImh0dHBzOi8vZGV2Lmlzc3Vlci5ldWRpdy5kZXYiLCAiaWF0IjogMTcxODExMzMzNCwgImV4cCI6IDE3MTgxMTY5MzR9.QA7er_vPCqQsXjP3BtL2uFT1tKYKqaV7RRd_rwcdBOOO_uniax2uwjsWp5m5TAXYjzhec_ioL3kmv2OmRSLhlg'
  ```

  payload:
  ```Json
{
    "credential_configuration_id": "eu.europa.ec.eudi.pid_vc_sd_jwt",
    "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA"
  }
}
  Request with multiple proofs:
  payload:
  ```Json
{
 "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc",
  "proofs": {
    "jwt": ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA","eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA","eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA"]
  }
}

  ```
  Request for encrypted response:  
  payload:
  ```Json
{
    "credential_configuration_id": "eu.europa.ec.eudi.pid_jwt_vc_json",
    "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA"
  },
  "credential_response_encryption":{
    "jwk":{
        "kty": "RSA",
        "e": "AQAB",
        "use": "enc",
        "kid": "TnZdnKa6J2CNWVqiXfeA0cTncNEUpW1aUz7sjLGT3KM",
        "alg": "RSA1_5",
        "n": "vb0jIdYbhIWgUguleNnycccu1O3of20BghIllQ9jjaa8QQNQaVN3KkRk6-YoeOz6PUfEtlZPBSQ3qmXndX3f1JPQ3m1hRor6oWs7oBzAndKbKAPtgnLl5iOMcQDW0K6OmIJJnrtrx6zTZCjcoJhdN063ZeUhmeQ5-K5kF0Ka9ZSdmqvTwpYmSTTbxrVtIJvq-LxqxPEb1a_cMVcZ4VahO5GCh8bGBcw0Rity9JGGxUo2m2c1e5cyqn5nN5tnHh0A17qinxlWg65CeOv9LTrEp4inf4ymlneyoNzhugdRqf5aS_3lLL-R4aQOxsm1nhB0JMpHKf23YRuNDT945GWP0w"
    },
    "alg":"RSA1_5",
    "enc":"A256GCM"
  }
}
  ```


Response:

+ *credentials* - OPTIONAL. Contains an array of one or more issued Credentials. It MUST NOT be used if the transaction_id parameter is present.
+ *transaction_id* - OPTIONAL. String identifying a Deferred Issuance transaction. This parameter is contained in the response if the Credential Issuer cannot immediately issue the Credential. 
+ *notification_id* - OPTIONAL. String identifying one or more Credentials issued in one Credential Response.

