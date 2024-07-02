# Deferred Endpoint

This endpoint is used to issue a Credential previously requested at the Credential Endpoint or Batch Credential Endpoint in cases where the Credential Issuer was not able to immediately issue this Credential. Support for this endpoint is OPTIONAL.

There must be a batch credential request or credential and where its response contains:

+ *c_nonce* - Required. String containing a nonce
+ *c_nonce_expires_in* - Required. Json integer denoting lifetime of c_nonce
+ *transaction_id* - String identifying a Deferred Issuance transaction

Deferred Endpoint only works if the response contains a *transaction_id* which is then used to make the request.

**Endpoint**: <https://issuer.eudiw.dev/deferred_credential> (or <https://localhost/deferred_credential> if installed locally)


**Example Request:**
  
  header:

  ```
  'Content-Type': 'application/json',
  'Authorization': 'Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Ik1tWkhTQzE0UlhwNVRUQjVkMHR1UTE5a1FYVnJTVlZLUldKelVWSTVlREJ6UWkxd1ZuQXdVMGgyYncifQ.eyJhdWQiOiBbIklEIl0sICJqdGkiOiAiYWY5MmRlMDg3YzI2NGM1OThhOTNmZTExZDAyYmFmNWEiLCAiY2xpZW50X2lkIjogIklEIiwgInN1YiI6ICJiYzM4YWVhNTEwMzMzZDI4NjUyYmIyYWJkM2EwZmJhZDg5M2JiM2JmMjBlNjJlNmZjYzFhODY4ZmQ0NDNmMjgzIiwgInNpZCI6ICJaMEZCUVVGQlFtMWpXWEIwTTJsQldrWlJSR2RNZVdoTmJsRkxjemN4TW1aNWJqVXROVlZPYXpoVk9USlVlRzVUU2xOeWNIZHJVV3d3T0dWSExXa3pXRU5FVlZCMVoxRkpka0V4TFRoRmVuZzJkbXA0V0V4NVIyUlRSMVo0ZG5kb1dHbEVVVTlhUm1wTGVqWkpSbkYwUVhwR1UzRk9TbmhHUmpWQ05FaE5RVlpLWW14UVRXZFdORkZMYzJKdFJteGlYMnBGT1dwaU5rTkdiamRGTFZwSlYwMXVWbDlCWlZKTWRrSkdkRGhET1dzM09FZHdjak4wYjIxWGVVeExSMkpVVms1V2FFTnFTa0pOZHpCMFZVeEpaa0V6TVVnelJGbHJZVFZSYkZOMllUUTJNVlpEVW0xeGJYaDVjblJ3ZDFKMFZrZE9abVJSVDNWbGEzZHFRbTFaUVhWRGIwVjNRamQyWmxCcVZBPT0iLCAidG9rZW5fY2xhc3MiOiAiYWNjZXNzX3Rva2VuIiwgImlzcyI6ICJodHRwczovL2lzc3Vlci5ldWRpdy5kZXYiLCAiaWF0IjogMTcxODcxNzAzOSwgImV4cCI6IDE3MTg3MjA2Mzl9.tQCfMGu_IPv4B5BGzKPWbS_i70gaEbaQ9JpoOgfKBkuAWYrMDmD8YVUEpDO3W-Gu6mkix_ev4IBQOX3gac_Eng'
  ```

  payload:
  ```
  'transaction_id': '3J0VrO3TiQAPHsMe8Nt89g'
  ```

Response:

+ *c_nonce* - String containing a nonce
+ *c_nonce_expires_in* - Json integer denoting lifetime of c_nonce
+ *credential* - Optional. Contains issued Credential
+ *credential_responses* - Optional. Contains issued Credentials
+ *notification_id* - Used by the Wallet to notify the Credential Issuer of certain events for issued Credentials. These events enable the Credential Issuer to take subsequent actions after issuance.
