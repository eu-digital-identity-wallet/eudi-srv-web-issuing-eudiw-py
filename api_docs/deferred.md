# Deferred Endpoint

This endpoint is used to issue a Credential previously requested at the Credential Endpoint or Batch Credential Endpoint in cases where the Credential Issuer was not able to immediately issue this Credential. Support for this endpoint is OPTIONAL.

There must be a credential request where it's response contains:

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

+ *credentials* - OPTIONAL. Contains an array of one or more issued Credentials. It MUST NOT be used if the transaction_id parameter is present.
+ *transaction_id* - OPTIONAL. String identifying a Deferred Issuance transaction. This parameter is contained in the response if the Credential Issuer cannot immediately issue the Credential. 
+ *notification_id* - OPTIONAL. String identifying one or more Credentials issued in one Credential Response.
