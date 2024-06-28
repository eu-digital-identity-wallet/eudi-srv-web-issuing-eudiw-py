# Token request (Post)

**Endpoint**: <https://issuer.eudiw.dev/token> (or <https://localhost/token> if installed locally)

## Token request with PKCE

The following parameters are supported:

+ *grant_type* - Required. Value must be set to “authorization_code”
+ *redirect_uri* - Required. Must be identical value to authorization request redirect_uri
+ *client_id* - Required.
+ *state* - Recommended. 
+ *code* - Required. The authorization code received from authorization
+ *code_verifier* - Required. RFC 7636 see section 4.1


**Example Request:**

header:
```
'Content-Type': 'application/x-www-form-urlencoded
```

payload:
```
grant_type=authorization_code&code=Z0FBQUFBQm1hWG5nb2ZKQlo0cEpuQ1pPZWpERU9iczhPYndETzRuRU5OZmkyX3FnNzAtM3ZYRmNpamZRdUF0d1B6Y0MzVmhlNnl2QWtjT281cW5lQjFSWW9RYVVmcmNQQVdVcjcxUUZ4RDFtYTZ0eWJNT3Y1aGI4VFAxX3hKd2FWeHpBMWZUYVNJcmY1LTNQRUdTbUJ0clZBdmJoeVpIZDdRN29maUdNTUh6OVhncWtpcFQ3d2xKVVRkYTRhU19EZHV5QTRHalgyRmtrVWNvcGdRUmRVMnI5X2NtYTJZZWVhUXl4NkhGRzBMaEN2c0pGQnBIemJfUUtIUlpMY09qQmRRSzI0OHdMNDRFWXpSU1lTRDhRNEZfYTI2a1hXQV80ZF93Z2VQdnAwY1VHcHVBaVZIZTZaS283cW5VeTVPcWlPQldxWm1ObHhIZ08xcHhFTENsajFwTDRmNVhZQ1pzbWlnSVd4TGZDcHYxTXdJV2cwdThzcVFqcWNDQVBiX0U1OUpRZ3RiZG41bTFVSHdoUk1KYlZEc0dIbXN1UmJRZ1Y5RXZrYURwLUMzd3FMLW0tV0Q0VUM3eGtFZER1bjN4ZWttWWxtbDBham9uM01XVy1mdUFqd2I5UTdtSU4xYmJGaEhOdEVHR3pPV2lLQjIwcmhkcjYxSG04R1lHWTdkcEE1Si1GVzRocGpvR1BzS1ZaSEU3WEY1QjJkYjNXY0wxSXE3TnZMb3ZoVkx4T3ZWRkxsUkV6QnNfYWxVNmdzNUh6em1Pb0I1eGhFLWdNSmRtWXVMV1pCZl8xSnhrZ2hmdjJNS3doeUpXWlRLM3FqcThMTU04MmZLT3hjQXNtaGNJMTlXTXdDYXJZbk5kX3lCQlNSRWk1T1pGd2NaYjdGNFVtUk1DRTRUaGw1OElFRVh3SGRPUmtPbnc9&redirect_uri=...&client_id=ID&state=vFs5DfvJqoyHj7_dZs2JbdklePg6pMLsUHHmVIfobRw&code_verifier=FnWCRIhpJtl6IYwVVYB8gZkQsmvBVLfU4HQiABPopYQ6gvIZBwMrXg
```

Response:

+ *token_type*
+ *scope* - If authorization through scope
+ *authorization_details* - If authorization through authorization details
+ *access_token*
+ *expires_in*
+ *refresh_token*
+ *id_token*

## Token request without PKCE

The "code" need to be saved to make the POST request for the Token.

The following parameters are supported:

+ *grant_type* - Required. Value must be set to “authorization_code”
+ *redirect_uri* - Required. Must be identical value to authorization requrest redirect_uri
+ *client_id* - Required.
+ *state* - Recommended. 
+ *code* - Required. The authorization code received from authorization


**Example Request:**

header:
```
'Content-Type': 'application/x-www-form-urlencoded
```

payload:
```
grant_type=authorization_code&code=Z0FBQUFBQm1hWG5nb2ZKQlo0cEpuQ1pPZWpERU9iczhPYndETzRuRU5OZmkyX3FnNzAtM3ZYRmNpamZRdUF0d1B6Y0MzVmhlNnl2QWtjT281cW5lQjFSWW9RYVVmcmNQQVdVcjcxUUZ4RDFtYTZ0eWJNT3Y1aGI4VFAxX3hKd2FWeHpBMWZUYVNJcmY1LTNQRUdTbUJ0clZBdmJoeVpIZDdRN29maUdNTUh6OVhncWtpcFQ3d2xKVVRkYTRhU19EZHV5QTRHalgyRmtrVWNvcGdRUmRVMnI5X2NtYTJZZWVhUXl4NkhGRzBMaEN2c0pGQnBIemJfUUtIUlpMY09qQmRRSzI0OHdMNDRFWXpSU1lTRDhRNEZfYTI2a1hXQV80ZF93Z2VQdnAwY1VHcHVBaVZIZTZaS283cW5VeTVPcWlPQldxWm1ObHhIZ08xcHhFTENsajFwTDRmNVhZQ1pzbWlnSVd4TGZDcHYxTXdJV2cwdThzcVFqcWNDQVBiX0U1OUpRZ3RiZG41bTFVSHdoUk1KYlZEc0dIbXN1UmJRZ1Y5RXZrYURwLUMzd3FMLW0tV0Q0VUM3eGtFZER1bjN4ZWttWWxtbDBham9uM01XVy1mdUFqd2I5UTdtSU4xYmJGaEhOdEVHR3pPV2lLQjIwcmhkcjYxSG04R1lHWTdkcEE1Si1GVzRocGpvR1BzS1ZaSEU3WEY1QjJkYjNXY0wxSXE3TnZMb3ZoVkx4T3ZWRkxsUkV6QnNfYWxVNmdzNUh6em1Pb0I1eGhFLWdNSmRtWXVMV1pCZl8xSnhrZ2hmdjJNS3doeUpXWlRLM3FqcThMTU04MmZLT3hjQXNtaGNJMTlXTXdDYXJZbk5kX3lCQlNSRWk1T1pGd2NaYjdGNFVtUk1DRTRUaGw1OElFRVh3SGRPUmtPbnc9&redirect_uri=...&client_id=ID&state=vFs5DfvJqoyHj7_dZs2JbdklePg6pMLsUHHmVIfobRw
```

Response:

+ *token_type*
+ *scope* - If authorization through scope
+ *authorization_details* - If authorization through authorization details
+ *access_token*
+ *expires_in*
+ *refresh_token*
+ *id_token*

