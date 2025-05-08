# Credential Offer 

## 1. Authorization code flow
 
**Endpoint**: <https://issuer.eudiw.dev/credential_offer> (or <https://localhost/credential_offer> if installed locally)

A form is presented showing the Request Credentials for your EUDI Wallet that can be requested.

![image](./images/credential_offer1.png)

After choosing the credential(s) and submitting, a QR code and DeepLink is generated:

![image](./images/credential_offer2.png)

This generated DeepLink contains information about the credentials chosen in the form.

 **Example:**

   if the selected options are Personal Identification Data and the Mobile Driver's License in both sd-jwt and mdoc format:

```
openid-credential-offer://credential_offer?credential_offer=%7B%22credential_issuer%22:%20%22https://issuer.eudiw.dev%22%2C%20%22credential_configuration_ids%22:%20%5B%22eu.europa.ec.eudi.pid_jwt_vc_json%22%2C%20%22eu.europa.ec.eudi.mdl_jwt_vc_json%22%2C%20%22eu.europa.ec.eudi.pid_mdoc%22%2C%20%22eu.europa.ec.eudi.mdl_mdoc%22%5D%2C%20%22grants%22:%20%7B%22authorization_code%22:%20%7B%7D%7D%7D>
```

## 2. Pre-Authorized Code Flow

Currently only suporting a loyalty credential through form

**Endpoint**: <https://dev.issuer.eudiw.dev/dynamic/preauth> (or <https://localhost/dynamic/preauth> if installed locally)


Example of generated DeepLink:
```
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%20%22https://issuer.eudiw.dev/%22%2C%20%22credential_configuration_ids%22:%20%5B%22eu.europa.ec.eudi.loyalty_mdoc%22%5D%2C%20%22grants%22:%20%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%20%7B%22pre-authorized_code%22:%20%22Z0FBQUFBQm1mWHdPdlR0X0JBTjRXR2EtRVFkZVpKTXFaTW95U29mVElnTkQ1cnphTEg5ajg0YnJTMk1JLUZaUHFlSUxuVDZ1c1hNRnZJQ3YzNUZfaVZuRVZueEotb1ROWkUyOTNGbUk2ZUJBemZXT2k0ZThRZHVTMWo2Z2JUYjJFOGwxQURxMWdYaHZjNFNCNXdkRVpocVlPV3VNSnlsT1g2Vjl2Nk1IOGJ0aWg2T2tMa1YyaVVudFJwc2owVzE4UGlod3RBM2w0UF9aQzdzTzFQUUZKNkRrYmtnei14ZmFXRWczWXV3Y2hGOFd2YUp6Q0dRMTB1aVNBTHNSSTg2aUJKNC0tTFBjSHFiTnRaRHpEdFdRNmlfcXM2clFaVXVXdjQ2TGZlejlKeXdjSEJDV0E3VVB1aGhhMDI2dlBMWXAyT3VXQ0F6Z1FvcHVVMUFhMUdxdl81WUpvbFp4bGNWRXRwdE85TC1yb29hbi1QbUFTN3BPX2NDM1pjdGk3b3d4VlVNMjhYelBjSWhZM3BoRzJhUFNZTzV2dFpZVUpreVpiT2w5c0hRR3VuZXY5enRaWHJRcEV0NEVTbnRpZkNpNU14QlJGWjVaY3ZUc0lkMUZ1MXJNckZzblBrNXl2ejBWWGJHQmJ4QUZLSjFvZExFSW1oaWdCS3FmSzM3dFlLOUk0NndUendvdmxCZWZtOWtPMzA0OEtTTnFxZmphYmRzc2Q5bXJpVlhwV2o4QWZ6OXNZNldMd1ctOW9pYmlnTHZnYklQVW9zV3JmUjdLM3oxVkpoQVJMeTlOaS1KSUFkSWlkc0xQNEFUaHoxNVYxUS1Qa3ZISzVpWjJ2UDB5MUZUc3IxMDE5dTR1YS10S2Q2eUl5R3FMMWhPQkJkSGdvSFJDOW1vbjg2VVJsVWpsckVaUTFnVVBHaXc9%22%7D%7D%7D
```
