## Credential Offer 

<https://issuer.eudiw.dev/credential_offer>

If running your own version of the issuer locally, it can be accessed on ```http://127.0.0.1:{flask_port}/credential_offer```

A form is presented showing the Request Credentials for your EUDI Wallet that can be requested.

![image](https://github.com/devisefutures/eudiw-issuer/assets/61158161/3bf05140-2416-44b5-970f-7b1c8bc2525a)

After submitting, a qrcode and DeepLink is generated:

![image](https://github.com/devisefutures/eudiw-issuer/assets/61158161/368e34fb-7f06-4c99-8c2b-e4601bccfa9e)

This generated DeepLink contains information about the credentials chosen in the form.

 *Example:*

   if the selected options are Personal Identification Data and the Mobile Driver's License in both sd-jwt and mdoc format:
   
  <openid-credential-offer://credential_offer?credential_offer=%7B%22credential_issuer%22:%20%22https://issuer.eudiw.dev%22%2C%20%22credential_configuration_ids%22:%20%5B%22eu.europa.ec.eudiw.pid_jwt_vc_json%22%2C%20%22eu.europa.ec.eudiw.mdl_jwt_vc_json%22%2C%20%22eu.europa.ec.eudiw.pid_mdoc%22%2C%20%22eu.europa.ec.eudiw.mdl_mdoc%22%5D%2C%20%22grants%22:%20%7B%22authorization_code%22:%20%7B%7D%7D%7D>
