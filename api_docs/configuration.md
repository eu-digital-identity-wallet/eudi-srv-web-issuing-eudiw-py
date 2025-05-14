# Configuration

For configuring your locally installed version of the EUDIW Issuer, you need to change the following configurations.

## 1. Service Configuration

Base configuration for the EUDIW Issuer is located in ```app/app_config/config_service.py```.

Parameters that should be changed:

- `service_url` (Base url of the service)
- `trusted_CAs_path` (Path to a folder with trusted IACA certificates)
- `eidasnode_url` (eIDAS Node base URL. Only needs to be changed if you're configuring the eIDAS Node)
- `eidasnode_lightToken_connectorEndpoint` (eIDAS node connector endpoint for lightrequest. Only needs to be changed if you're configuring the eIDAS Node.)

You must copy your IACA trusted certificate(s) (in PEM format) to the `trusted_CAs_path` folder - you can find an example test IACA certificate for country Utopia (UT) [here](test_tokens/IACA-token/PIDIssuerCAUT01.pem.gz) -.

## 2. Configuration of Countries

The supported countries configuration of the EUDIW Issuer is located in ```/app/app_config/config_countries.py```.

Parameters that should be changed for each country:

+ `name` - name of the country
+ `connection_type`- options are eidasnode, oauth, and openid.
+ `pid_mdoc_privkey`- Document/Credential signer (DS) private key file location.
+ `pid_mdoc_privkey_passwd` - Document/Credential signer (DS) private key password.( Can be None or bytes. Example: b"password")
+ `pid_mdoc_cert` - Document/Credential signer (DS) certificate file location.


You must copy your DS private key (in PEM format) to `pid_mdoc_privkey` file (the password must be defined in `pid_mdoc_privkey_passwd`), and the certificate (in DER format) to `pid_mdoc_cert` file.

You can find example test private DS keys and certificates, for country Utopia (UT) [here](test_tokens/DS-token/) - the password of the example test private DS keys is b"pid-ds-0002".
To decrypt the private key you can run the following command `openssl ec -in PID-DS-0002.pid-ds-0002.key.pem -out PID-DS-0002-decrypted.key.pem`.


## 3. OID4VCI configuration 

For configuring the installed [idpy-oidc](https://github.com/IdentityPython/idpy-oidc) and [openid4v](https://github.com/rohe/openid4v) libraries, you need to change the following parameters in the ```app/app_config/oid_config.py``` configuration file:

- port

## 4. Metadata configuration

The EUDIW Issuer OAuth2 metadata configuration files are located in ```app/metadata_config/metadata_config.json``` and ```app/metadata_config/openid-configuration.json```

You must change the base URL of the endpoints from ```https://issuer.eudiw.dev``` to a custom one or ``` https://localhost``` if installed locally

Example:
```json
"credential_issuer": "{base_url}",
"credential_endpoint": "{base_url}/credential",
"notification_endpoint": "{base_url}/notification",
"deferred_credential_endpoint": "{base_url}/deferred_credential",
```
