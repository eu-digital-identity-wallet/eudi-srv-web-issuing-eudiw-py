# Configuration

For configuring your locally installed version of the EUDIW Issuer, you need to change the following configurations.

## 1. Service Configuration

Base configuration for the EUDIW Issuer is located in ```app/app_config/config_service.py```.

Parameters that should be changed:

- `service_url` (Base url of the service)
- `trusted_CAs_path` (Path to a folder with trusted DER IACA certificates)
- `eidasnode_url` (eIDAS Node base URL. Only needs to be changed if you're configuring the eIDAS Node)
- `eidasnode_lightToken_connectorEndpoint` (eIDAS node connector endpoint for lightrequest. Only needs to be changed if you're configuring the eIDAS Node.)

## 2. Configuration of Countries

The supported countries configuration of the EUDIW Issuer is located in ```/app/app_config/config_countries.py```.

Parameters that should be changed for each country:

+ `name` - name of the country
+ `connection_type`- options are eidasnode, oauth, and openid.
+ `pid_mdoc_privkey`- Document/Credential signer (DS) private key location.
+ `pid_mdoc_privkey_passwd` - Document/Credential signer (DS) private key password.
+ `pid_mdoc_cert` - Document/Credential signer (DS) certificate location.


## 3. OID4VCI configuration 

For configuring the installed [idpy-oidc](https://github.com/IdentityPython/idpy-oidc) and [openid4v](https://github.com/rohe/openid4v) libraries, you need to change the following parameters in the ```app/app_config/oid_config.json``` configuration file:

- domain
- port
