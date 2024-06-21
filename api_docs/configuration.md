## 0. Configuration

The following document specifies some of the configuration that should be done to the issuer

## 1. Service Configuration
Base configuration for issuer service.

Located in ```/app/app_config/config_service.py```

Parameters that should be changed:
- service_url (Base url of the service)
- trusted_CAs_path (Path to a folder with trusted DER CA certificates)
- eidasnode_url (eIDAS Node base URL)
- eidasnode_lightToken_connectorEndpoint (eIDAS node connector endpoint for lightrequest)

## 2. Configuration of Countries
This file configures the supported countries of the issuer.

Located in ```/app/app_config/config_countried.py```

Parameters that should be changed for each country:
- pid_mdoc_privkey (Private key used to sign the credential)
- pid_mdoc_cert (Certificate to be included in the credential)

## 3. OID4VCI configuration 
Configures the [idpy-oidc](https://github.com/IdentityPython/idpy-oidc) and [openid4v](https://github.com/rohe/openid4v) services

Located in ```app/app_config/oid_config.json```

Parameters that should be changed:
- domain
- port
