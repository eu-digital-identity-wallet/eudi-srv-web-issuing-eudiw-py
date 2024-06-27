## 0. Configuration

The following document specifies the changes needed to add a new credential to the issuer.
We will use a generic loyalty card credential as an example for this configuration.

## 1. Metadata Configuration
Add a new json file with the credential metadata to ```app/metadata_config/credentials_supported```

For this example we will use ```app/metadata_config/credentials_supported/loyalty_mdoc.json```

Example loyalty card metadata for mso_mdoc format (ISO.18013-5):
```json
{
  "eu.europa.ec.eudi.loyalty_mdoc": {
    "format": "mso_mdoc",
    "doctype": "eu.europa.ec.eudi.loyalty.1",
    "scope": "eu.europa.ec.eudi.loyalty.1",
    "cryptographic_binding_methods_supported": [
      "jwk",
      "cose_key"
    ],
    "credential_signing_alg_values_supported": [
      "ES256"
    ],
    "proof_types_supported": {
      "jwt": {
        "proof_signing_alg_values_supported": [
          "ES256"
        ]
      },
      "cwt": {
        "proof_signing_alg_values_supported": [
          "ES256"
        ]
      }
    },
    "display": [
      {
        "name": "Loyalty",
        "locale": "en",
        "logo": {
          "url": "https://examplestate.com/public/pid.png",
          "alt_text": "A square figure of a PID"
        }
      }
    ],
    "claims": {
      "eu.europa.ec.eudi.loyalty.1": {
        "given_name": {
          "mandatory": true,
          "value_type": "string",
          "display": [
            {
              "name": "Current First Names",
              "locale": "en"
            }
          ]
        },
        "family_name": {
          "mandatory": true,
          "value_type": "string",
          "display": [
            {
              "name": "Current Family Name",
              "locale": "en"
            }
          ]
        },
        "company": {
          "mandatory": true,
          "value_type": "string",
          "display": [
            {
              "name": "Loyalty card company",
              "locale": "en"
            }
          ]
        },
        "client_id": {
          "mandatory": true,
          "value_type": "string",
          "display": [
            {
              "name": "Comapny internal client id",
              "locale": "en"
            }
          ]
        },
        "issuance_date": {
          "mandatory": true,
          "display": [
            {
              "name": "Date of credential issuance",
              "locale": "en"
            }
          ]
        },
        "expiry_date": {
          "mandatory": true,
          "display": [
            {
              "name": "Date of credential expiration",
              "locale": "en"
            }
          ]
        }
      }
    }
  }
}
```

## 2. Service Configuration

Located in ```/app/app_config/config_service.py```

- Add a new entry to config_doctype (Using the doctype of the credential as key)

This configures the issuing authority, organization and validity used for the credential.
```python
"eu.europa.ec.eudi.loyalty.1": {
    "issuing_authority": "Test QEAA issuer",
    "organization_id": pid_organization_id,
    "validity": qeaa_validity,
    "organization_name": "Test QEAA issuer",
    "namespace": "eu.europa.ec.eudi.loyalty.1",
}
```
- Add a new entry to auth_method_supported_credencials (Using the credential identifier specified in the metadata)

This configures the type of user authentication allowed for the credential. Either authentication through a PID using openid4VP or through a country (iDP/eidas node or a simple form)
The following examples adds the loyalty credential to the country authentication.
```python
auth_method_supported_credencials = {
    "PID_login": [
    ],
    "country_selection": [
        "eu.europa.ec.eudi.loyalty_mdoc",
    ],
}
```

## 3. Configuration of Countries
Located in ```/app/app_config/config_countries.py```

Here we will configure which countries or if the form supports the loyalty credential.

Add an entry to the supported_credentials of a country using the credential id defined in the metadata.

An example for this loyalty credential:

```python
"supported_credentials": [
  "eu.europa.ec.eudi.loyalty_mdoc"
]
```
