# Configuration

This document specifies the changes needed to add a new attestation/credential to the EUDIW Issuer.
We will use a generic loyalty card credential as an example for this configuration.

## 1. Metadata Configuration

Add a new json file with the credential metadata to ```app/metadata_config/credentials_supported```

For this example we will use ```app/metadata_config/credentials_supported/loyalty_mdoc.json```

Example loyalty card metadata for mso_mdoc format (ISO 18013-5), with namespace `eu.europa.ec.eudi.loyalty_mdoc`:

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

If you want to issue a different attestation/credential using this example as a template, please choose a different namespace, doctype, and scope, and modify the claims to include the required attributes.

For more information on the metadata parameters, please refer to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-metadata.




## 2. Service Configuration

In the service configuration file (```app/app_config/config_service.py```), you need to configure the issuing authority, organization and validity of the credential.

- Add a new entry to config_doctype (using the doctype of the credential as key)

```python
"eu.europa.ec.eudi.loyalty.1": {
    "issuing_authority": "Test QEAA issuer",
    "organization_id": pid_organization_id,
    "validity": qeaa_validity,
    "organization_name": "Test QEAA issuer",
    "namespace": "eu.europa.ec.eudi.loyalty.1",
}
```

- Add a new entry to auth_method_supported_credencials (using the credential identifier specified in the metadata)

    This configures the type of user authentication allowed for the credential. You may choose authentication through a PID using OpenId4VP, or through a country selection (options are: IDP, eidas node or a simple form).

    In the following examples the authentication allowed for the loyalty credential is country selection.

```python
auth_method_supported_credencials = {
    "PID_login": [
    ],
    "country_selection": [
        "eu.europa.ec.eudi.loyalty_mdoc",
    ],
}
```

## 3. Configuration of Countries supported by the EUDIW Issuer

Located in ```app/app_config/config_countries.py```, this configuration file contains configuration data related to the countries supported by the PID Issuer, and the credentials supported by each country.

For example, to add the loyalty credential to the `formCountry`, you need to add the loyalty credential id (defined in the metadata) to the `supported_credentials` of the `formCountry`.

```python
"supported_credentials": [
  "eu.europa.ec.eudi.loyalty_mdoc"
]
```
