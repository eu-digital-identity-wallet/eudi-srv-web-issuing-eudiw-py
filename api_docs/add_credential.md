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
      "scope": "eu.europa.ec.eudi.loyalty_mdoc",
      "cryptographic_binding_methods_supported": [
        "jwk", "cose_key"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "proof_types_supported": {
        "jwt": {
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
            "uri": "https://examplestate.com/public/pid.png",
            "alt_text": "A square figure of a PID"
          }
        }
      ],
      "claims": [
          {
            "path":["eu.europa.ec.eudi.loyalty.1","given_name"],
            "mandatory": true,
            "value_type":"string",
            "source":"user",
            "display": [
              {
                "name": "Given Name",
                "locale": "en"
              }
            ]
          },
          {
            "path":["eu.europa.ec.eudi.loyalty.1","family_name"],
            "mandatory": true,
            "value_type":"string",
            "source":"user",
            "display": [
              {
                "name": "Family Name",
                "locale": "en"              }
            ]
          },
          {
            "path":["eu.europa.ec.eudi.loyalty.1","company"],
            "mandatory": true,
            "value_type":"string",
            "source":"user",
            "display": [
              {
                "name": "Loyalty Card Company",
                "locale": "en"              }
            ]
          },
          {
            "path":["eu.europa.ec.eudi.loyalty.1","client_id"],
            "mandatory": true,
            "value_type":"string",
            "source":"user",
            "display": [
              {
                "name": "Client ID",
                "locale": "en"              }
            ]
          },
          {
            "path":["eu.europa.ec.eudi.loyalty.1","issuance_date"],
            "mandatory": true,
            "source":"issuer",
            "display": [
              {
                "name": "Issuance Date",
                "locale": "en"
              }
            ]
          },
          {
            "path":["eu.europa.ec.eudi.loyalty.1","expiry_date"],
            "mandatory": true,
            "source":"issuer",
            "display": [
              {
                "name": "Expiry Date",
                "locale": "en"
              }
            ]
          }
      ],
      "issuer_config":{
            "issuing_authority":"Test PID issuer",
            "organization_id":"EUDI Wallet Reference Implementation",
            "validity":90,
            "organization_name":"Test PID issuer",
            "namespace": "eu.europa.ec.eudi.loyalty.1"
        }
    }
  }
```

If you want to issue a different attestation/credential using this example as a template, please choose a different namespace, doctype, and scope, and modify the claims to include the required attributes.

For more information on the metadata parameters, please refer to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-metadata.

**Extra Parameters** 
- source: Where the attributed is sourced from. Either the user or issuer (Example: Issuance Date is filled in by the issuer while given_name is filled in by the user on the form)
- value_type: Type of the value expected. This will add the attribute to the forms. (Can be string, full-date, jpeg, driving_privileges, uint, bool)
- issuer_conditions: a json structure with extra parameters and logic allowing for more complex credentials.
- issuer_config: a json structure with extra parameters used in credential creation

### 1.1 Issuer Conditions
The issuer_conditions structure can be used in the metadata as follows:
- Specific to a claim:

  Allows for the usage of nested claims by defining the value_type as another claims structure with the same identifier inside the issuer_conditions. Additionally, it can specify the cardinality not only of the claim itself but also of its nested claims.  
  As an example we have the credential Portable Document A1 (PDA1) which has a claim places_of_work.  
This claim allows for two nested claims, a place_of_work and a no_fixed_place.  
  We can define the value_type as the structure places_of_work_attributes, the identifier we will use inside issuer_conditions, the places_of_work_attributes will contain two claim structures, place_of_work and no_fixed_place. Inside these two structures we define the nested claim as seen below.  
  Within each nested claim, we can once again add issuer_conditions, specifying its cardinality and a not_used_if field. In this case, the not_used_if field ensures that place_of_work cannot be used if no_fixed_place is present, and vice versa.
  
  ```json
  "places_of_work": {
          "mandatory": true,
          "value_type":"places_of_work_attributes",
          "source":"user",
          "display": [
            {
              "name": "Places of Work",
              "locale": "en"            }
          ],
          "issuer_conditions": {
            "cardinality": {
              "min": 1,
              "max": 1
            },
            "places_of_work_attributes":{
              "place_of_work": {
                "mandatory": false,
                "value_type": "place_of_work_attributes",
                "source": "user",
                "issuer_conditions": {
                  "cardinality": {
                    "min": 0,
                    "max": "n"
                  },
                  "not_used_if": {
                      "logic": "any",
                      "attributes": ["no_fixed_place"]
                  },
                  "place_of_work_attributes":{
                    "company": {
                      "mandatory": true,
                      "value_type": "string",
                      "source": "user"
                    },
                    "flag_base_home_state": {
                      "mandatory": false,
                      "value_type": "string",
                      "source": "user"
                    },
                    "company_id": {
                      "mandatory": false,
                      "value_type": "string",
                      "source": "user"
                    },
                    "id_type": {
                      "mandatory": false,
                      "value_type": "string",
                      "source": "user"
                    },
                    "street": {
                      "mandatory": false,
                      "value_type": "string",
                      "source": "user"
                    },
                    "town": {
                      "mandatory": true,
                      "value_type": "string",
                      "source": "user"
                    },
                    "postal_code": {
                      "mandatory": false,
                      "value_type": "string",
                      "source": "user"
                    },
                    "country_code": {
                      "mandatory": true,
                      "value_type": "string",
                      "source": "user"
                    }
                  }
                }
              },
              "no_fixed_place": {
                "mandatory": false,
                "value_type": "no_fixed_place_attributes",
                "source": "user",
                "issuer_conditions": {
                  "cardinality": {
                    "min": 0,
                    "max": "n"
                  },
                  "not_used_if": {
                      "logic": "any",
                      "attributes": ["place_of_work"]
                  },
                  "no_fixed_place_attributes":{
                    "country_code": {
                      "mandatory": true,
                      "value_type": "string",
                      "source": "user"
                    }
                  }
                }
              }
            }
          }
        }
  ```
- Encompassing multiple claims:
  
  Currently this approach supports the condition at_least_one_of which specifies that at least one of these claims need to be present in the credential.  
  As an example, the Health ID credential requires at least one of the following claims to be present: health_insurance_id, patient_id, tax_number, one_time_token.  
  For this example the following issuer_conditions would be added inside the claims{} field but outside any specific claim.
  
```json
"overall_issuer_conditions": {
          "at_least_one_of":[
                "health_insurance_id",
                "patient_id",
                "tax_number",
                "one_time_token"
            ]
        }
```


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

- If this credential supports Dynamic Credential Request, add a new entry to dynamic_issuing

This configures which attestation and attributes are asked for in the OID4VP Request When using Dynamic credential request to issue this credential.

Follows the format:
```python
dynamic_issuing = {
      "credential_configuration_id":{
          "DocType":{"Namespace":["attribute",...,"attribute"]}
      }
}
```

Example from age over 18 pseudonym:
```python
dynamic_issuing = {
      "eu.europa.ec.eudi.pseudonym_over18_mdoc":{
          "eu.europa.ec.eudi.pid.1":{"eu.europa.ec.eudi.pid.1":["age_over_18"]}
      }
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
