# Credential Offer Endpoint

Generates an OID4VCI (OpenID for Verifiable Credential Issuance) Credential Offer. 

### Request

`GET /credential_offer_create`

**Query Parameters:**

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `credential_configuration_id` | `string` | **Yes** | The credential configuration identifier of the credential type to be issued. (Found in Issuer Metadata) |

**Example Curl**

```bash
curl -X GET "https://issuer.eudiw.dev/credential_offer_create?credential_configuration_id=eu.europa.ec.eudi.pid_mdoc"
```

### Responses

**Success (200 OK)**

Returns the Credential Offer JSON.

```json
{
   "credential_configuration_ids":[
      "eu.europa.ec.eudi.pid_mdoc"
   ],
   "credential_issuer":"https://issuer.eudiw.dev",
   "grants":{
      "authorization_code":{
         "issuer_state":"c6128dad-7b3e-42c7-9845-644a80574f51"
      }
   }
}
```

**Error (400 Bad Request)**

Returns when parameters are missing.

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: credential_configuration_id"
}

```