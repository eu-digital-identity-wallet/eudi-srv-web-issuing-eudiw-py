
# qeaa issuer - version 0.4

The functionality of the qeaa issuer is defined in the issuing-qeaa repo.

## 1. Web Service APIs

+ Pre-production / tests URL: <https://issuer.eudiw.dev/>

### 1.1 Get qeaa in CBOR and SD-JWT format

Issues qeaa in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

The request contains the API version, Issuer country, the EUDI Wallet instance certificate and a returnURL.
After receiving the request, the user's (EUDI Wallet holder) browser will be redirect to the Issuer country eIDAS Node (or to the Issuer country Identity Provider) to authenticate itself and to consent to share the qeaa attributes with the qeaa issuer.

After creating the signed qeaa in CBOR and SD-JWT format, the qeaa issuer will redirect the user's browser to the returnURL (qeaa in CBOR and SD-JWT format will be ciphered with the EUDI Wallet instance certificate).

#### 1.1.1 (GET) V04/getpid

Starts the process of issuance of the qeaa in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

+ Pre-production / tests URL: <https://issuer.eudiw.dev/qeaa/getqeaa>

The **qeaa/getqeaa** GET request contains the following fields:

+ *version* (mandatory) - API version
+ *country* (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
+ *certificate* (mandatory) - Wallet instance (device) certificate (PEM format) encoded in base64urlsafe format. The wallet instance public key will be:
  + validated, when the Wallet Issuer Trusted list (or similar) is available
  + included in the mdoc MSO and in the SD-JWT (to be decided, according to the ARF - no decision yet -);
  + used to encrypt fields *cbor* and *sd-jwt* of the response (ECC-Based Hybrid Encryption + AES-256-GCM) sent to the returnURL (see section 1.1.2).
+ *returnURL* (mandatory) - URL where the response will be redirected. If the returnURL is not present, an HTTP_400_BAD_REQUEST error will be returned.


Available *country* codes, for testing:

+ FC (Form Country) - a form, with the necessary qeaa attributes, will be presented to the user (EUDI Wallet holder). The user will insert the values, that will not be verified;

Supported certificate algorithms and public key curves for testing:

+ Algorithm: ecdsa-with-SHA256 (OID: 1.2.840.10045.4.3.2), and EC Curve P-256 (secp256r1, OID: 1.2.840.10045.3.1.7)

Example:

```https://issuer.eudiw.dev/qeaa/getqeaa?version=0.2&country=PT&certificate=MIIH6DCCBdCgAwIBAgIIO0P-pTW...&returnURL=https://url.redirect.to/route```


### 1.2 Get qeaa in CBOR and SD-JWT format (without UI/UX for the end user)

Issues qeaa in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

The request contains the API version, Issuer country, the EUDI Wallet instance certificate, returnURL and the basic information for qeaa issuance (First name, Family name, Birthday).
After receiving the request, the signed qeaa is created in CBOR and SD-JWT format, and the qeaa issuer will redirect the user's browser to the returnURL (qeaa in CBOR and SD-JWT format will be ciphered with the EUDI Wallet instance certificate).

#### 1.2.1 (POST) V04/form

Issues the qeaa in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

+ Pre-production / tests URL: <https://issuer.eudiw.dev/qeaa/form>

The **qeaa/getqeaa** POST request contains the following JSON body:

+ *version* (mandatory) - API version
+ *country* (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
+ *certificate* (mandatory) - Wallet instance (device) certificate (PEM format) encoded in base64urlsafe format. The wallet instance public key will be:
  + validated, when the Wallet Issuer Trusted list (or similar) is available
  + included in the mdoc MSO and in the SD-JWT (to be decided, according to the ARF - no decision yet -);
  + used to encrypt fields *cbor* and *sd-jwt* of the response (ECC-Based Hybrid Encryption + AES-256-GCM) sent to the returnURL (see section 1.2.1).
+ *returnURL* (mandatory) - URL where the response will be redirected. If the returnURL is not present, an HTTP_400_BAD_REQUEST error will be returned.
+ *nipc* - legal person identification number
+ *name* - name
+ *entidade* - entity
+ *nipc2* - legal person identification number
+ *email* - worker's email
+ *contr* - assigned by

Available *country* codes, for testing:

+ FC (Form country) - a form, with the necessary PID attributes, will be presented to the user (EUDI Wallet holder). The user will insert the values, that will not be verified;

Supported certificate algorithms and public key curves for testing:

+ Algorithm: ecdsa-with-SHA256 (OID: 1.2.840.10045.4.3.2), and EC Curve P-256 (secp256r1, OID: 1.2.840.10045.3.1.7)


#### 1.2.2 (GET) returnURL

Redirects the user's browser to the *returnURL* (described in section 1.1.1). The qeaa in CBOR and SD-JWT format is ciphered (ECC-Based Hybrid Encryption(using ECDH) + AES-256-GCM) with the Wallet instance public key.

+ URL: *returnURL* (from qeaa/getqeaa - see section 1.1.1)

The **returnURL** GET response contains the following fields:

+ *mdoc* - qeaa in cbor/mdoc format (base64 encoded), ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
+ *mdoc_nonce* - random AES initialization vector (bytes encoded in base64urlsafe format).
+ *mdoc_authTag* - MAC code of the encrypted text, obtained by the GCM block mode (bytes encoded in base64urlsafe format).
+ *mdoc_ciphertextPubKey* - randomly generated ephemeral public key, that will be used to derive the symmetric encryption key, using the ECDH key agreement scheme. Public key in DER format, encoded in base64urlsafe format.
+ *sd_jwt* - qeaa in SD-JWT format.
+ *error* - error number. 0 if no error. Additional errors defined below. If error != 0, all/some fields may have an empty value.
+ *error_str* - Error information.

Error codes (available in the [API error code file](error.md))


For more information on ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM please read [ECC Encryption / Decryption](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption). Remember that *ciphertextPubKey* \* *privKey* = *shared AES-256-GCM symmetric key*, where *privKey* is the private key of the Wallet Instance. The *shared AES-256-GCM symmetric key* shall be used to decrypt the *cbor* and *sd-jwt*.

Example:

```https://url.redirect.to/route?mdoc=ZvibMIWQQU6Vq...j_9IBg%3D%3D&nonce=9D0gLMlpOevM...%3D%3D&authTag=Sc-bNfqKj6Dn6JU...D&ciphertextPubKey=MFkwEwYHKoZIzj0DAQcDQg...3p65dW1_sGtXzxbUHFNkNKo47og%3D%3D&sd_jwt=eyJhbGciOiAiRVMyN...tMTItMjYiXQ~&error=0&error_str=No+error.```
