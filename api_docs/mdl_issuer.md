
# mDL issuer - version 0.4

The functionality of the mDL issuer is defined in the issuing-mDL repo.

## 1. Web Service APIs

+ Pre-production / tests URL: <https://issuer.eudiw.dev/>

### 1.1 Get mDL in CBOR and SD-JWT format

Issues mDL in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

The request contains the API version, Issuer country, the EUDI Wallet instance certificate and a returnURL.
After receiving the request, the user's (EUDI Wallet holder) browser will be redirect to the Issuer country eIDAS Node (or to the Issuer country Identity Provider) to authenticate itself and to consent to share the mDL attributes with the mDL issuer.

After creating the signed mDL in CBOR and SD-JWT format, the mDL issuer will redirect the user's browser to the returnURL (mDL in CBOR and SD-JWT format will be ciphered with the EUDI Wallet instance certificate).

#### 1.1.1 (GET) V04/getpid

Starts the process of issuance of the mDL in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

+ Pre-production / tests URL: <https://issuer.eudiw.dev/mdl/getmdl>

The **mdl/getmdl** GET request contains the following fields:

+ *version* (mandatory) - API version
+ *country* (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
+ *certificate* (mandatory) - Wallet instance (device) certificate (PEM format) encoded in base64urlsafe format. The wallet instance public key will be:
  + validated, when the Wallet Issuer Trusted list (or similar) is available
  + included in the mdoc MSO and in the SD-JWT (to be decided, according to the ARF - no decision yet -);
  + used to encrypt fields *cbor* and *sd-jwt* of the response (ECC-Based Hybrid Encryption + AES-256-GCM) sent to the returnURL (see section 1.1.2).
+ *returnURL* (mandatory) - URL where the response will be redirected. If the returnURL is not present, an HTTP_400_BAD_REQUEST error will be returned.


Available *country* codes, for testing:

+ FC (Form Country) - a form, with the necessary mDL attributes, will be presented to the user (EUDI Wallet holder). The user will insert the values, that will not be verified;

Supported certificate algorithms and public key curves for testing:

+ Algorithm: ecdsa-with-SHA256 (OID: 1.2.840.10045.4.3.2), and EC Curve P-256 (secp256r1, OID: 1.2.840.10045.3.1.7)

Example:

```https://issuer.eudiw.dev/mdl/getmdl?version=0.2&country=PT&certificate=MIIH6DCCBdCgAwIBAgIIO0P-pTW...&returnURL=https://url.redirect.to/route```


### 1.2 Get mDL in CBOR and SD-JWT format (without UI/UX for the end user)

Issues mDL in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

The request contains the API version, Issuer country, the EUDI Wallet instance certificate, returnURL and the basic information for mDL issuance (First name, Family name, Birthday).
After receiving the request, the signed mDL is created in CBOR and SD-JWT format, and the mDL issuer will redirect the user's browser to the returnURL (mDL in CBOR and SD-JWT format will be ciphered with the EUDI Wallet instance certificate).

#### 1.2.1 (POST) V04/form

Issues the mDL in CBOR (ISO 18013-5 mdoc) and SD-JWT format.

+ Pre-production / tests URL: <https://issuer.eudiw.dev/mdl/form>

The **mdl/getmdl** POST request contains the following JSON body:

+ *version* (mandatory) - API version
+ *country* (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.
+ *certificate* (mandatory) - Wallet instance (device) certificate (PEM format) encoded in base64urlsafe format. The wallet instance public key will be:
  + validated, when the Wallet Issuer Trusted list (or similar) is available
  + included in the mdoc MSO and in the SD-JWT (to be decided, according to the ARF - no decision yet -);
  + used to encrypt fields *cbor* and *sd-jwt* of the response (ECC-Based Hybrid Encryption + AES-256-GCM) sent to the returnURL (see section 1.2.1).
+ *returnURL* (mandatory) - URL where the response will be redirected. If the returnURL is not present, an HTTP_400_BAD_REQUEST error will be returned.
+ *CurrentGivenName* - First name.
+ *CurrentFamilyName* - Family name.
+ *DateOfBirth* - Birthdate.
+ *DocumentNumber* - Document Number
+ *BirthPlace* - Birth Place
+ *Portrait* - citizen picture
+ *DrivingPrivileges* - categories qualified to drive

Available *country* codes, for testing:

+ FC (Form country) - a form, with the necessary PID attributes, will be presented to the user (EUDI Wallet holder). The user will insert the values, that will not be verified;

Supported certificate algorithms and public key curves for testing:

+ Algorithm: ecdsa-with-SHA256 (OID: 1.2.840.10045.4.3.2), and EC Curve P-256 (secp256r1, OID: 1.2.840.10045.3.1.7)


#### 1.2.2 (GET) returnURL

Redirects the user's browser to the *returnURL* (described in section 1.1.1). The mDL in CBOR and SD-JWT format is ciphered (ECC-Based Hybrid Encryption(using ECDH) + AES-256-GCM) with the Wallet instance public key.

+ URL: *returnURL* (from mdl/getmdl - see section 1.1.1)

The **returnURL** GET response contains the following fields:

+ *mdoc* - mDL in cbor/mdoc format (base64 encoded), ciphered with the Wallet instance public key - ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM - (bytes encoded in base64urlsafe format).
+ *mdoc_nonce* - random AES initialization vector (bytes encoded in base64urlsafe format).
+ *mdoc_authTag* - MAC code of the encrypted text, obtained by the GCM block mode (bytes encoded in base64urlsafe format).
+ *mdoc_ciphertextPubKey* - randomly generated ephemeral public key, that will be used to derive the symmetric encryption key, using the ECDH key agreement scheme. Public key in DER format, encoded in base64urlsafe format.
+ *sd_jwt* - mDL in SD-JWT format.
+ *error* - error number. 0 if no error. Additional errors defined below. If error != 0, all/some fields may have an empty value.
+ *error_str* - Error information.

Error codes (available in the [API error code file](error.md))


For more information on ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM please read [ECC Encryption / Decryption](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption). Remember that *ciphertextPubKey* \* *privKey* = *shared AES-256-GCM symmetric key*, where *privKey* is the private key of the Wallet Instance. The *shared AES-256-GCM symmetric key* shall be used to decrypt the *cbor* and *sd-jwt*.

Example:

```https://url.redirect.to/route?mdoc=A3SIRUmLuIw...FmltmKysEfJ9LXJy66TaydkGEAVrlblIoNEnQ&nonce=TooIrlICaVnrT...3D%3D&authTag=XPZZVcIH2...D&ciphertextPubKey=MFkwEwYHKoZ...lxLg%3D%3D&sd_jwt=eyJhbGciOiAiRVMyNTY...W5nX3NpZ24iLCAiRkMiXQ~&error=0&error_str=No+error.```
