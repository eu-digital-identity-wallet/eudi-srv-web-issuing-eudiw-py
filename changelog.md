# Changelog

## [0.3.0]

### Added:
-  A new mandatory argument, "device_publickey", has been added. This new attribute is the wallet instance public key.
-  Added a tutorial on how to use Pytest, which can be found in the tests folder, "Pytest_Tutorial.md".


### Changed

-  Modifications to the /get_pid and /pid routes: when the "country" parameter is empty, the user is redirected to the 
    /pid route to choose the corresponding country. In the /pid route, when a card is selected, the user is redirected 
    back to /getpid, now with the desired country information.
    
### Fixed	
-  Correction in the encoding process where the data was encoded twice in base64. Rectified to just base64 encoding.


## [0.4.0]

### Added:

-  Added tutorial on using the Robot framework, found in the tests folder under the name, "robot_tutorial.md".
	
-  Added functionality for issuing mDL requests, both in CBOR and SD-JWT format. To use the "/mdl" and "/getmdl" 
    routes, the operation and arguments required are the same as for the PID.
	
- Added metadata to the PID ("issuance_date", "expiry_date", "issuing_authority" and "issuing_country").
	
- Added the "un_distinguishing_sign" attribute to the mDL.

## [0.5.0]

_20 Jun 2024_

### Added:
-  Support notification endpoint - OID4VCI draf13
-  Support deferred flow - OID4VCI draft 13
-  Support dynamic-credential-request - OID4VCI draft 13
-  Support Pre-Authorized Code Flow - OID4VCI draft 13
-  Support credential offer - OID4VCI draft 13
-  Configure a new generic IdP based on OIDC
-  Support batch flow - OID4VCI draft 13


### Changed
-  Update current flows to OID4VCI draft 13
-  Remove /oidc route
-  A more dynamically built form and country selection
-  Changed doctype and namespace from "eudiw" to "eudi" in pid and age verification credentials. 


### Fixed
-  UI scalling for mobile devices
-  Pull [#11](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/pull/11) Fix date validation for issue_date and expiry_date for doc_type org.iso.18013.5.1.mDL
-  Pull [#7](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/pull/7) Fix Directory /tmp/log does not exist

## [0.6.0]

_04 Oct 2024_
### Added:
- Docker
- config with environment variables
- Issue Photo ID attestation
- Issue attestations needed for the LSP POTENTIAL
- Endpoint to create a credential offer, from an external request
- Credential offer guides to the front page
- Issuing PID/EAA with optional attributes
- Added information to the metadata on how the attribute will be sourced

### Changed
- UI changes in the credential offer and authorisation pages
- change the way optional attributes are managed
- dynamic generation of Issuer managed attributes (issuance date, expiration date, issuing authority, issuing country, ...)
- Improve responsiveness to the issuer profile and service (including UI) to improve usability and accessibility

### Fixed
- Fixed form data being prematurely removed
- Conflicting dependencies
- Dynamic Issuing always requests full PID attestation instead of the required attributes.
  

## [0.7.0]

_28 Jan 2025_
### Added:
- Authorization server metadata
- Attestation Revocation
-  Issuer logo to metadata

### Changed
- Align SD-JWT-VC format of PID with latest drafts

## [0.7.1]

_05 Mar 2025_
### Added:
- EHIC Credential compliant with LSP DC4EU technical specification.
- PDA1 Credential compliant with LSP DC4EU technical specification.
- sd-jwt vc: EHIC, PDA1, HIID, IBAN, MSISDN, POR, Tax, Pseudonym age over 18.
- Created a new issuer_conditions schema in credential metadate to further specify complex credentials like nested claims.

### Changed
- Backend logic management creating the form and credentials based on metadata issuer_condtitions
- Front-end form changes to dynamically create a form based on metadata issuer_conditions with nested fields, cardinality and nested mandatory.
- Update PID to version 1.5

### Fixed
- Status code on oauth2 PAR is 200 should be 201

## [0.7.2]

_15 Apr 2025_
### Changed
- oid4vp presentation_id to transaction_id

### Fixed
- EHIC and PDA1 not appearing in credential offer selection
- Some PID sd-jwt vc attribure identifiers
- PDA1 and EHIC formatting
- Remove padding from mdoc base64 url encode
- Fix jwk coordinate padding
- remove location_status from PID mdoc

## [0.8.0]

_05 May 2025_
### Added:
- Nonce Endpoint

### Changed
- Credential endpoint oid4vci d15
- Deferred endpoint oid4vci d15
- Metadata oid4vci d15
- Set scopes to credential id
- Further separation of sd-jwt vc and mdoc formatters based on metadata

## [0.8.1]

_25 Jun 2025_

### Changed
- PID to new spec

### Fixed
- Refresh token rotation
- CoR uri 

## [0.8.2]

_14 Jul 2025_

### Changed
- Preauth form and main generated the same.

### Fixed
- Bug where PID and PID sd-jwt cannot be issued at the same time with deeplink 
- Cannot add PID due to bracket error
- SD-JWT VC PID contains improperly disclosed elements in nationalities
- Unable to issue PoR Credential through wallet tester

## [0.9]

_11 Nov 2025_

### Added
- Support for Credential Request encryption
- Key attestations proof type
- Pytest tests
- `session_manager` for tracking session state throughout the service

### Changed
- Split Issuer backend, frontend, and authorization server into separate services
- Updated PID to the latest version
- Refactored and cleaned up code
- Migrated configuration, variables, and secrets to `.env` format
- Streamlined Dockerfile for minimal deployment

## [0.9.1]

_26 Nov 2025_

### Added
- External credential offer API

### Fixed
- install.md URLs 
- update .env example

## [0.9.2]

_28 Nov 2025_

### Fixed
- Fix invalid version tag in Docker Compose file by @thirtified

## [0.9.3]

_05 Dec 2025_

### Added
- OID4VP and Credential offer scheme env variables

### Fixed
- Fix Pre-Authorization Front-End URL Handling
- mDL with multiple driving privileges
- key_attestation in JWT format handling
- Form Formatter Not Marking Mandatory Attributes

### Changed
- Updated revocation test to OID4VP version 1


## [0.9.4]

_02 Apr 2026_

### Added
- Sign metadata endpoint
- WUA trust validator

### Fixed
- PID SD-JWT VC: email_address and mobile_phone_number not remapped to IANA-registered claim names
- encoding for place_of_birth in MSO MDoc PID
- invalid values for credential_signing_alg_values_supported for mdoc credentials in metadata

### Changed
- Configuration to yaml
- install.md



## [0.9.5]

_29 Apr 2026_

### Fixed
- Update PID SD-JWT VC attributes for `email_address` and `mobile_phone_number` 
- Update PID SD-JWT VC attribute `address`
- Update TAX mdoc metadata field `credential_signing_alg_values_supported`

## [0.9.6]

_25 Jun 2026_

### Fixed
- Updated all unit tests, now passing successfully.

## [0.9.7]

_5 Aug 2026_

### Changed
- Updated supported credentials metadata to include `credential_reuse_policy`.
- Updated implementation to align with EUDI TS3 v1.5 specification.

## [0.9.8]

_14 Aug 2026_

### Changed
- Updated OID4VP requests to specify either a registration certificate or intended use on Verifier requests.

### Fixed
- Fixed invalid `validUntil` timestamp format in the issuance of some mso_mdoc credentials.

## [0.9.9]

_06 Oct 2026_

### Added
- `GET /metadata/<frontend_id>` and `GET /metadata/<frontend_id>/signed` (API key protected): the backend builds each frontend's metadata, so frontends no longer assemble and sign it themselves.
- `test_features` configuration (`form_countries`, `passport_age_verification`, `tx_code_in_offer`), all off by default: these demo flows issue credentials from self-asserted data.
- `secret_key` configuration: the session cookie signing key; start-up fails when it is missing, a placeholder or shorter than 32 characters, because a known key lets anyone forge sessions.
- `authorization_server.api_key`, `jwks_uri`, `jwks_path` and `issuer` configuration, used to call the authorization server and to verify its `session_token`.
- Per-client rate limits (`rate_limiting`, Flask-Limiter) on the endpoints that issue, sign or look up data, with `trusted_proxies` for deployments behind nginx: no endpoint was throttled.
- DPoP proof verification on `/credential`, `/deferred_credential` and `/notification` when introspection reports `cnf.jkt`, so a DPoP-bound token can no longer be replayed as a bearer token.
- Regression tests replaying each finding of the 2026-07 security assessments (`tests/test_security_regressions.py`).

### Changed
- `/auth_choice` takes the session id, scope and authorization details only from the `session_token` signed by the authorization server, and refuses a session already bound to another browser: query parameters allowed session fixation.
- `/credentialOfferReq2` returns `{"credential_offer", "tx_code"}` and the offer no longer contains the tx_code (unless `tx_code_in_offer`), since the tx_code is a second factor delivered out of band; the request JWT must carry `exp` and `iat` (lifetime at most 1 h).
- OID4VP presentation requests use a random nonce per presentation instead of a fixed value, which allowed replaying recorded presentations.
- `/credential` only issues the credential configurations the access token was authorized for.
- `/logs` only accepts a session UUID and matches it as a whole token: a substring returned every user's log lines.
- `/revocation/revoke` only accepts the identifier issued to the same browser session, and checks its expiry.
- `metadata_signer` no longer lets the metadata override `sub`, `iat`, `iss`, `exp`, `nbf`, `aud` or `jti`, and no longer returns internal error details; an unknown frontend gets 404.
- x5c-signed JWTs (key attestations, offer requests) only accept asymmetric algorithms by default, and intermediate certificates must be CAs.
- Responses carry a Content-Security-Policy and `Referrer-Policy`; the auto-submit page only posts to configured frontends.
- The browser session is cleared when the user is handed back to the wallet.
- Placeholder `backend_api_key` values (`change-me`) are treated as unset.
- The Docker image runs as an unprivileged user (UID 10001) and only copies `app/`.
- CI: SonarCloud runs on `pull_request` instead of `pull_request_target` (fork PR code ran with repository secrets) and actions are pinned to commit SHAs.
- Removed the `/formatter/cbor` and `/formatter/sd-jwt` routes, which signed caller-supplied data with the issuer keys; issuance calls the formatters directly.
- Dependencies: pyMDOC-CBOR moves to the niscy-eudiw fork 0.6.0, which no longer caps its dependencies through `cwt`, so `cryptography` goes from 41.0.7 (2023, missing later security fixes) to 50.0.2, with `cbor2` 5.9.0, `pycose` 1.1.0 and `jwcrypto` 1.6.1. `cwt` and `cbor_diag` are no longer installed. The fork also fixes batch-issued mdocs whose nested dates (e.g. mDL `driving_privileges`) were tagged twice, and brainpool device keys written with the wrong COSE curve identifier.

### Fixed
- Reflected XSS in the auto-submit page: the payload was rendered unescaped inside a single-quoted attribute.
- `credential_offer_URI` is validated, so it cannot inject script-capable URLs.
- `/getpidoid4vp` and the revocation flow fetched any `presentation_id`, exposing other users' presentations; it must now belong to the caller's session.
- PID presentations must contain exactly one PID document, and the document signer certificate's validity is checked.
- The attribute form cannot change values read from a verified PID.
- `/form_authorize_generate` used a posted `user_id` instead of the browser session.
- `/dynamic/redirect` checks a random, single-use OAuth `state`; the OpenID connectors used the session id as state.
- Huge list indices in form field names no longer allocate unbounded memory.
- SD-JWT issuance no longer reseeds Python's global random generator with a constant.
- `Session.__repr__` masks codes, tokens and personal data.
- Requests with only `credential_identifier` no longer fail with a server error.
- The WIA `client_status` claim is read from the access token only after its signature is verified with the authorization server keys.
- Log lines escape line breaks in every request-supplied or externally received value (log injection).
- A browser request without an active issuance session (expired, or already handed back to the wallet) gets 400 instead of a 500.

## [Unreleased]

### Added
- `admin_api_key` guards `GET /logs`, `GET /admin/sessions/client_status` and `POST /metadata/metadata_signer`; `backend_api_key` only reads frontend metadata.
- `trusted_CAs_paths.{key_attestation, offer_request, pid_signer}`: optional per-purpose trust anchors.
- `frontends_config.<id>.payload_key`: display payloads also carry `payload_jwt`, an HS256 JWT valid for 5 minutes.
- `max_content_length` (default 1 MiB), `session_file_threshold` (default 10000) and `proof_validation.key_attestation_max_age_seconds` (default 24 h).
- `proof_validation.single_use_nonce` (default `true`; OpenID4VCI 1.0 §13.8).
- `variables`: configuration strings may use `${name}`.
- `frontends_config.<id>.registration_certificate_path`: published as the frontend's `issuer_info`.
- `countries.<code>.issuing_country` (default: the entry's code); `FC`, `AV` and `AV2` use `LU`.
- `GET /metadata/<frontend_id>` returns `jwt_vc_issuer` for the frontend's `/.well-known/jwt-vc-issuer`; SD-JWT VCs carry a `kid`.
- JWT proofs may name the holder key with a `did:jwk` or `did:key` `kid` (OpenID4VCI 1.0 appendix F.1).
- ES384 and ES512 proofs and key attestations (TS3 2.6).
- `credential_offer_mode=by_reference`: offers by `credential_offer_uri` (OpenID4VCI 1.0 §4.1.3).
- `GET /auth_method_choice` shows the authentication choice again for the current session.
- Revoking a credential revokes every instance issued with it in the same session.
- `expiry.cleanup_interval` (minutes, default 60): a scheduler purges expired offers, revocation requests and sessions; `/nonce` did it on every call.

### Changed
- Each `c_nonce` is single use; a bad one gets `invalid_nonce` (was `invalid_proof`).
- More proofs than the batch size are rejected before verification.
- A trust validator `trusted: false` answer is final.
- Signer and `x5c` certificates must have the right CA, key usage and PID EKU profile.
- `/preauth` and `/preauth_form` are POST-only.
- The test-environment defaults need `EUDIW_TEST_ENV=true`; `CI` and `SONARCLOUD` no longer enable them.
- Key attestations must carry `key_storage_status` with `exp` and a status list reference (TS3 2.3.2 / 2.4.1).
- SD-JWT VCs use the frontend URL as `iss` instead of `service_url`.
- A frontend's `oauth-authorization-server` metadata is a copy of its `openid-configuration` (RFC 8414).
- Credential offers and revocation are limited to the credentials the frontend publishes.
- Access token errors carry a `WWW-Authenticate` challenge (RFC 6750 §3, RFC 9449 §7.1).
- A credential the access token does not cover gets 403 `insufficient_scope` (OpenID4VCI 1.0 §8.3.1.1).
- Ambiguous credential requests (`credential_identifier` with `credential_configuration_id`, `proof` with `proofs`) are rejected.
- Credential error bodies contain only `error` and `error_description` (OpenID4VCI 1.0 §8.3.1.2).
- `/deferred_credential` and `/notification` check the access token first and return spec error codes (OpenID4VCI 1.0 §9.1, §11.3).
- The OID4VP PID login requests only mandatory claims; revocation requests one.
- `display_authorization` payloads carry `image_attributes`.
- The PID `portrait` and `picture` are one field on the attribute form.
- `verify_jwt_with_x5c` reads `typ` from the verified token (SonarCloud).
- Test for `/dynamic/form` posted without `proceed` (upstream #178).
- `pipeline.yml` runs on `main` and `branch-*` instead of `dev`, `preprod` and `main`.

### Fixed
- Key attestations without `iat` / `exp`, too old or with another `typ` were accepted.
- Bad `credential_response_encryption` was rejected only after signing; it gets 400 `invalid_encryption_parameters` first.
- `/preauth` without a valid `credentials_id` returned 500.
- Log messages could forge log records; CR / LF are escaped.
- `/logs` reported `successful` from forgeable log text.
- `/notification` accepted any `notification_id`.
- `GET /credential_offer_choice` created a session for any `frontend_id`.
- `FC`, `AV` and `AV2` credentials had an `issuing_country` that did not match the signer certificate.
- Wallet clocks slightly ahead got proofs and DPoP rejected; 60 s skew is allowed.
- An offer by `credential_offer_uri` could be fetched repeatedly, even after expiry.
- A malformed WIA `client_status` caused a 500.
- PID `sex` was issued as a string (PID Rulebook).
- SD-JWT VC `picture` was issued as base64url instead of a data URL (PID Rulebook §4.1).
- The seafarer `issuing_authority_logo` was shown in the wrong encoding.
- `gitleaks/gitleaks.toml` failed to load, so the secret scan never ran.
- The Docker image did not start without `libpq5`.
- `install.md` and `licenses.md` listed gunicorn, which is not a dependency.
