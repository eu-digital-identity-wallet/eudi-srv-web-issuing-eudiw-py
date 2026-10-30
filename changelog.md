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
- `admin_api_key`: guards `GET /logs`, `GET /admin/sessions/client_status` and `POST /metadata/metadata_signer` (503 while unset). `backend_api_key` now only reads frontend metadata.
- Optional per-purpose trust anchors `trusted_CAs_paths.{key_attestation, offer_request, pid_signer}`; a purpose left out uses `trusted_CAs_path`.
- Signed display payloads: with `frontends_config.<id>.payload_key` (at least 32 characters) every page posted to a frontend `/display_*` route also carries `payload_jwt`, an HS256 JWS over `{payload, aud, iat, exp}` (5 minutes). Without the key the payload is posted unsigned and a warning is logged once.
- `max_content_length` (default 1 MiB, 413 above), `session_file_threshold` (default 10000) and `proof_validation.key_attestation_max_age_seconds` (default 24 h).
- `proof_validation.single_use_nonce` (default `true`): `false` lets a wallet reuse a valid `c_nonce` until it expires (OpenID4VCI 1.0 §13.8), and the used-nonce store is not consulted.
- `variables` configuration section: any string value may use `${name}` (e.g. `"${keys_dir}/PID-DS-0002_PT.pem"`), and a variable may use the ones defined before it. An undefined variable stops start-up. The example configuration uses `backend_url`, `frontend_url`, `status_list_url`, `eudiw_dir`, `keys_dir` and `certs_dir`, and the eIDAS node countries share their settings through YAML anchors.
- `frontends_config.<id>.registration_certificate_path`: the frontend's registration certificate (`rc-wrp+jwt`), published as `issuer_info` (`format: registration_cert`) in its unsigned and signed metadata. Start-up fails when the file does not hold a JWT. Before, every frontend copied the backend's `issuer_info`.
- `countries.<code>.issuing_country`: the ISO 3166-1 alpha-2 code written as `issuing_country` (default: the entry's code). It is required for entries that are not countries (`FC`, `AV`, `AV2`, which now use `LU`), and must match the `countryName` of the document signer (ISO/IEC 18013-5).
- SD-JWT VC issuer metadata: `GET /metadata/<frontend_id>` also returns `jwt_vc_issuer` (`{"issuer": <frontend URL>, "jwks"}`) for the frontend's `/.well-known/jwt-vc-issuer`, with the public key of every country `_default` signing certificate (`x5c`, `x5t#S256`). SD-JWT VCs carry a `kid` header (RFC 7638 thumbprint) naming their key in this JWKS. A frontend URL with a path needs a reverse-proxy rewrite.
- JWT proofs may name the holder key with a `kid` DID URL (`did:jwk`, or `did:key` with P-256) instead of `jwk`; `jwk`, `kid` and `x5c` are mutually exclusive (OpenID4VCI 1.0 appendix F.1). The jwt_vc credential configurations advertise `did:jwk` and `did:key` in `cryptographic_binding_methods_supported`.
- Proofs and key attestations may be signed with ES384 (P-384) and ES512 (P-521) as well as ES256, each algorithm only with its own curve (TS3 2.6); every credential configuration advertises the three. JWK coordinates of P-384 / P-521 keys are padded to the curve size (RFC 7518 §6.2.1.2).
- Credential offers by reference: with `credential_offer_mode=by_reference` the offer URI carries a `credential_offer_uri` (OpenID4VCI 1.0 §4.1.3) instead of the offer, in the authorization code and pre-authorized flows.
- `GET /auth_method_choice` shows the authentication method choice again for the browser's issuance session (the Back button of the PID login page); without an active session it returns 400.
- Revocation of a batch: each issued status entry is recorded in `issued_status_entry` with its session and credential type, and revoking one presented instance revokes every instance issued with it in the same session (one batch request and its re-issuances). Before, only the presented instance was revoked, the one already used for the presentation.
- `expiry.cleanup_interval` (minutes, default 60): the scheduler purges expired credential offers, revocation requests and sessions on that interval. Before, `/nonce` purged them on every call, so they stayed in memory while no wallet asked for a nonce. The scheduler shuts down at exit.

### Changed
- `verify_jwt_with_x5c` reads the `typ` header from `jwt.decode_complete` (verified together with the signature) instead of `jwt.get_unverified_header` (SonarCloud: JWT used without verifying its signature).
- By default each `c_nonce` is accepted by one credential request only (see `proof_validation.single_use_nonce`). An unknown, undecryptable, expired or reused `c_nonce` is answered with `invalid_nonce` (was `invalid_proof`); a proof without a `c_nonce`, when one is required, stays `invalid_proof` (OpenID4VCI 1.0 §8.3.1.2). Deferred retrieval reuses the holder keys proven by the first request instead of verifying the proofs again.
- A request with more proofs than the batch size is rejected with `invalid_credential_request` before any proof is verified (it was truncated after verification).
- A trust validator `trusted: false` answer is final; the local CA store is only used when the validator fails or is disabled.
- Signer certificates must not be CAs and, with `keyUsage`, allow `digitalSignature`; PID document signers with `extendedKeyUsage` need `1.0.18013.5.1.2`; `x5c` intermediates need `cA=TRUE` and `keyCertSign`.
- `/preauth` and `/preauth_form` are POST-only; `/credential_offer` reaches `/preauth` with a 307 redirect.
- The test-environment defaults need `EUDIW_TEST_ENV=true`; `CI` and `SONARCLOUD` no longer enable them.
- Key attestations must carry `key_storage_status` with a numeric `exp` and a `status.status_list` reference (`idx`, `uri`) (TS3 2.3.2 / 2.4.1); one without it was accepted, and the revocation check skipped.
- SD-JWT VCs use the session's frontend URL as `iss` (the `credential_issuer` wallets know, and the host the x5c SAN names) instead of the backend `service_url`.
- A frontend's `oauth-authorization-server` metadata is a copy of its `openid-configuration`: its `issuer` is the frontend URL (RFC 8414) and it lists PAR, DPoP and wallet attestation. It came from a separate template whose `issuer` and endpoints pointed to the backend.
- Credential selection is limited to the credentials the frontend publishes (`frontends_config.<id>.credentials_supported`) on `/credential_offer_choice`, `/credential_offer`, `/credential_offer_create` (default frontend) and the revocation flow; any other credential gets 400. `/revocation/revocation_choice` accepts `frontend_id` (404 when unknown) and the later revocation pages go to that frontend. `/revocation/oid4vp_call` rejects unknown and non-revocable credentials.
- Access token errors on `/credential`, `/deferred_credential` and `/notification` carry a `WWW-Authenticate` challenge (RFC 6750 §3, RFC 9449 §7.1, `DPoP` with `algs`). A request without Bearer / DPoP credentials gets 401 with no error code (was `invalid_request`); a DPoP-bound token sent as Bearer gets `invalid_token` (RFC 9449 §7.2; was `invalid_dpop_proof`).
- A credential configuration the access token does not cover gets 403 `insufficient_scope` (OpenID4VCI 1.0 §8.3.1.1), an unknown `credential_identifier` `unknown_credential_identifier`; only an unsupported configuration still gets `unknown_credential_configuration`.
- Credential requests are rejected with both `credential_identifier` and `credential_configuration_id` (`invalid_credential_request`), with both `proof` and `proofs`, or when `proofs` holds anything but exactly one proof type (`invalid_proof`).
- `/credential` and `/deferred_credential` error bodies only contain `error` / `error_description` (OpenID4VCI 1.0 §8.3.1.2), with descriptions limited to the characters OAuth allows. `notification_id` is only returned with issued credentials, never in error or deferred responses.
- `/deferred_credential` checks the access token before reading the body. A missing `transaction_id` gets 400 `invalid_credential_request` and a malformed one 400 `invalid_transaction_id` (both were 401, the second as `invalid_transaction_id_format`). A `transaction_id` stops working once its credential has been obtained (OpenID4VCI 1.0 §9.1).
- `/notification` checks the access token before reading the body. A body that is not a JSON object, a missing or non-string `notification_id`, or an `event` other than `credential_accepted`, `credential_failure` or `credential_deleted` gets 400 `invalid_notification_request` (OpenID4VCI 1.0 §11.3).
- The OID4VP PID login requests only the PID's mandatory claims; the revocation flow requests a single claim (the first mandatory one), as it only needs the issuer-signed status.
- `display_authorization` payloads carry `image_attributes`, so the consent page shows those values as images. One `IMAGE_ATTRIBUTES` list must cover every `"value_type": "jpeg"` claim (enforced by a test).
- The PID mdoc `portrait` and SD-JWT VC `picture` are one *portrait* field on the attribute form, for either PID or both together; its value is issued under both names, and a verified portrait cannot be overridden through `picture`. Both PIDs requested together showed two image choices, and the SD-JWT VC alone showed *picture*.

### Fixed
- Key attestations without `iat` / `exp`, older than the maximum age or with another `typ` were accepted; untrusted ones caused a server error instead of `invalid_proof`.
- `credential_response_encryption` with unsupported or malformed values was only rejected after the credentials were signed, as `invalid_credential_response_encryption`. It now gets 400 `invalid_encryption_parameters` (OpenID4VCI 1.0 §8.3.1.2) first.
- `/preauth` without a valid `credentials_id` returned 500; it returns 400.
- Every log message has CR / LF escaped by a handler filter, and every traceback line is indented, so an exception message cannot forge a log record. The 404 handler escapes the path.
- `/logs` reported `successful` from log text a request could forge; it now comes from the session state.
- `/notification` accepted and logged any `notification_id`; it must belong to the access token's session (400 `invalid_notification_id`).
- `GET /credential_offer_choice` created a server-side session for any `frontend_id`; an unknown one gets 404.
- Credentials issued through the FormEU (`FC`) and age verification (`AV`, `AV2`) forms carried that configuration key as `issuing_country`, which did not match the document signer certificate.
- Key attestations and other x5c-signed JWTs (60 s), and DPoP proofs (`iat` up to 60 s ahead or 300 s old), were rejected when the wallet's clock ran slightly ahead: PyJWT allowed no clock skew.
- An offer served by `credential_offer_uri` (which may contain the `pre-authorized_code`) could be fetched any number of times, even after it expired. It is now single use and sent with `Cache-Control: no-store`; authorization code offers given by value are no longer stored.
- A malformed WIA `client_status` in the access token caused a 500; it gets 401 `invalid_token`.
- The PID `sex` claim from the form was issued as a string; it is a uint / JSON number (PID Rulebook).
- The SD-JWT VC `picture` was issued as base64url; it is a `data:image/jpeg;base64,` URL (PID Rulebook §4.1).
- The seafarer `issuing_authority_logo` was shown on the consent page in the wrong encoding.
- `pipeline.yml` only ran on pushes to `dev`, `preprod` and `main`; the repository's branches are `branch-*`, so no branch image was built. It now runs on `main` and `branch-*`.
- `gitleaks/gitleaks.toml`: the `Env Var` rule had no `id`, so current gitleaks refused to load the config and the (non-blocking) secret scan never ran. The rule is now `env-var`.
- The Docker image did not start: `psycopg` (pure Python) loads the system `libpq`, which the runtime image lacked (`ImportError: no pq wrapper available`). The runtime stage now installs `libpq5`.
