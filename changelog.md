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

