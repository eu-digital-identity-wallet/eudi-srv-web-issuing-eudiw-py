# PID issuer API error codes

General purpose error codes

+ -1: Error undefined. Please contact PID Provider backend support.
+ 0: No error.
+ 11: Query with no returnURL.
+ 12: Query with no version.
+ 13: Version is not supported.
+ 14: URL not well formed.
+ 15: Query with no device_publickey.
+ 16: The device_publickey is not in the correct format.

pid/getpid error codes:

+ 101: Missing mandatory pid/getpid fields.
+ 102: Country is not supported.
+ 103: Certificate not correctly encoded.
+ 104: Certificate algorithm or curve not supported.

formatter/cbor error codes:

+ 401: Missing mandatory formatter fields.

eIDAS nodes error codes:

+ 301: Missing mandatory lightrequest eidasnode fields.
+ 302: Missing mandatory lightresponse eidasnode fields.
+ 303: Error obtaining attributes.
+ 304: PID attribute(s) missing.
+ 305: Certificate not available.

IdP error codes:

+ 501:Missing mandatory IdP fields