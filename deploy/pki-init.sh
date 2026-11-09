#!/usr/bin/env sh
#
# Lay out the issuer's document-signing material into /etc/eudiw/pid-issuer-dev,
# which the deploy stack mounts as a named volume.
#
# Safe to run on every deploy. It writes the material the deploy passes in and
# generates two keys only if they are absent, so repeated runs produce the same
# result. That is what makes it usable as an init container, unlike the WeBuild
# scripts in interop_event_tools, which mint a new CA on every run and must stay
# a deliberate ceremony.
#
# Everything signs with GRNET's document signer, passed in by the deploy. The
# generated keys are per-deployment.
set -eu

OUT="${PKI_OUT:-/etc/eudiw/pid-issuer-dev}"
CERT_DIR="$OUT/cert"
PRIVKEY_DIR="$OUT/privKey"

mkdir -p "$CERT_DIR" "$PRIVKEY_DIR"

# Until 0.11.0 the image carried EU test tokens, unpacked here into cert/ and
# privKey/; the config never signed with them. 0.11.0 ships no test material,
# so remove what earlier runs left: cert/ is the issuer's trusted CAs, and the
# EU test IACA does not belong there.
rm -f "$CERT_DIR"/PID-DS-0002* "$CERT_DIR"/PIDIssuerCAUT01.pem "$PRIVKEY_DIR"/PID-DS-0002*
# Likewise the separate SD-JWT PID signer, gone since DS 01 signs everything.
rm -rf "$OUT/ds-pid"

# GRNET's document signer: signs the PIDs and the frontend's metadata. Rewritten
# on every run. In ds/, not cert/, which the issuer loads as trusted CAs.
DS_DIR="$OUT/ds"
DS_KEY_FILE="${DS_KEY_FILE:-/run/secrets/ds-key}"
[ -s "$DS_KEY_FILE" ] || { echo "pki-init: no document-signer key at $DS_KEY_FILE" >&2; exit 1; }
[ -n "${DS_CERT_PEM:-}" ] || { echo "pki-init: DS_CERT_PEM is not set" >&2; exit 1; }
[ -n "${IACA_PEM:-}" ] || { echo "pki-init: IACA_PEM is not set" >&2; exit 1; }
mkdir -p "$DS_DIR"
printf '%s\n' "$DS_CERT_PEM" > "$DS_DIR/signing.pem"
openssl x509 -in "$DS_DIR/signing.pem" -outform der -out "$DS_DIR/signing.der"
# Compose writes the secret without its final newline; put it back.
printf '%s\n' "$(cat "$DS_KEY_FILE")" > "$DS_DIR/signing.key"
if [ "$(openssl pkey -in "$DS_DIR/signing.key" -pubout)" != "$(openssl x509 -in "$DS_DIR/signing.pem" -noout -pubkey)" ]; then
    echo "pki-init: the document-signer key does not belong to its certificate" >&2
    exit 1
fi
echo "pki-init: document signer $(openssl x509 -in "$DS_DIR/signing.pem" -noout -subject)"

# Optional: the access certificate (WRPAC) and registration certificate (WRPRC)
# the Launchpad registrar issued for the issuer. The WRPAC signs the frontend's
# metadata, which wallets check against the Commission's WRPAC providers list;
# the WRPRC goes into the metadata as issuer_info. Without a WRPAC the document
# signer signs the metadata, as before. Without a WRPRC there is no
# registration.jwt, and the deploy leaves registration_certificate_path empty:
# 0.11.0 refuses to start on an empty file. Rewritten on every run.
WRP_DIR="$OUT/wrp"
WRP_ACCESS_KEY_FILE="${WRP_ACCESS_KEY_FILE:-/run/secrets/wrp-access-key}"
rm -rf "$WRP_DIR"
mkdir -p "$WRP_DIR"
if [ -n "${WRP_ACCESS_CERT_PEM:-}" ] && [ -s "$WRP_ACCESS_KEY_FILE" ]; then
    printf '%s\n' "$WRP_ACCESS_CERT_PEM" | openssl x509 -out "$WRP_DIR/signing.pem"
    printf '%s\n' "$(cat "$WRP_ACCESS_KEY_FILE")" > "$WRP_DIR/signing.key"
    if [ "$(openssl pkey -in "$WRP_DIR/signing.key" -pubout)" != "$(openssl x509 -in "$WRP_DIR/signing.pem" -noout -pubkey)" ]; then
        echo "pki-init: the WRPAC key does not belong to its certificate" >&2
        exit 1
    fi
    echo "pki-init: metadata signed by WRPAC $(openssl x509 -in "$WRP_DIR/signing.pem" -noout -subject)"
else
    cp -f "$DS_DIR/signing.pem" "$DS_DIR/signing.key" "$WRP_DIR/"
    echo "pki-init: no WRPAC; the document signer signs the metadata"
fi
if [ -n "${WRP_REGISTRATION_CERT:-}" ]; then
    printf '%s' "$WRP_REGISTRATION_CERT" > "$WRP_DIR/registration.jwt"
    echo "pki-init: issuer_info carries the WRPRC"
fi
chmod 644 "$WRP_DIR"/*

# Trust our IACA for PIDs presented back to the issuer.
printf '%s\n' "$IACA_PEM" > "$CERT_DIR/root-ca-grnet.pem"

# Generated, not shipped: these are per-deployment and must survive a redeploy,
# which is why the volume is named rather than anonymous. Regenerating the
# credential-request key changes the public JWK advertised in the issuer
# metadata.
if [ ! -f "$PRIVKEY_DIR/nonce_rsa2048.pem" ]; then
    echo "pki-init: generating nonce key"
    openssl genrsa -out "$PRIVKEY_DIR/nonce_rsa2048.pem" 2048
fi

# Must be P-256: _build_credential_encryption_metadata() rejects anything else.
if [ ! -f "$PRIVKEY_DIR/credential_request.pem" ]; then
    echo "pki-init: generating credential-request key"
    openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVKEY_DIR/credential_request.pem"
fi

chmod 644 "$PRIVKEY_DIR"/* "$CERT_DIR"/* "$DS_DIR"/*
echo "pki-init: ready"
ls "$DS_DIR" | sed 's/^/  ds\//'
ls "$CERT_DIR" | sed 's/^/  cert\//'
ls "$PRIVKEY_DIR" | sed 's/^/  privKey\//'
