#!/usr/bin/env sh
#
# Lay out the issuer's document-signing material into /etc/eudiw/pid-issuer-dev,
# which the deploy stack mounts as a named volume.
#
# Safe to run on every deploy. It unpacks material that ships in the image and
# generates two keys only if they are absent, so repeated runs produce the same
# result. That is what makes it usable as an init container, unlike the WeBuild
# scripts in interop_event_tools, which mint a new CA on every run and must stay
# a deliberate ceremony.
#
# The reference archives are EU *test* material; the config signs with GRNET's
# document signer, passed in by the deploy. The generated keys are per-deployment.
set -eu

OUT="${PKI_OUT:-/etc/eudiw/pid-issuer-dev}"
CERT_DIR="$OUT/cert"
PRIVKEY_DIR="$OUT/privKey"
TOKENS="${TEST_TOKENS:-/app/api_docs/test_tokens}"

# The reference stack ships several document signers. PID-DS-0002 is the one
# upstream's config already names.
DS="PID-DS-0002"
DS_PASSWORD="pid-ds-0002"

mkdir -p "$CERT_DIR" "$PRIVKEY_DIR"

if [ -f "$CERT_DIR/${DS}_EU_cert.der" ]; then
    echo "pki-init: document signer already unpacked"
else
    echo "pki-init: unpacking $DS"
    # The zip holds <DS>.cert.der and <DS>.pid-ds-0002.key.pem. Python's zipfile
    # rather than unzip, which the slim runtime image does not carry.
    python3 -m zipfile -e "$TOKENS/DS-token/$DS.zip" "$PRIVKEY_DIR"
    mv -f "$PRIVKEY_DIR/$DS.cert.der" "$CERT_DIR/"

    # The shipped key is an encrypted PKCS#8 blob whose password is its own
    # friendlyName. The app hands the configured password straight to
    # load_pem_private_key(), which wants bytes rather than the string YAML
    # gives it, so an encrypted key cannot be used as-is. Decrypting here keeps
    # metadata_signing_key_password null.
    DS_KEY=$(find "$PRIVKEY_DIR" -maxdepth 1 -name "$DS*.key.pem" -print | head -1)
    openssl pkey -in "$DS_KEY" -passin "pass:$DS_PASSWORD" \
        -out "$PRIVKEY_DIR/$DS.decrypted.pem"

    # The signed-metadata path loads the certificate as PEM, the mdoc signing
    # path reads DER. Keep both.
    openssl x509 -inform der -in "$CERT_DIR/$DS.cert.der" -out "$CERT_DIR/$DS.cert.pem"

    # The config names country-specific files. All point at the same test signer
    # in the reference setup.
    for country in EE EU PT UT; do
        cp -f "$PRIVKEY_DIR/$DS.decrypted.pem" "$PRIVKEY_DIR/${DS}_${country}.pem"
        cp -f "$CERT_DIR/$DS.cert.der"         "$CERT_DIR/${DS}_${country}_cert.der"
        cp -f "$CERT_DIR/$DS.cert.pem"         "$CERT_DIR/${DS}_${country}_cert.pem"
    done
    rm -f "$PRIVKEY_DIR/$DS.decrypted.pem"

    gunzip -c "$TOKENS/IACA-token/PIDIssuerCAUT01.pem.gz" > "$CERT_DIR/PIDIssuerCAUT01.pem"
fi

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

# Optional: GRNET's WE BUILD-onboarded certificate, the one on the Commission's
# PID providers list, signs the SD-JWT VC PIDs (pid_sd_jwt in the issuer config).
# Without it the document signer signs everything. Rewritten on every run, and
# removed when not provided, so the issuer config's optional entry is skipped.
PID_DIR="$OUT/ds-pid"
PID_SD_JWT_KEY_FILE="${PID_SD_JWT_KEY_FILE:-/run/secrets/pid-sd-jwt-key}"
rm -rf "$PID_DIR"
if [ -n "${PID_SD_JWT_CERT_PEM:-}" ] && [ -s "$PID_SD_JWT_KEY_FILE" ]; then
    mkdir -p "$PID_DIR"
    # The leaf only: openssl x509 reads the first certificate of a bundle.
    printf '%s\n' "$PID_SD_JWT_CERT_PEM" | openssl x509 -out "$PID_DIR/signing.pem"
    openssl x509 -in "$PID_DIR/signing.pem" -outform der -out "$PID_DIR/signing.der"
    printf '%s\n' "$(cat "$PID_SD_JWT_KEY_FILE")" > "$PID_DIR/signing.key"
    if [ "$(openssl pkey -in "$PID_DIR/signing.key" -pubout)" != "$(openssl x509 -in "$PID_DIR/signing.pem" -noout -pubkey)" ]; then
        echo "pki-init: the PID SD-JWT key does not belong to its certificate" >&2
        exit 1
    fi
    chmod 644 "$PID_DIR"/*
    echo "pki-init: PID SD-JWT signer $(openssl x509 -in "$PID_DIR/signing.pem" -noout -subject)"
else
    echo "pki-init: no PID SD-JWT signer; the document signer signs every credential"
fi

# Optional: the access certificate (WRPAC) and registration certificate (WRPRC)
# the Launchpad registrar issued for the issuer. The WRPAC signs the frontend's
# metadata, which wallets check against the Commission's WRPAC providers list;
# the WRPRC goes into the metadata as issuer_info. Without a WRPAC the document
# signer signs the metadata, as before, and registration.jwt is left empty,
# which the app reads as no issuer_info. Rewritten on every run.
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
printf '%s' "${WRP_REGISTRATION_CERT:-}" > "$WRP_DIR/registration.jwt"
if [ -s "$WRP_DIR/registration.jwt" ]; then
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
