# Deploying the issuer

One stack, three containers plus an init container: the PID issuer, the OIDC
authorization server, and the Postgres they need.

`docker-build.yml` publishes an image on push. `docker-deploy.yml` is manual
only, so merging a branch never changes what is running.

The deploy drives the box's Docker daemon over SSH. Nothing is copied to the
server: compose reads the file and the environment on the runner and sends the
daemon an already-expanded spec. Only containers, named volumes and the Docker
socket exist on the box.

## Two repositories, one stack

The OIDC server is built in `eudi-srv-issuer-oidc-py` and deployed from here.
The dependency runs one way, the issuer calls it for `/introspection` and
sends browsers to its `/verify/user`, never the reverse, and the config naming
both services lives here. That repository has a build workflow and no `deploy/`.

## Before the first deploy

**The edge must be up.** nginx-proxy, acme-companion and `proxy-net` are defined
in `eudi-srv-wallet-provider`. The preflight step stops if `proxy-net` is
missing.

**A document signer, from `WEBUILD/pki`.** The `pki-init` container writes it
into a named volume from what the deploy passes in, so nothing is placed on the
box by hand. See "The document signer" below.

## Repository secrets

| Secret | What it is |
| --- | --- |
| `SSH_KEY` | Private key authorised for `ubuntu@3.69.83.252`. Written to `~/.ssh/eudiw-deploy` on the runner. Paste the whole file, BEGIN and END lines included. |
| `DATABASE_PASSWORD` | Postgres password for this stack. Generated, not reused. |
| `STATUSLIST_API_KEY` | `X-Api-Key` the issuer sends to the status list when allocating a revocation index. Must match that service's own `API_key`, currently `test`. |
| `DS_KEY_PEM` | The document signer's private key, from `WEBUILD/pki/leaves/pid-ds-gr-01/pid-ds-gr-01.key`. See "The document signer" below. |

Everything else is committed in `stack.env`, where it is reviewable in a diff.

Three repository **variables**, not secrets, because all are public and a
variable can be read back and compared:

| Variable | What it is |
| --- | --- |
| `CRL_PEM` | The CRL, from `WEBUILD/pki/crl/crl.pem`. Refreshed yearly, see "The CRL" below. |
| `IACA_PEM` | The IACA, from `WEBUILD/pki/ca/root-ca-grnet.pem`. Changes only on a reissue. |
| `DS_CERT_PEM` | The document signer's certificate, from `WEBUILD/pki/leaves/pid-ds-gr-01/pid-ds-gr-01.crt`. |

    gh variable set CRL_PEM     --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/crl/crl.pem
    gh variable set IACA_PEM    --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/ca/root-ca-grnet.pem
    gh variable set DS_CERT_PEM --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/leaves/pid-ds-gr-01/pid-ds-gr-01.crt
    gh secret set   DS_KEY_PEM  --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/leaves/pid-ds-gr-01/pid-ds-gr-01.key

Nothing keeps `STATUSLIST_API_KEY` in step with the status list's copy. Changing
one without the other means every credential issuance fails at the revocation
call.

Optional, for the access and registration certificates below: the variables
`WRP_ACCESS_CERT_PEM` and `WRP_REGISTRATION_CERT`, and the secret
`WRP_ACCESS_KEY_PEM`. Unset, the document signer signs the metadata and there
is no `issuer_info`.

    gh variable set WRP_ACCESS_CERT_PEM   --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/registrar/issuer/wrpac.pem
    gh secret set   WRP_ACCESS_KEY_PEM    --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/registrar/issuer/wrpac.key
    gh variable set WRP_REGISTRATION_CERT --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/registrar/issuer/wrprc.jwt

## The access and registration certificates

Wallets check the certificate in the signed metadata's `x5c` against the
Commission's list of access certificate providers (`wrpac-providers`), and
read the issuer's registration certificate from `issuer_info`. GRNET's come
from the EUDI Wallets Launchpad registrar (`itb.registry.serviceproviders.eudiw.dev`):
the WRPAC `CN=GRNET Issuer, O=GRNET S.A., organizationIdentifier=VATGR-EL094536469`,
issued by `PID Issuer CA 02` (on the Commission's list and on upstream's), and
the WRPRC with `sub` `VATGR-EL094536469` and the PID, QEAA, public EAA and
non-qualified EAA provider entitlements. Both valid to October 2028. Kept in
`WEBUILD/pki/registrar/issuer/`.

`pki-init` writes them to `wrp/` in the volume, and the config points the
frontend's metadata key, certificate and `registration_certificate_path` there.
Without them it copies the document signer into `wrp/` and leaves
`registration.jwt` empty, which the app reads as no `issuer_info`. The issuer's
environment carries `WRP_SHA256`, so a change recreates it.

**The WRPRC registers the SD-JWT VC PID only** (`provides_attestations`). A
wallet that enforces the registration blocks the other credentials from this
issuer as over-provided: the mdoc PID, the payment card, the mDL. GRNET's wallet
enforces it only with "Check Registration Certificates" on, which is off by
default.

## Routing

Every service shares `demo.eudiw.grnet.gr`, the only hostname that exists, and is
told apart by path:

| Path | Service |
| --- | --- |
| `/` | status list |
| `/wallet-provider/` | wallet provider |
| `/issuer/` | this issuer |
| `/issuer/oidc/` | the OIDC server, nested; see "Why the OIDC server is under /issuer/" |
| `/revocation/` | the CRL, in this stack too; see "The CRL" below |

`VIRTUAL_DEST=/` strips the prefix, so both apps serve at their own root and are
unaware of it. The issuer rewrites its own published metadata at startup by
substituting `service_url` for the `credential_issuer` value baked into
`app/metadata_config/*.json`, so the prefix propagates without a code change.

### Discovery endpoints need a proxy rule

RFC 8414 §3.1 puts discovery metadata at the **host root** regardless of the
issuer's path: a client asking about `https://host/issuer` fetches
`https://host/.well-known/openid-credential-issuer/issuer`. On this hostname the
root belongs to the status list, so without a rule the wallet gets its 404.

The rule lives in `eudi-srv-wallet-provider`'s deploy compose, as an inline
config mounted at `/etc/nginx/vhost.d/demo.eudiw.grnet.gr`, because that stack
owns the proxy. It proxies to `<host>-<sha1 of VIRTUAL_PATH>`, which is how
nginx-proxy names a path-routed upstream.

Changing `ISSUER_PATH` or `OIDC_PATH` here means recomputing those hashes there:

    printf '%s' "/issuer/" | sha1sum

## Why the OIDC server is under /issuer/

It was at `/auth/` until 2026-09-24, and discovery was broken three ways:

    issuer's authorization_servers        https://<host>/issuer/oidc       404
    the issuer's own AS metadata           endpoints under /issuer/oidc/    404
    the OIDC server's own metadata         https://dev.issuer.eudiw.dev/oidc, the EU's server

Upstream assumes the authorization server is **the credential issuer URL plus
`/oidc`**. Its issuer runs at a host root, so for them that is `/oidc`; ours is
at `/issuer`, so for us it is `/issuer/oidc`. The issuer's metadata, its own
copy of the AS metadata, and the frontend (`app/__init__.py:268`) all derive it
that way, by substituting the base URL. Mounting the OIDC server there makes
all of them true as shipped, instead of overriding each.

nginx picks the longest prefix, so `/issuer/oidc/` wins over `/issuer/`. The
issuer serves nothing under `/oidc/` itself.

**The OIDC server's metadata still needs rewriting.** Its well-known routes send
`/app/openid-configuration.json` as shipped (`views.py`, `well_known`), and
`config.json` never reaches it, so it names upstream's host however `domain` and
`base_url` are set. `deploy/render-oidc-metadata.py` reads it out of the image,
substitutes `OIDC_PUBLIC_URL` for `https://dev.issuer.eudiw.dev/oidc`, and fails
if any `eudiw.dev` URL survives. Compose mounts the result over the original.

One more upstream URL, left alone: `views.py:865` redirects to
`https://dev.issuer.eudiw.dev/oidc/verify/user`, but it is in `/jwt_token`, a
route its own comment calls a test and nothing calls.

Changing `OIDC_PATH` means changing `oidc-config.patch.json` (`domain`,
`base_url`, `allowed_htu`), the frontend's `OIDC_PUBLIC_URL`, and the
`/.well-known/…/issuer/oidc` rule and its sha1 in `eudi-srv-wallet-provider`.
It also changes what every issued token names as its issuer.

## The CRL

The `crl` service is stock nginx serving two public files:

    http://demo.eudiw.grnet.gr/revocation/crl.pem      the CRL, DER
    https://demo.eudiw.grnet.gr/pki/root-ca-grnet.pem  the IACA, PEM, https only

The IACA was under `/revocation/` until 2026-09-24. It moved because a trust
anchor is not revocation data, and because the plain-http exception covers the
whole `/revocation/` prefix: a certificate you are about to trust should not
come over plain http. `PKI_PATH` is outside that exception, so it redirects
like every other path, and the deploy workflow checks that it does.

The first URL is not ours to choose. It is the `crlDistributionPoints` of the
IACA and of every certificate under it, signed in, so `CRL_PATH` in `stack.env`
cannot change without reissuing the whole PKI. It lives in this stack because
the IACA is the root above this issuer's document signer; the issuer itself
never fetches it.

Three things about it are deliberate and look wrong.

**It is DER, at a URL ending in `.pem`.** RFC 5280 §4.2.1.13 requires a single
DER-encoded CRL at an http distribution point. The name comes from gfour's
server, which served PEM, and is now permanent. Served PEM, openssl fails with
`missing asn1 encoding` and Go refuses it; Java accepts either. `Content-Type`
is `application/pkix-crl`, per RFC 2585. The source stays PEM, in
`WEBUILD/pki` and in `CRL_PEM`, and the deploy converts it.

**It is served over plain http, and must not redirect.** CRLs are http by
convention, being signed objects, and a JVM verifier will not follow an http to
https redirect: `HttpURLConnection` returns the 301 and stops, checked. **Do not
set `HTTPS_METHOD=noredirect` on this container** to get that. nginx-proxy
applies it per hostname, taking the first container that sets it, so it would
drop the redirect and HSTS for every service on the host. The exception is a
port-80 server block in `eudi-srv-wallet-provider`'s compose, which must be
deployed first. Without it, the http URL returns 301 and the deploy fails its
check.

**It arrives as environment variables, not configs.** Compose recreates a
container when its environment changes but not when a config's content does, so
this way a CRL refresh rolls out on a plain deploy and restarts only this
container. The DER travels base64-encoded and is decoded at start.

The deploy workflow refuses a CRL that does not verify against the IACA. That is
the failure already live on gfour's `:5607`, whose CRL is signed by the
superseded root.

### Refreshing it, yearly

The current one runs to **Sep 22 2027**. `nextUpdate` is a year after issue;
past it, verifiers treat the CRL as stale. Why a year, and why the IACA key is
not in GitHub so a workflow could do it, is in `WEBUILD/pki/README.md`.

    cd ../pki && ./pki.sh crl
    gh variable set CRL_PEM --repo grnet/eudi-srv-web-issuing-eudiw-py < crl/crl.pem
    # then run the Deploy workflow

After deploying, the workflow checks that the http URL answers 200 without a
redirect.

## The document signer

The PIDs and the frontend's signed metadata are signed by `pid-ds-gr-01`, issued
from the IACA in `WEBUILD/pki` with `./pki.sh leaf pid-ds-gr-01`. Until
2026-09-25 they were signed with upstream's reference test signer, `PID-DS-0002`
under `PID Issuer CA - UT 01`, which expired on Sep 24 2025 and which no wallet
trusting GRNET could accept.

**How it arrives.** The key is a compose secret, `ds-key`, from `DS_KEY_PEM`, so
it is a file in `pki-init` rather than something `docker inspect` prints. The
certificate is in `pki-init`'s environment. `pki-init` writes both to `ds/` in
the volume on every run, as `signing.key`, `signing.der` (PID signing reads DER)
and `signing.pem` (the metadata's x5c), and fails if the key is not the
certificate's. Not into `cert/`: the issuer loads every `*.pem` there as a
trusted CA, which a signer is not. The IACA does go into `cert/`, so a PID issued
here verifies when a wallet presents it back to log in.

The deploy workflow refuses a signer that does not chain to the IACA or whose
key is not its own.

**Signed metadata comes from the frontend.** The EUDI wallet requires signed
issuer metadata by default (OpenID4VCI 1.0 §12.2.2) and refuses an issuer
without it, showing "Issuance blocked". As upstream designed it, the frontend is
the credential issuer a wallet is pointed at: at startup it has its metadata
signed here, through `/metadata/metadata_signer` with the `frontends_config` key
and certificate, and serves the JWT to `Accept: application/jwt`. This backend's
own well-known route is unsigned, so **wallets must use the frontend's URL**,
`FRONTEND_PUBLIC_URL`, not `ISSUER_PUBLIC_URL`. The credential endpoints it
advertises are still this backend's.

**The frontend signs once, at startup**, and caches the result. After a deploy
that changes the signer, restart it (`docker restart eudiw-frontend`) or it
keeps serving metadata signed by the old one. The deploy workflow fetches the
metadata as the wallet does and checks the x5c is this signer.

**Renewing it**, before Oct 29 2027 (400 days):

    cd ../pki && ./pki.sh leaf pid-ds-gr-01
    gh variable set DS_CERT_PEM --repo grnet/eudi-srv-web-issuing-eudiw-py < leaves/pid-ds-gr-01/pid-ds-gr-01.crt
    gh secret set   DS_KEY_PEM  --repo grnet/eudi-srv-web-issuing-eudiw-py < leaves/pid-ds-gr-01/pid-ds-gr-01.key
    # then run the Deploy workflow

    docker restart eudiw-frontend          # DOCKER_HOST=ssh://aws-gfour

A plain deploy is enough for the issuer. The certificate's fingerprint is in its
environment as `DS_CERT_SHA256`, unread by the app, so a new signer changes the
service definition and compose recreates the issuer, which loads its key only at
startup. The frontend is another stack and needs the restart above. Wallets need
nothing: they trust the IACA, not the signer.

## The OIDC config

Upstream's `config.json` is 359 lines and almost all of it is fine as shipped.
Four values vary per deployment, so `render-oidc-config.py` reads the config out
of the image being deployed and merges `oidc-config.patch.json` over it. The
result is passed to compose as `OIDC_CONFIG_JSON` and mounted as a config.

`idpyoidc` expands `{domain}` itself, so setting `domain` also fixes
`server_name`, `op.server_info.issuer` and `webserver.domain`.

Worth knowing: `allowed_htu` is a DPoP allowlist. A token request whose URL is
not on it is rejected, so it has to name the token endpoint as the wallet sees
it, through the proxy and with the prefix.

## Internal and external URLs

The authorization server is reached two ways, and the config says so:

    base_url:             https://demo.eudiw.grnet.gr/issuer/oidc               metadata
    user_verify_endpoint: https://demo.eudiw.grnet.gr/issuer/oidc/verify/user   browser redirect
    internal_url:         http://oidc:5000                                      issuer to OIDC, in-network

`user_verify_endpoint` must be public: the issuer redirects the browser there
after the form (`app/route_dynamic.py`). Until 2026-09-25 it used
`internal_url`, and the browser landed on `http://oidc:5000`, which does not
resolve outside Docker.

Plain http on the internal one is not a shortcut. The OIDC server's `ssl_context`
is commented out upstream, so it serves http and nginx-proxy terminates TLS.
`app/route_oidc.py:297` prefers `internal_url` and falls back to `base_url`;
without it the issuer would dial its own public URL and go out through the proxy
and back.

## Postgres

Required at startup, not optional. `app/__init__.py:132` calls `init_db_status`
at import time, and the pool opens eagerly with upstream's own comment saying it
raises if the database is unreachable. It then creates three tables. This arrived
with the TS3 v1.5 work; older versions of this service had no database.

16.14-alpine, matching what `install.md` states the issuer was tested against.
Note the data mount is `/var/lib/postgresql/data`, correct up to 17; the wallet
provider runs 18, which changed that path.

## Image tags

Both deployed services already use `sha-` tags rather than `latest` or a branch
tag, because a sha- tag names exactly one build and is published on every run.
`latest` is only published from a repository's default branch, and none of these
branches has merged there.

The OIDC tag cannot be derived from a commit in this repository, so the
workflow takes it as a required input. Use the newest `sha-` tag with a
published image in `eudi-srv-issuer-oidc-py`. That is not always the branch
tip: the build skips markdown-only commits.

## Config changes need a recreate

Compose does not recreate a container when only a config's **content** changes.
It compares the service definition, and `content: ${VAR}` is textually the same
whatever `VAR` expands to. So a fix to `stack.env`, `config_issuer_backend.yaml.template`
or `oidc-config.patch.json` deploys without taking effect, and the container
keeps running with the old file. The deploy reports success.

In the Deploy workflow, tick **Recreate containers even if the image tag is
unchanged**.

Cost a debugging cycle on the first deploy: the issuer kept crashing on a config
error that had already been fixed.

The wallet provider's stack is not affected the same way. Its inline configs hold
literal text, so editing one changes the service definition and compose recreates
on its own. Only `content: ${VAR}` hides the change.

## Still to sort

- `pki-init` still unpacks the reference signer, `PID-DS-0002`, and its CA into
  the volume. Nothing signs with it any more, but its CA and certificates are in
  `cert/`, so the issuer still trusts them for presented PIDs.
- **Wallet attestations: no revocation check, and weak trust on the backend.**
  EU's validators reject our wallet provider's and status list's certificates,
  so both are off. The OIDC server trusts wallet attestations by the wallet
  provider's certificate, fetched from its `/jwks` and mounted into
  `oidc_trusted_attesters/` (`oidc-config.patch.json`). The backend has no such
  option: with `trust_validator.enabled: false` it accepts a key attestation
  from any signer. Neither checks revocation. To restore both, run our own
  trust and status validators (`eu-digital-identity-wallet/eudi-srv-trust-validator`)
  with GRNET's anchors, including the status list's signer, and point all four
  URLs at them.
- `dynamic_presentation_url` still points at an EU reference service.
