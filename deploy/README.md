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
The dependency runs one way: the issuer calls it for `/introspection`,
`/preauth_generate` and its keys, and sends browsers to its `/verify/user`,
never the reverse. Both configs live here, as templates. That repository has a
build workflow and no `deploy/`.

The frontend (`eudi-srv-web-issuing-frontend-eudiw-py`) is a stack of its own,
but versions go together: since 0.11.0 it loads its metadata from this issuer
with an API key (`ISSUER_BACKEND_API_KEY`, below), and an older frontend sends
none. Upgrade both at once.

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
| `DS_KEY_PEM` | The document signer's private key, `WEBUILD/pki/leaves/pid-ds-gr-01/pid-ds-gr-01.key` (DS 01 kept its key). See "The document signer" below. |
| `ISSUER_SECRET_KEY` | Signs the issuer's session cookie (`secret_key`). At least 32 characters; the issuer refuses to start otherwise. |
| `ISSUER_BACKEND_API_KEY` | `X-Api-Key` the frontend sends to load its metadata (`backend_api_key`). The same value is the frontend repository's secret of the same name. |
| `ISSUER_ADMIN_API_KEY` | `X-Api-Key` of the administrative endpoints (`/logs`, `/admin/...`, `/metadata/metadata_signer`). Never given to a frontend. |
| `OIDC_BACKEND_API_KEY` | `X-Api-Key` the issuer sends to the OIDC server's `/introspection` and `/preauth_generate`: the issuer's `authorization_server.api_key` and the OIDC server's `backend_api_key`. |
| `GR_OIDC_CLIENT_SECRET` | Client secret at the third-party OpenID Connect provider behind the `GR` country (`countries.GR.auth.client_secret`). Optional: the deploy only warns without it, but the GR login then fails. Its base URL and client id are `GR_OIDC_BASE_URL` and `GR_OIDC_CLIENT_ID` in `stack.env`. |

The four before it arrived with 0.11.0 (issuer) and 0.10.0 (OIDC server). Generated,
each a different random value:

    for s in ISSUER_SECRET_KEY ISSUER_BACKEND_API_KEY ISSUER_ADMIN_API_KEY OIDC_BACKEND_API_KEY; do
      openssl rand -hex 32 | gh secret set $s --repo grnet/eudi-srv-web-issuing-eudiw-py
    done

`ISSUER_BACKEND_API_KEY` must also be set, to the same value, in
`grnet/eudi-srv-web-issuing-frontend-eudiw-py`, so generate it once and set it
in both:

    k=$(openssl rand -hex 32)
    printf '%s' "$k" | gh secret set ISSUER_BACKEND_API_KEY --repo grnet/eudi-srv-web-issuing-eudiw-py
    printf '%s' "$k" | gh secret set ISSUER_BACKEND_API_KEY --repo grnet/eudi-srv-web-issuing-frontend-eudiw-py

Everything else is committed in `stack.env`, where it is reviewable in a diff.

Three repository **variables**, not secrets, because all are public and a
variable can be read back and compared:

| Variable | What it is |
| --- | --- |
| `CRL_PEM` | The CRL, from `WEBUILD/pki/crl/crl.pem`. Refreshed yearly, see "The CRL" below. |
| `IACA_PEM` | The IACA, from `WEBUILD/pki/ca/root-ca-grnet.pem`. Changes only on a reissue. |
| `DS_CERT_PEM` | The document signer's certificate, `GRNET PID Provider DS 01`, from `WEBUILD/pki/etsi-profile/grnet-pid-ds-etsi.pem`. |

    gh variable set CRL_PEM     --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/crl/crl.pem
    gh variable set IACA_PEM    --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/ca/root-ca-grnet.pem
    gh variable set DS_CERT_PEM --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/etsi-profile/grnet-pid-ds-etsi.pem
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
Without a WRPAC it copies the document signer into `wrp/`. Without a WRPRC it
writes no `registration.jwt`, and the deploy leaves `registration_certificate_path`
empty: since 0.11.0 the issuer refuses to start on an empty file, but skips an
empty path, and then publishes no `issuer_info`. The issuer's environment
carries `WRP_SHA256`, so a change recreates it.

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

For the issuer, `VIRTUAL_DEST=/` strips the prefix, so it serves at its own root
and is unaware of it; `service_url` tells it where it is published.

The OIDC server has no `VIRTUAL_DEST`, so the prefix is passed on. Since 0.10.0
it serves every route under the path of its `domain`, `/issuer/oidc/...`, and
it was stripped before that.

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

**The OIDC server's rule changed with 0.10.0.** Each frontend now has its own
authorization server issuer, `https://demo.eudiw.grnet.gr/issuer/oidc/<frontend id>`,
so its RFC 8414 metadata is at
`/.well-known/oauth-authorization-server/issuer/oidc/<frontend id>`. The server
answers that path itself, at its own root, so the edge must forward the URI
unchanged. The old rule matched only `.../issuer/oidc` and rewrote it to
`/.well-known/$1`. The metadata is also at
`/issuer/oidc/<frontend id>/.well-known/oauth-authorization-server`, which needs
no rule. The deploy checks both.

The backend's own discovery rule (`/.well-known/<service>/issuer`) has nothing to
serve any more: since 0.11.0 only the frontend publishes credential issuer
metadata.

## Why the OIDC server is under /issuer/

It was at `/auth/` until 2026-09-24, and discovery was broken three ways:

    issuer's authorization_servers        https://<host>/issuer/oidc       404
    the issuer's own AS metadata           endpoints under /issuer/oidc/    404
    the OIDC server's own metadata         https://dev.issuer.eudiw.dev/oidc, the EU's server

Until 0.11.0 upstream assumed the authorization server is **the credential
issuer URL plus `/oidc`**, and derived it that way in the issuer's metadata and
the frontend. Ours is at `/issuer`, so it went to `/issuer/oidc`. Since 0.11.0
the issuer names `<authorization_server.base_url>/<frontend id>` instead, so
the path is a choice now, kept so that URLs wallets have seen stay put.

nginx picks the longest prefix, so `/issuer/oidc/` wins over `/issuer/`. The
issuer serves nothing under `/oidc/` itself.

Since 0.10.0 the OIDC server builds its metadata from its config, so nothing is
rewritten any more. Before that it sent upstream's `openid-configuration.json`
as shipped, and the deploy substituted our URL into it.

Changing `OIDC_PATH` means changing `OIDC_DOMAIN` and `OIDC_PUBLIC_URL` in
`stack.env`, and the `/.well-known/…/issuer/oidc` rule and its sha1 in
`eudi-srv-wallet-provider`. It also changes what every issued token names as
its issuer, so wallets holding refresh tokens must start over.

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

Every credential, both PID formats included, is signed by `GRNET PID Provider
DS 01` (`WEBUILD/pki/etsi-profile/grnet-pid-ds-etsi.pem`), issued from the IACA
in `WEBUILD/pki` in the ETSI PID provider profile, with the key of
`pid-ds-gr-01`. It replaced `pid-ds-gr-01` at the Launchpad (October 2026),
because the Commission's trust validator wants the ETSI profile, and since then
it also signs the SD-JWT VC PIDs. With a WRPAC configured, that signs the
frontend's metadata instead; see "The access and registration certificates".
Until
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
signed here, through `/metadata/<frontend id>/signed` with `ISSUER_BACKEND_API_KEY`
(since 0.11.0; `/metadata/metadata_signer` before), signed with the
`frontends_config` key and certificate, and serves the JWT to
`Accept: application/jwt`. This backend publishes no metadata of its own any
more, so **wallets must use the frontend's URL**,
`FRONTEND_PUBLIC_URL`, not `ISSUER_PUBLIC_URL`. The credential endpoints it
advertises are still this backend's.

**The frontend signs once, at startup**, and caches the result. After a deploy
that changes the signer, restart it (`docker restart eudiw-frontend`) or it
keeps serving metadata signed by the old one. The deploy workflow fetches the
metadata as the wallet does and checks the x5c is this signer.

**Renewing it**, before Dec 3 2027: reissue it in the ETSI profile
(`WEBUILD/pki/etsi-profile/pid-ds.cnf`), then

    gh variable set DS_CERT_PEM --repo grnet/eudi-srv-web-issuing-eudiw-py < ../pki/etsi-profile/grnet-pid-ds-etsi.pem
    gh secret set   DS_KEY_PEM  --repo grnet/eudi-srv-web-issuing-eudiw-py < <the new key, if it changed>
    # then run the Deploy workflow

    docker restart eudiw-frontend          # DOCKER_HOST=ssh://aws-gfour

A plain deploy is enough for the issuer. The certificate's fingerprint is in its
environment as `DS_CERT_SHA256`, unread by the app, so a new signer changes the
service definition and compose recreates the issuer, which loads its key only at
startup. The frontend is another stack and needs the restart above. Wallets need
nothing: they trust the IACA, not the signer.

## The OIDC config

Since 0.10.0 the OIDC image ships no configuration. `authorization_config.yaml.template`
is upstream's `config.yaml` with our values, each marked `GRNET:`. The deploy
runs envsubst over it, like the issuer's template, and compose mounts the
result at `/etc/issuer_config/authorization_config.yaml`, where the image's CMD
reads it. Until 0.10.0 the deploy merged a small patch over the `config.json`
inside the image.

What it sets:

| Key | Value |
| --- | --- |
| `domain` | `OIDC_DOMAIN`, `demo.eudiw.grnet.gr/issuer/oidc`. The server expands `{domain}`, so this also sets `server_name`, `op.server_info.issuer` and `webserver.domain`. |
| `base_url` | `OIDC_PUBLIC_URL` |
| `frontends` | `FRONTEND_ID`, our one frontend |
| `authorization_redirect_url` | the issuer's `/auth_choice`, which now receives a signed `session_token` |
| `backend_api_key` | `OIDC_BACKEND_API_KEY` |
| token endpoint kwargs | the Commission's wallet providers list (`WALLET_PROVIDERS_LOTE_URL`) and its signer CAs, the pinned wallet provider as a fallback, and both EU validators off |

Upstream's defaults stay: PAR, PKCE S256, DPoP and wallet attestation all
required, as HAIP asks. `allowed_htu` is gone: since 0.10.0 the DPoP `htu` and
the wallet attestation PoP `aud` are each frontend's own endpoints.

The server writes its keys to `/app/private` on first start, a named volume
(`oidc-private`), so a redeploy keeps them. New keys would invalidate
outstanding tokens and the `session_token` the issuer verifies.

The wallet providers list needs GRNET's idpy-oidc in the image, built from
`eudi-srv-issuer-oidc-py`'s `grnet` with `requirements.txt` pinned to a commit
that has it. An image without it ignores the list and trusts the pinned wallet
provider certificate instead.

For the testbed's negative cases, run the Deploy workflow with
`wallet_providers_lote_url` set to the list's `_empty` copy.

## Internal and external URLs

The authorization server is reached two ways, and the config says so:

    base_url:             https://demo.eudiw.grnet.gr/issuer/oidc               metadata
    user_verify_endpoint: https://demo.eudiw.grnet.gr/issuer/oidc/verify/user   browser redirect
    internal_url:         http://oidc:5000/issuer/oidc                          issuer to OIDC, in-network

`user_verify_endpoint` must be public: the issuer redirects the browser there
after the form. Until 2026-09-25 it used `internal_url`, and the browser landed
on `http://oidc:5000`, which does not resolve outside Docker.

Plain http on the internal one is not a shortcut. The OIDC server has no TLS,
so it serves http and nginx-proxy terminates TLS. `app/services/auth_server.py`
prefers `internal_url` for `/introspection`, `/preauth_generate` and the keys
that verify the `session_token`, and falls back to `base_url`; without it the
issuer would dial its own public URL and go out through the proxy and back.
Since 0.10.0 it carries the path: the server serves under it.

## Postgres

Required at startup, not optional. The issuer opens its status database pool
when it starts (`app/factory.py`), and fails if the database is unreachable. It then creates three tables. This arrived
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
whatever `VAR` expands to. So a fix to `stack.env` or a template would deploy
without taking effect, the container keeping the old file, and the deploy would
report success. That cost a debugging cycle on the first deploy: the issuer
kept crashing on a config error that had already been fixed.

So the deploy puts a hash of each rendered config in its container's
environment (`ISSUER_CONFIG_SHA256`, `OIDC_CONFIG_SHA256`), which the apps never
read. A changed config changes the service definition, and compose recreates
the container. The same goes for the signers (`DS_CERT_SHA256`, `WRP_SHA256`)
and the wallet provider's certificate (`WALLET_PROVIDER_CERT_SHA256`).

**Recreate containers even if the image tag is unchanged**, in the Deploy
workflow, is still there for anything else.

## Key attestations

Almost every credential requires a key attestation with its proof
(`key_attestations_required` in the metadata), the PIDs and the SCA cards
included. Since 0.11.0 the issuer checks its `x5c` chain against local trust
anchors whenever the trust validator is off, as it is here. Before, it took a
key attestation from any signer.

Those anchors are the wallet provider's certificate, which the deploy reads from
its `/jwks` and compose mounts at `/etc/eudiw/trust/wallet-providers/`
(`trusted_CAs_paths.key_attestation`). Not `cert/`: that holds GRNET's IACA,
which anchors PIDs presented back, and a wallet provider must not be able to
anchor a PID signer, nor the IACA a key attestation.

So the issuer accepts key attestations from GRNET's wallet provider only. A
wallet from another provider on the Commission's list gets its wallet
attestation accepted by the OIDC server, and then its key attestation refused
here.

## Still to sort

- **Revocation of wallet and key attestations is not checked.** EU's status
  validator rejects our status list's signer, so it is off in both services.
  Our own status validator (`eu-digital-identity-wallet/eudi-srv-status-validator-py`)
  with GRNET's anchors would restore it.
- **Key attestations from other wallet providers are refused**, see "Key
  attestations". The issuer cannot read the wallet providers list as the OIDC
  server does. Putting the list's certificates in
  `/etc/eudiw/trust/wallet-providers/` at deploy time, or our own trust
  validator, would fix it.
- The issuer posts its `/display_*` payloads to the frontend unsigned and logs a
  warning. A `payload_key` shared with the frontend (`frontends_config` here,
  `payload_key` there) would sign them.
