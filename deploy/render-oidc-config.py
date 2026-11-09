#!/usr/bin/env python3
"""Merge deploy/oidc-config.patch.json over the OIDC image's own config.json.

Upstream's config is 359 lines and almost all of it is fine as shipped. Only
four values vary per deployment, so this reads the image's copy, deep-merges the
patch, and prints the result for compose to mount.

    ./deploy/render-oidc-config.py ghcr.io/grnet/eudi-srv-issuer-oidc-py:TAG

Keys beginning with an underscore are comments and are dropped. Lists replace
rather than append: allowed_htu is an allowlist, and appending to upstream's
would leave eudiw.dev URLs on it.
"""
import json
import os
import subprocess
import sys


def merge(base, patch):
    for k, v in patch.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            merge(base[k], v)
        else:
            base[k] = v
    return base


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    image = sys.argv[1]

    # Read the config out of the image rather than the repo: this repository is
    # the issuer's, and the OIDC config belongs to the image being deployed.
    shipped = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "cat", image, "/app/config.json"],
        capture_output=True, text=True, check=True,
    ).stdout

    here = __file__.rsplit("/", 1)[0]
    with open(f"{here}/oidc-config.patch.json") as f:
        patch = json.load(f)

    config = merge(json.loads(shipped), patch)

    # The wallet providers list for this deploy, e.g. the _empty twin for the
    # Launchpad testbed's negative cases; the patch's otherwise.
    lote_url = os.environ.get("WALLET_PROVIDERS_LOTE_URL")
    if lote_url:
        config["op"]["server_info"]["endpoint"]["token"]["kwargs"]["wallet_providers_lote_url"] = lote_url

    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()
