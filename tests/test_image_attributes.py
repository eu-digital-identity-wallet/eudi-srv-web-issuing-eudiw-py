###############################################################################
# Copyright (c) 2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import json
from pathlib import Path

from app.core.constants import IMAGE_ATTRIBUTES

CREDENTIALS_DIR = Path(__file__).resolve().parent.parent / "app" / "metadata_config" / "credentials_supported"


def _jpeg_claims(node):
    if isinstance(node, dict):
        if node.get("value_type") == "jpeg":
            yield node["path"][-1]
        for value in node.values():
            yield from _jpeg_claims(value)
    elif isinstance(node, list):
        for value in node:
            yield from _jpeg_claims(value)


def test_every_jpeg_claim_is_an_image_attribute():
    """The consent page shows, and mdoc issuance embeds, only listed images."""
    claims = {
        (path.name, name)
        for path in CREDENTIALS_DIR.glob("*.json")
        for name in _jpeg_claims(json.loads(path.read_text(encoding="utf-8")))
    }
    assert claims
    assert {(file, name) for file, name in claims if name not in IMAGE_ATTRIBUTES} == set()
