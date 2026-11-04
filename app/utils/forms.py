# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
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
"""Helpers for reading HTML form submissions."""

from __future__ import annotations

from typing import Any, Dict

from werkzeug.datastructures import MultiDict


def parse_form(form: MultiDict) -> Dict[str, Any]:
    """Flattens a submitted form, collecting ``field[]`` keys as lists.

    Args:
        form: ``request.form``.

    Returns:
        ``{name: value}`` where ``name[]`` keys become ``name: [values]``.
    """
    return {
        (key.replace("[]", "") if key.endswith("[]") else key): (
            form.getlist(key) if key.endswith("[]") else form.get(key)
        )
        for key in form.keys()
    }
