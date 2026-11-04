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
"""Input validation helpers (request arguments and dates)."""

from __future__ import annotations

import logging
from typing import Iterable, List, Mapping, Tuple


from app.utils.dates import parse_date

logger = logging.getLogger(__name__)


def validate_mandatory_args(args: Mapping[str, object], mandlist: Iterable[str]) -> Tuple[bool, List[str]]:
    """Checks that every mandatory argument has a value.

    Args:
        args: Query / form / JSON arguments.
        mandlist: Names that must be present (not ``None``) in ``args``.

    Returns:
        ``(True, [])`` when all are present, otherwise ``(False, missing)``.
    """
    missing = [m for m in mandlist if args.get(m) is None]
    return (not missing, missing)


def validate_date_format(date: str) -> bool:
    """Checks that ``date`` is a ``YYYY-MM-DD`` string.

    Args:
        date: Candidate date.

    Returns:
        ``True`` if the format is valid.
    """
    try:
        parse_date(date)
        return True
    except ValueError:
        return False

