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
"""Date parsing and formatting helpers."""

from __future__ import annotations

import datetime

DATE_FORMAT = "%Y-%m-%d"


def parse_date(value: str) -> datetime.date:
    """Parses a ``YYYY-MM-DD`` date.

    Args:
        value: Date string.

    Returns:
        The parsed date.

    Raises:
        ValueError: If ``value`` is not in ``YYYY-MM-DD`` format.
    """
    return datetime.datetime.strptime(value, DATE_FORMAT).date()


def format_date(value: datetime.date) -> str:
    """Formats a date as ``YYYY-MM-DD``.

    Args:
        value: Date or datetime.

    Returns:
        The formatted string.
    """
    return value.strftime(DATE_FORMAT)


def date_to_timestamp(value: str) -> int:
    """Converts a ``YYYY-MM-DD`` string to a local-midnight epoch timestamp.

    Args:
        value: Date string.

    Returns:
        Seconds since the epoch.

    Raises:
        ValueError: If ``value`` is not in ``YYYY-MM-DD`` format.
    """
    return int(datetime.datetime.strptime(value, DATE_FORMAT).timestamp())


def calculate_age(date_of_birth: str) -> int:
    """Computes the age in whole years from a date of birth.

    Args:
        date_of_birth: Date of birth as ``YYYY-MM-DD``.

    Returns:
        The age today.

    Raises:
        ValueError: If ``date_of_birth`` is not in ``YYYY-MM-DD`` format.
    """
    birth_date = parse_date(date_of_birth)
    today = datetime.date.today()
    had_birthday = (today.month, today.day) >= (birth_date.month, birth_date.day)
    return today.year - birth_date.year - (0 if had_birthday else 1)


def to_rfc3339(value: str) -> str:
    """Converts a date to an RFC 3339 UTC midnight timestamp.

    Any time part (``...T...``) is discarded first, so the function is
    idempotent.

    Args:
        value: ``YYYY-MM-DD`` date, optionally followed by ``T<time>``.

    Returns:
        E.g. ``"2025-01-20T00:00:00Z"``.

    Raises:
        ValueError: If the date part is not in ``YYYY-MM-DD`` format.
    """
    return parse_date(value.split("T")[0]).strftime("%Y-%m-%dT00:00:00Z")
