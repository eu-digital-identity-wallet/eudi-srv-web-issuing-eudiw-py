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
"""Tests for the log injection defences of the logging setup."""

import logging
import sys

from app.core.logging_setup import LineBreakEscapeFilter, SafeTracebackFormatter

FORMAT = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"


def _record(msg, exc=None):
    exc_info = None
    if exc is not None:
        try:
            raise exc
        except type(exc):
            exc_info = sys.exc_info()
    return logging.LogRecord("t", logging.ERROR, __file__, 1, msg, None, exc_info)


def test_traceback_lines_cannot_forge_a_record():
    forged = "2026-01-01 00:00:00,000 | app | INFO | forged"
    record = _record("failed", ValueError(f"bad\n{forged}\r{forged}"))
    LineBreakEscapeFilter().filter(record)

    lines = SafeTracebackFormatter(FORMAT).format(record).split("\n")

    assert lines[0].endswith("| ERROR | failed")
    assert all(line.startswith("    | ") for line in lines[1:])
    assert any(line == f"    | {forged}" for line in lines)
    assert "\r" not in "\n".join(lines)


def test_message_without_exception_unchanged():
    assert SafeTracebackFormatter("%(message)s").format(_record("plain")) == "plain"
