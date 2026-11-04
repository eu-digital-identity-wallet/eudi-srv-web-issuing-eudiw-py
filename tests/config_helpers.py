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
"""Test helpers to override the issuer configuration in every app module.

Each module does ``from app.core.config import CONFIGURATION``, so a test
that needs a specific configuration must rebind the name in all of them.
"""

from __future__ import annotations

import contextlib
import importlib
import pkgutil
from functools import lru_cache
from types import ModuleType
from typing import Any, Iterator, Tuple
from unittest.mock import patch

import app


@lru_cache(maxsize=1)
def configuration_modules() -> Tuple[ModuleType, ...]:
    """Returns every ``app`` module that has a ``CONFIGURATION`` attribute.

    Returns:
        The modules (imported once and cached).
    """
    modules = [importlib.import_module(m.name) for m in pkgutil.walk_packages(app.__path__, "app.")]
    return tuple(m for m in modules if hasattr(m, "CONFIGURATION"))


@contextlib.contextmanager
def patch_configuration(config: Any) -> Iterator[Any]:
    """Temporarily replaces ``CONFIGURATION`` in every app module.

    Usable as a context manager or as a decorator (no argument is injected).

    Args:
        config: Replacement configuration (dict or mock).

    Yields:
        ``config``.
    """
    with contextlib.ExitStack() as stack:
        for module in configuration_modules():
            stack.enter_context(patch.object(module, "CONFIGURATION", config))
        yield config


def set_configuration(monkeypatch: Any, config: Any) -> Any:
    """Replaces ``CONFIGURATION`` in every app module for the current test.

    Args:
        monkeypatch: pytest ``monkeypatch`` fixture.
        config: Replacement configuration.

    Returns:
        ``config``.
    """
    for module in configuration_modules():
        monkeypatch.setattr(module, "CONFIGURATION", config)
    return config
