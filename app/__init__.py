# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
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
"""EUDIW PID Issuer package.

Layout:
    core/          Configuration, shared state, constants, logging, errors.
    routes/        Flask blueprints (HTTP layer only).
    services/      Business logic and clients of external services.
    repositories/  In-memory and Postgres persistence.
    utils/         Small, dependency-free helpers.

``create_app`` is the application factory (``FLASK_APP=app:create_app``).
"""

from app.factory import create_app

__all__ = ["create_app"]
