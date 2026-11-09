# coding: latin-1
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
"""In-process APScheduler running the nightly status sweep and the purge of
expired in-memory entries."""

from __future__ import annotations

import atexit
import logging
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import CONFIGURATION
from app.repositories.offer_store import purge_expired
from app.services.nightly_sweep import run_sweep

logger = logging.getLogger(__name__)

#: Minutes between two purges when ``expiry.cleanup_interval`` is not set.
DEFAULT_CLEANUP_INTERVAL = 60

_scheduler: Optional[BackgroundScheduler] = None


def start_scheduler() -> BackgroundScheduler:
    """Starts the background scheduler inside this Flask process.

    It runs the nightly status sweep at 2:00am and purges expired offers,
    revocation requests and sessions every ``expiry.cleanup_interval``
    minutes (default :data:`DEFAULT_CLEANUP_INTERVAL`).

    Safe to call once at start-up for a single-process deployment;
    subsequent calls return the already running scheduler.

    Returns:
        The running scheduler.
    """
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        run_sweep,
        trigger=CronTrigger(hour=2, minute=00),
        id="nightly_status_sweep",
        max_instances=1,
        coalesce=True,
    )
    cleanup_interval = CONFIGURATION["expiry"].get("cleanup_interval", DEFAULT_CLEANUP_INTERVAL)
    _scheduler.add_job(
        purge_expired,
        trigger=IntervalTrigger(minutes=cleanup_interval),
        id="purge_expired",
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    atexit.register(_scheduler.shutdown, wait=False)
    logger.info(
        f"Scheduler started (nightly sweep daily at 2:00am, purge of expired entries "
        f"every {cleanup_interval} min)."
    )
    return _scheduler
