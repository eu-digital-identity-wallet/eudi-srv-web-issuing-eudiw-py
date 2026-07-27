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
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.nightly_status_sweep import run_sweep

logger = logging.getLogger(__name__)

_scheduler = None


def start_scheduler():
    """
    Starts the nightly sweep scheduler inside this Flask process.
    Safe to call once at app startup for a single-process deployment.
    """
    global _scheduler

    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        run_sweep,
        trigger=CronTrigger(hour=2, minute=00),
        id="nightly_status_sweep",
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info("Nightly sweep scheduler started (runs daily at 2:00am).")
