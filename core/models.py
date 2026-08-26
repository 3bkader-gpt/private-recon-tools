"""
Data models for bounty program classification.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProgramStatus = Literal["active", "dead", "error"]


@dataclass(slots=True)
class Classification:
    url: str
    status: ProgramStatus
    reason_code: str
    reason: str
    platform: str = "unknown"
    response_pct: int | None = None
    bounty_eligible: bool | None = None
    program_handle: str | None = None
