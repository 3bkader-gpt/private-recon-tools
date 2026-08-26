"""
Bugcrowd Program Classifier
===========================
Classifies Bugcrowd external/embedded report submission endpoints.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Optional

from core.models import Classification

BUGCROWD_DEAD_PATTERNS = (
    "this engagement is not live",
    "the engagement must be in progress",
    "the requested page was not found",
    "page not found",
    "submissions are closed",
    "this program is no longer accepting",
    "program retired",
    "program is closed",
    "engagement completed",
    "access denied",
)

BUGCROWD_ACTIVE_SIGNALS = (
    "submission form",
    "select the vulnerable target",
    "submission title",
    "vulnerability details",
)


def classify_bugcrowd_text(url: str, text: str) -> Classification:
    low = text.lower()

    for pattern in BUGCROWD_DEAD_PATTERNS:
        if pattern in low:
            return Classification(
                url=url,
                status="dead",
                reason_code="bugcrowd_engagement_not_live" if "not live" in pattern else "bugcrowd_closed",
                reason=f"Bugcrowd dead signal: '{pattern}'",
                platform="bugcrowd",
            )

    has_active_signal = any(sig in low for sig in BUGCROWD_ACTIVE_SIGNALS)
    if has_active_signal:
        # Check if there is a domain whitelist warning vs actually active form
        whitelisted_only = "unknown domain. this domain must be whitelisted" in low or "missing referrer header" in low
        detail = "Active submission form (whitelisted domains only)" if whitelisted_only else "Active submission form"
        return Classification(
            url=url,
            status="active",
            reason_code="active_submission_form",
            reason=detail,
            platform="bugcrowd",
            bounty_eligible=True,
        )

    return Classification(
        url=url,
        status="dead",
        reason_code="no_submission_form",
        reason="No active submission form or targets detected",
        platform="bugcrowd",
    )


async def classify_bugcrowd_url(
    context,
    url: str,
    timeout_ms: int = 20000,
    wait_ms: int = 1500,
) -> Classification:
    page = await context.new_page()
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        if wait_ms > 0:
            await page.wait_for_timeout(wait_ms)
        text = await page.inner_text("body")
        return classify_bugcrowd_text(url, text)
    except Exception as exc:
        return Classification(
            url=url,
            status="error",
            reason_code="fetch_error",
            reason=f"{type(exc).__name__}: {str(exc)}",
            platform="bugcrowd",
        )
    finally:
        try:
            await page.close()
        except Exception:
            pass
