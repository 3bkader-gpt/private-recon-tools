"""
HackerOne Program Classifier
============================
Classifies HackerOne embedded submission and policy endpoints.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Optional

from core.models import Classification

RESPONSE_PCT_RE = re.compile(r"(\d+)\s*%\s*", flags=re.IGNORECASE)

CLOSED_SIGNAL_PATTERNS: tuple[str, ...] = (
    "program not live",
    "this program is not open to submissions yet",
    "program closed",
    "not accepting submissions",
    "is not accepting submissions",
    "archived",
    "this program is no longer accepting",
    "this program is currently not accepting",
    "has been deactivated",
    "no longer accepting",
    "submissions are paused",
)


def classify_h1_text(url: str, text: str, min_response_pct: int = 100) -> Classification:
    collapsed = re.sub(r"\s+", " ", text).strip()
    low = collapsed.lower()

    if "error 1015" in low or "you are being rate limited" in low:
        return Classification(
            url=url,
            status="error",
            reason_code="rate_limited",
            reason="Cloudflare Rate Limited (Error 1015)",
            platform="hackerone",
        )

    # Response standards check (e.g. 80% of reports meet response standards)
    match = RESPONSE_PCT_RE.search(collapsed)
    pct_val: Optional[int] = None
    if match:
        try:
            pct_val = int(match.group(1))
            if pct_val < min_response_pct:
                return Classification(
                    url=url,
                    status="dead",
                    reason_code="low_response_standards",
                    reason=f"Low response standards: {pct_val}% (<{min_response_pct}%)",
                    platform="hackerone",
                    response_pct=pct_val,
                )
        except Exception:
            pass

    for pattern in CLOSED_SIGNAL_PATTERNS:
        if pattern in low:
            return Classification(
                url=url,
                status="dead",
                reason_code="closed_signal",
                reason=f"Closed signal detected: '{pattern}'",
                platform="hackerone",
                response_pct=pct_val,
            )

    return Classification(
        url=url,
        status="active",
        reason_code="needs_scope_validation",
        reason="No dead signal on main page",
        platform="hackerone",
        response_pct=pct_val,
    )


async def wait_for_react_stable(page, timeout_ms: int = 6000, extra_wait_ms: int = 600) -> None:
    table_or_empty = ".daisy-table, .daisy-table-empty, table, text=/no assets in scope|no results found|matching assets/i"
    loading_like = ".loading, [aria-busy='true'], .skeleton, .spinner, .is-loading"
    try:
        await page.wait_for_selector(table_or_empty, timeout=timeout_ms)
    except Exception:
        await page.wait_for_timeout(min(extra_wait_ms, 1000))

    try:
        if await page.locator(loading_like).count() > 0:
            await page.wait_for_selector(loading_like, state="detached", timeout=min(timeout_ms, 3000))
    except Exception:
        pass

    await page.wait_for_timeout(extra_wait_ms)


def build_scopes_url(security_page_link: str) -> str:
    base = security_page_link.rstrip("/")
    if base.startswith("/"):
        base = f"https://hackerone.com{base}"
    return f"{base}/policy_scopes?bounty_eligibility=eligible&type=team"


async def apply_eligible_bounty_filter(page, timeout_ms: int = 5000, retries: int = 2) -> tuple[bool, str]:
    last_reason = "unknown_filter_failure"
    dropdown_locators = (
        "[data-testid='spec-asset-filter-eligible-for-bounty']",
        "div:has([data-testid='field-label'] span:has-text('Bounty eligibility'))",
        "button:has-text('Bounty eligibility')",
        "[aria-label*='Bounty eligibility']",
        "button:has-text('Bounty')",
    )
    option_locators = (
        "[role='option']:has-text('Eligible for bounty')",
        "div:has-text('Eligible for bounty')",
        "text='Eligible for bounty'",
        "li:has-text('Eligible for bounty')",
    )
    verification_locators = (
        "[data-testid='spec-asset-filter-eligible-for-bounty']:has-text('Eligible for bounty')",
        ".css-1gu5kac-singleValue:has-text('Eligible for bounty')",
        "button:has-text('Eligible for bounty')",
        "text='Eligible for bounty'",
    )

    for _ in range(retries + 1):
        try:
            opened = False
            for locator in dropdown_locators:
                loc = page.locator(locator)
                if await loc.count() > 0:
                    await loc.first.click(timeout=timeout_ms)
                    opened = True
                    break
            if not opened:
                last_reason = "filter_dropdown_not_found"
                continue

            await page.wait_for_timeout(400)
            selected = False
            for locator in option_locators:
                loc = page.locator(locator)
                if await loc.count() > 0:
                    await loc.first.click(timeout=timeout_ms)
                    selected = True
                    break
            if not selected:
                last_reason = "filter_option_not_found"
                continue

            await wait_for_react_stable(page, timeout_ms=min(timeout_ms, 5000), extra_wait_ms=700)
            for locator in verification_locators:
                if await page.locator(locator).count() > 0:
                    return True, "filter_applied"

            last_reason = "filter_verification_failed"
        except Exception as exc:
            last_reason = f"filter_click_error:{type(exc).__name__}"

    return False, last_reason


def classify_scopes(url: str, scopes_text: str) -> Classification:
    lower_scopes = scopes_text.lower()
    dead_keywords = (
        "no assets in scope",
        "no results found",
        "no matching assets",
        "0 assets in scope",
        "0 matching assets",
    )
    for kw in dead_keywords:
        if kw in lower_scopes:
            return Classification(
                url=url,
                status="dead",
                reason_code="no_bounty_eligible_assets",
                reason="No bounty-eligible assets after UI filter",
                platform="hackerone",
                bounty_eligible=False,
            )
    return Classification(
        url=url,
        status="active",
        reason_code="eligible_assets_found",
        reason="Bounty-eligible assets found",
        platform="hackerone",
        bounty_eligible=True,
    )


async def classify_hackerone_url(
    context,
    url: str,
    timeout_ms: int = 25000,
    wait_ms: int = 1500,
    min_response_pct: int = 100,
    filter_ineligible: bool = True,
    artifacts_dir: Optional[Path] = None,
    max_retries: int = 2,
) -> Classification:
    for attempt in range(max_retries + 1):
        page = await context.new_page()
        try:
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            if wait_ms > 0:
                await page.wait_for_timeout(wait_ms)

            text = await page.inner_text("body")
            result = classify_h1_text(url, text, min_response_pct=min_response_pct)

            if result.reason_code == "rate_limited":
                if attempt < max_retries:
                    await page.close()
                    await asyncio.sleep(6.0 + attempt * 3.0)
                    continue

            if result.status == "active" and filter_ineligible:
                security_page_link = None
                try:
                    await page.wait_for_selector("text=Security Page", timeout=min(wait_ms + 2000, 5000))
                except Exception:
                    pass

                for selector in ["text=Security Page", "a:has-text('Security Page')", "a.daisy-link"]:
                    try:
                        loc = page.locator(selector)
                        if await loc.count() > 0:
                            security_page_link = await loc.first.get_attribute("href")
                            if security_page_link:
                                break
                    except Exception:
                        continue

                if security_page_link:
                    scopes_url = build_scopes_url(security_page_link)
                    await page.goto(scopes_url, timeout=timeout_ms, wait_until="domcontentloaded")
                    await wait_for_react_stable(page, timeout_ms=min(timeout_ms, 7000), extra_wait_ms=800)

                    filter_ok, filter_reason = await apply_eligible_bounty_filter(page, timeout_ms=5000, retries=2)
                    scopes_text = await page.inner_text("body")

                    if not filter_ok:
                        fallback = classify_scopes(url, scopes_text)
                        if fallback.status == "dead":
                            result = Classification(
                                url=url,
                                status="dead",
                                reason_code="no_bounty_eligible_assets_fallback",
                                reason=f"{fallback.reason} (fallback after {filter_reason})",
                                platform="hackerone",
                                bounty_eligible=False,
                            )
                        else:
                            if artifacts_dir:
                                safe_name = re.sub(r"[^a-zA-Z0-9]+", "_", url)[:80]
                                try:
                                    await page.screenshot(path=str(artifacts_dir / f"{safe_name}_failed.png"), full_page=True)
                                except Exception:
                                    pass
                            result = Classification(
                                url=url,
                                status="dead",
                                reason_code="scope_filter_unverified_treated_dead",
                                reason=f"Filter verification failed ({filter_reason}); conservatively classified as dead",
                                platform="hackerone",
                                bounty_eligible=False,
                            )
                    else:
                        result = classify_scopes(url, scopes_text)
                else:
                    return Classification(
                        url=url,
                        status="error",
                        reason_code="security_page_missing",
                        reason="Security Page link not found on embedded submission page",
                        platform="hackerone",
                    )

            return result
        except Exception as exc:
            if attempt < max_retries and ("rate" in str(exc).lower() or "timeout" in str(exc).lower()):
                await asyncio.sleep(4.0)
                continue
            return Classification(
                url=url,
                status="error",
                reason_code="fetch_failed",
                reason=f"{type(exc).__name__}: {str(exc)}",
                platform="hackerone",
            )
        finally:
            try:
                await page.close()
            except Exception:
                pass
