"""
filter_hackerone_dead.py
========================
Filter dead / inactive HackerOne programs from a list of URLs.

Filters:
  - "Program not live", "Program closed", etc.
  - "X% of reports meet response standards" (filters if < 100)
  - Cloudflare rate limits (Error 1015)

Usage:
  python filter_hackerone_dead.py --input hackerone_urls.txt
  python filter_hackerone_dead.py --input hackerone_urls.txt --min-response-pct 80
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import random
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# ──────────────────────────────────────────────────────────────────────────────
# Detection patterns
# ──────────────────────────────────────────────────────────────────────────────
RESPONSE_PCT_RE = re.compile(
    r"(\d+)\s*%\s*",
    flags=re.IGNORECASE,
)

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


@dataclass(slots=True)
class Classification:
    url: str
    status: str   # "active" | "dead" | "error"
    reason_code: str
    reason: str


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def load_urls(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip().replace("\ufeff", "") for ln in raw if ln.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.write_text("\n".join(lines), encoding="utf-8")


def write_csv(path: Path, rows: list[Classification]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "status", "reason_code", "reason"])
        for row in rows:
            writer.writerow([row.url, row.status, row.reason_code, row.reason])


# ──────────────────────────────────────────────────────────────────────────────
# Classification logic
# ──────────────────────────────────────────────────────────────────────────────
def classify_text(url: str, text: str, min_response_pct: int) -> Classification:
    collapsed = re.sub(r"\s+", " ", text).strip()
    low = collapsed.lower()

    # Cloudflare / Rate limit detection
    if "error 1015" in low or "you are being rate limited" in low:
        return Classification(url, "error", "rate_limited", "Cloudflare Rate Limited (Error 1015)")

    # Response standards check (e.g., "50% of reports meet response standards")
    match = RESPONSE_PCT_RE.search(collapsed)
    if match:
        pct = int(match.group(1))
        if pct < min_response_pct:
            return Classification(
                url,
                "dead",
                "low_response_standards",
                f"Low response standards: {pct}% (<{min_response_pct}%)",
            )

    for pattern in CLOSED_SIGNAL_PATTERNS:
        if pattern in low:
            return Classification(url, "dead", "closed_signal", pattern)

    return Classification(url, "active", "needs_scope_validation", "No dead signal on main page")


async def wait_for_react_stable(
    page,
    timeout_ms: int,
    extra_wait_ms: int = 600,
) -> None:
    """Wait for a stable post-hydration state before reading DOM text."""
    table_or_empty = ".daisy-table, .daisy-table-empty, text=/no assets in scope|no results found|matching assets/i"
    loading_like = ".loading, [aria-busy='true'], .skeleton, .spinner, .is-loading"
    try:
        await page.wait_for_selector(table_or_empty, timeout=timeout_ms)
    except Exception:
        # Fallback to a small delay when no guard selector is visible.
        await page.wait_for_timeout(min(extra_wait_ms, 1200))

    # If there are loading indicators, wait briefly for them to disappear.
    try:
        if await page.locator(loading_like).count() > 0:
            await page.wait_for_selector(loading_like, state="detached", timeout=min(timeout_ms, 3500))
    except Exception:
        pass

    await page.wait_for_timeout(extra_wait_ms)


def build_scopes_url(security_page_link: str) -> str:
    base = security_page_link.rstrip("/")
    if base.startswith("/"):
        base = f"https://hackerone.com{base}"
    return f"{base}/policy_scopes?bounty_eligibility=eligible&type=team"


async def apply_eligible_bounty_filter(page, timeout_ms: int, retries: int = 2) -> tuple[bool, str]:
    """Apply the bounty eligibility filter via real UI clicks and verify it stuck."""
    last_reason = "unknown_filter_failure"
    dropdown_locators = (
        "button:has-text('Bounty eligibility')",
        "[aria-label*='Bounty eligibility']",
        "button:has-text('Bounty')",
    )
    option_locators = (
        "text='Eligible for bounty'",
        "li:has-text('Eligible for bounty')",
        "[role='option']:has-text('Eligible for bounty')",
    )
    verification_locators = (
        "button:has-text('Eligible for bounty')",
        "text='Eligible for bounty'",
    )

    for _ in range(retries + 1):
        try:
            # Open dropdown
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

            # Select eligible option
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

            # Wait for React refresh and verify filter is now visible as selected.
            await wait_for_react_stable(page, timeout_ms=min(timeout_ms, 6000), extra_wait_ms=900)
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
            return Classification(url, "dead", "no_bounty_eligible_assets", "No bounty-eligible assets after UI filter")
    return Classification(url, "active", "eligible_assets_found", "Bounty-eligible assets found")


# ──────────────────────────────────────────────────────────────────────────────
# Core async engine
# ──────────────────────────────────────────────────────────────────────────────
async def fetch_and_classify(
    context,  # playwright BrowserContext
    url: str,
    timeout_ms: int,
    wait_ms: int,
    retries: int,
    min_delay: float,
    max_delay: float,
    min_response_pct: int,
    filter_ineligible: bool,
    artifacts_dir: Path,
) -> Classification:
    last_error = "unknown"
    for attempt in range(retries + 1):
        page = await context.new_page()
        try:
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            if wait_ms > 0:
                await page.wait_for_timeout(wait_ms)
            
            # Using body inner_text captures what user sees (React rendered)
            text = await page.inner_text("body")
            result = classify_text(url, text, min_response_pct)
            
            # Extra check: Ineligible scopes
            if result.status == "active" and filter_ineligible:
                try:
                    # Find link to Security Page
                    security_page_link = None
                    # Be patient on the initial page for the link to appear
                    try:
                        await page.wait_for_selector("text=Security Page", timeout=max(wait_ms, 5000))
                    except: pass

                    for selector in ["text=Security Page", "a:has-text('Security Page')", "a.daisy-link"]:
                        try:
                            loc = page.locator(selector)
                            if await loc.count() > 0:
                                security_page_link = await loc.first.get_attribute("href")
                                if security_page_link: break
                        except: continue
                    
                    # Navigation to policy scopes
                    if security_page_link:
                        scopes_url = build_scopes_url(security_page_link)
                        
                        await page.goto(scopes_url, timeout=timeout_ms, wait_until="domcontentloaded")
                        await wait_for_react_stable(page, timeout_ms=min(timeout_ms, 7000), extra_wait_ms=800)
                        
                        filter_ok, filter_reason = await apply_eligible_bounty_filter(page, timeout_ms=min(timeout_ms, 7000), retries=2)
                        scopes_text = await page.inner_text("body")
                        if not filter_ok:
                            # Fallback: if UI controls are missing, classify conservatively as dead
                            # unless we can strongly prove eligible assets are present.
                            fallback = classify_scopes(url, scopes_text)
                            if fallback.status == "dead":
                                result = Classification(
                                    url,
                                    "dead",
                                    "no_bounty_eligible_assets_fallback",
                                    f"{fallback.reason} (fallback after {filter_reason})",
                                )
                            else:
                                artifact_name = re.sub(r"[^a-zA-Z0-9]+", "_", url)[:80]
                                screenshot_path = artifacts_dir / f"{artifact_name}_filter_failed.png"
                                html_path = artifacts_dir / f"{artifact_name}_filter_failed.html"
                                try:
                                    await page.screenshot(path=str(screenshot_path), full_page=True)
                                except Exception:
                                    pass
                                try:
                                    html_path.write_text(await page.content(), encoding="utf-8")
                                except Exception:
                                    pass
                                result = Classification(
                                    url,
                                    "dead",
                                    "scope_filter_unverified_treated_dead",
                                    f"Filter verification failed ({filter_reason}); conservatively classified as dead",
                                )
                        else:
                            result = classify_scopes(url, scopes_text)
                    else:
                        return Classification(url, "error", "security_page_missing", "Security Page link not found")
                except:
                    return Classification(url, "error", "scope_validation_failed", "Failed during scope validation")

            await asyncio.sleep(random.uniform(min_delay, max_delay))
            return result
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if "Target page, context or browser has been closed" in str(exc):
                # Script is shutting down
                break
            if attempt < retries:
                await asyncio.sleep(random.uniform(min_delay, max_delay))
        finally:
            try:
                await page.close()
            except: pass

    return Classification(url, "error", "fetch_failed", last_error)


async def run_all(
    urls: list[str],
    timeout: int,
    wait_ms: int,
    retries: int,
    min_delay: float,
    max_delay: float,
    concurrency: int,
    min_response_pct: int,
    filter_ineligible: bool,
    artifacts_dir: Path,
) -> list[Classification]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        sys.exit("Playwright not installed.")

    timeout_ms = timeout * 1000
    results: list[Classification | None] = [None] * len(urls)
    total = len(urls)
    completed = 0
    semaphore = asyncio.Semaphore(concurrency)

    async with async_playwright() as p:
        print("Launching browser...", flush=True)
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        )
        print("Browser ready [ok]\n", flush=True)

        async def process(idx: int, url: str):
            nonlocal completed
            try:
                async with semaphore:
                    result = await fetch_and_classify(
                        context, url,
                        timeout_ms=timeout_ms,
                        wait_ms=wait_ms,
                        retries=retries,
                        min_delay=min_delay,
                        max_delay=max_delay,
                        min_response_pct=min_response_pct,
                        filter_ineligible=filter_ineligible,
                        artifacts_dir=artifacts_dir,
                    )
                    results[idx] = result
                    completed += 1
                    icon = {"active": "[ok]", "dead": "[dead]", "error": "[!]"}[result.status]
                    print(
                        f"[{completed}/{total}] {icon} {result.status.upper()} :: {url} :: {result.reason_code} :: {result.reason}",
                        flush=True,
                    )
            except asyncio.CancelledError:
                if results[idx] is None:
                    results[idx] = Classification(url, "error", "cancelled", "Cancelled")
                raise

        tasks = [asyncio.create_task(process(i, u)) for i, u in enumerate(urls)]
        try:
            await asyncio.gather(*tasks)
        except (asyncio.CancelledError, KeyboardInterrupt):
            print("\nStopping...", flush=True)
            for t in tasks: t.cancel()
        finally:
            await context.close()
            await browser.close()

    return [r if r else Classification(urls[i], "error", "incomplete", "Incomplete") for i, r in enumerate(results)]


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Filter dead HackerOne program URLs.")
    p.add_argument("--input", type=Path, default=Path("hackerone_urls.txt"))
    p.add_argument("--sample", type=int, default=0, help="First N URLs only.")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--min-delay", type=float, default=0.3)
    p.add_argument("--max-delay", type=float, default=0.8)
    p.add_argument("--wait-ms", type=int, default=2000)
    p.add_argument("--concurrency", type=int, default=3)
    p.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    p.add_argument(
        "--min-response-pct", type=int, default=100,
        help="Filter programs with response standards < this (default 100).",
    )
    p.add_argument(
        "--filter-ineligible", action="store_true", default=True,
        help="Check policy page and filter out programs with 0 bounty-eligible assets (default: True).",
    )
    p.add_argument(
        "--no-filter-ineligible", action="store_false", dest="filter_ineligible",
        help="Disable ineligible scope filtering.",
    )
    return p.parse_args()


def main() -> None:
    print("filter_hackerone_dead: starting...", flush=True)
    args = parse_args()

    urls = load_urls(args.input)
    if args.sample > 0:
        urls = urls[: args.sample]

    print(f"Loaded {len(urls)} URL(s) from {args.input.resolve()}", flush=True)
    print(
        f"timeout={args.timeout}s | concurrency={args.concurrency} "
        f"| filter-response-standards < {args.min_response_pct}%",
        flush=True,
    )
    artifacts_dir = args.input.parent / args.artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    try:
        results = asyncio.run(
            run_all(
                urls,
                timeout=args.timeout,
                wait_ms=args.wait_ms,
                retries=args.retries,
                min_delay=args.min_delay,
                max_delay=args.max_delay,
                concurrency=args.concurrency,
                min_response_pct=args.min_response_pct,
                filter_ineligible=args.filter_ineligible,
                artifacts_dir=artifacts_dir,
            )
        )
    except KeyboardInterrupt:
        print("\nInterrupted by user. Saving partial results…", flush=True)
        # Results lists are already handled by Incomplete status in run_all
        return

    out_dir = args.input.parent
    dead = [r.url for r in results if r.status == "dead"]
    active = [r.url for r in results if r.status == "active"]
    error = [r.url for r in results if r.status == "error"]

    write_lines(out_dir / "hackerone_dead.txt", dead)
    write_lines(out_dir / "hackerone_active.txt", active)
    write_lines(out_dir / "hackerone_errors.txt", error)
    write_csv(out_dir / "hackerone_classified.csv", results)

    print("\n---- Summary ----", flush=True)
    print(f"Total:  {len(results)}")
    print(f"Active: {len(active)}")
    print(f"Dead:   {len(dead)}")
    print(f"Error:  {len(error)}")
    print(f"\nOutputs saved to: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
