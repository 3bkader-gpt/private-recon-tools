import asyncio
import csv
import random
import re
from pathlib import Path
from typing import Optional, Tuple

from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

INPUT_PATH = Path(r"C:\Users\medoo\Desktop\PocketPaw\hackerone_urls.txt")
ACTIVE_PATH = Path(r"C:\Users\medoo\Desktop\PocketPaw\hackerone_active.txt")
DEAD_PATH = Path(r"C:\Users\medoo\Desktop\PocketPaw\hackerone_dead.txt")
CSV_PATH = Path(r"C:\Users\medoo\Desktop\PocketPaw\hackerone_classified.csv")

REASON_CODES = {
    "closed_signal",
    "low_response_standards",
    "scope_filter_unverified_treated_dead",
    "no_bounty_eligible_scope",
    "navigation_failed",
    "active",
}

GOTO_TIMEOUT = 12000
LOAD_TIMEOUT = 4000
CLICK_TIMEOUT = 3000
FILTER_REFRESH_WAIT_MS = 1500
PACING_MIN = 1.0
PACING_MAX = 1.0


def detect_closed_signal(text: str) -> Optional[str]:
    pats = [
        r"program\s+is\s+closed",
        r"not\s+accepting\s+reports",
        r"program\s+is\s+paused",
        r"program\s+paused",
        r"program\s+is\s+deactivated",
        r"no\s+longer\s+accepting\s+reports",
        r"submissions\s+are\s+closed",
    ]
    low = text.lower()
    for p in pats:
        if re.search(p, low):
            return f"Closed/paused signal detected: {p}"
    return None


def extract_response_standards(text: str) -> Optional[int]:
    for p in [
        r"response\s+standards[^\d]{0,40}(\d{1,3})\s*%",
        r"response\s+rate[^\d]{0,40}(\d{1,3})\s*%",
        r"response\s+efficiency[^\d]{0,40}(\d{1,3})\s*%",
    ]:
        m = re.search(p, text, flags=re.I)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
    return None


async def safe_click(locator, timeout=CLICK_TIMEOUT) -> bool:
    try:
        await locator.first.wait_for(state="visible", timeout=timeout)
        await locator.first.click(timeout=timeout)
        return True
    except Exception:
        return False


async def click_any(page, locators) -> bool:
    for loc in locators:
        if await safe_click(loc):
            return True
    return False


async def goto_with_retry(page, url: str) -> Tuple[bool, str]:
    last = ""
    for attempt in range(1, 4):
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=GOTO_TIMEOUT)
            try:
                await page.wait_for_load_state("networkidle", timeout=LOAD_TIMEOUT)
            except Exception:
                pass
            return True, "ok"
        except (PlaywrightTimeoutError, Exception) as e:
            last = f"attempt_{attempt}:{type(e).__name__}:{e}"
            if attempt < 3:
                await page.wait_for_timeout(800)
    return False, last or "goto_failed"


async def ensure_policy_area(page) -> bool:
    return await click_any(page, [
        page.get_by_role("link", name=re.compile(r"security\s+page|security\s+policy|program\s+policy|policy", re.I)),
        page.get_by_role("button", name=re.compile(r"security\s+page|security\s+policy|program\s+policy|policy", re.I)),
        page.locator("a,button", has_text=re.compile(r"security\s+page|security\s+policy|program\s+policy|policy", re.I)),
    ])


async def open_scope_view(page) -> bool:
    return await click_any(page, [
        page.get_by_role("tab", name=re.compile(r"in\s*scope|scopes?|policy\s+scopes?", re.I)),
        page.get_by_role("link", name=re.compile(r"in\s*scope|scopes?|policy\s+scopes?", re.I)),
        page.get_by_role("button", name=re.compile(r"in\s*scope|scopes?|policy\s+scopes?", re.I)),
        page.locator("a,button", has_text=re.compile(r"in\s*scope|scopes?|policy\s+scopes?", re.I)),
    ])


async def apply_bounty_filter(page) -> Tuple[bool, str]:
    opened = await click_any(page, [
        page.get_by_role("button", name=re.compile(r"bounty\s+eligibility", re.I)),
        page.get_by_role("combobox", name=re.compile(r"bounty\s+eligibility", re.I)),
        page.locator("button,div[role='button'],label", has_text=re.compile(r"bounty\s+eligibility", re.I)),
    ])
    if not opened:
        return False, "filter_dropdown_not_found"

    chosen = await click_any(page, [
        page.get_by_role("option", name=re.compile(r"eligible\s+for\s+bounty", re.I)),
        page.get_by_role("menuitemcheckbox", name=re.compile(r"eligible\s+for\s+bounty", re.I)),
        page.get_by_role("checkbox", name=re.compile(r"eligible\s+for\s+bounty", re.I)),
        page.locator("label,div,span,li,button", has_text=re.compile(r"eligible\s+for\s+bounty", re.I)),
    ])
    if not chosen:
        return False, "eligible_option_not_found"

    try:
        await page.wait_for_load_state("networkidle", timeout=LOAD_TIMEOUT)
    except Exception:
        pass
    await page.wait_for_timeout(FILTER_REFRESH_WAIT_MS)

    verify = [
        page.locator("[aria-label*='filter' i], .filters, .filter, .badge, .tag", has_text=re.compile(r"eligible\s+for\s+bounty", re.I)),
        page.get_by_text(re.compile(r"eligible\s+for\s+bounty", re.I)),
    ]
    for loc in verify:
        try:
            if await loc.first.is_visible(timeout=1200):
                return True, "verified"
        except Exception:
            pass

    return False, "filter_applied_but_unverified"


async def has_scope_rows(page) -> bool:
    body = (await page.locator("body").inner_text()).lower()
    for p in [r"no\s+results", r"no\s+assets", r"no\s+in-?scope", r"0\s+assets", r"no\s+bounty\s+eligible\s+assets"]:
        if re.search(p, body):
            return False

    for sel in ["table tbody tr", "[role='row']", ".scope-item", "[data-testid*='scope']"]:
        try:
            if await page.locator(sel).count() > 0:
                return True
        except Exception:
            pass
    return False


async def classify(page, url: str) -> Tuple[str, str, str]:
    ok, nav_detail = await goto_with_retry(page, url)
    if not ok:
        return "dead", "navigation_failed", f"Navigation failed after retries: {nav_detail}"

    text = await page.locator("body").inner_text()

    closed = detect_closed_signal(text)
    if closed:
        return "dead", "closed_signal", closed

    pct = extract_response_standards(text)
    if pct is not None and pct < 100:
        return "dead", "low_response_standards", f"Low response standards: {pct}% (<100%)"

    if not await ensure_policy_area(page):
        return "dead", "navigation_failed", "policy_area_not_found_click_failed"

    try:
        await page.wait_for_load_state("domcontentloaded", timeout=LOAD_TIMEOUT)
    except Exception:
        pass
    await page.wait_for_timeout(800)

    if not await open_scope_view(page):
        return "dead", "navigation_failed", "scope_view_not_found_click_failed"

    try:
        await page.wait_for_load_state("domcontentloaded", timeout=LOAD_TIMEOUT)
    except Exception:
        pass
    await page.wait_for_timeout(800)

    filt_ok, detail = await apply_bounty_filter(page)
    if not filt_ok:
        return "dead", "scope_filter_unverified_treated_dead", detail

    if not await has_scope_rows(page):
        return "dead", "no_bounty_eligible_scope", "No bounty-eligible assets remain after filter"

    return "active", "active", "UI-verified bounty filter + bounty-eligible scope exists"


async def main():
    urls = [u.strip() for u in INPUT_PATH.read_text(encoding="utf-8").splitlines() if u.strip()]

    # reset outputs
    ACTIVE_PATH.write_text("", encoding="utf-8")
    DEAD_PATH.write_text("", encoding="utf-8")
    with CSV_PATH.open("w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerow(["url", "status", "reason_code", "reason"])

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        for i, url in enumerate(urls, start=1):
            try:
                status, reason_code, reason = await classify(page, url)
            except Exception as e:
                status, reason_code, reason = "dead", "navigation_failed", f"Unhandled classify error: {type(e).__name__}: {e}"

            if reason_code not in REASON_CODES:
                reason_code = "navigation_failed"

            with CSV_PATH.open("a", encoding="utf-8", newline="") as f:
                csv.writer(f).writerow([url, status, reason_code, reason])

            target = ACTIVE_PATH if status == "active" else DEAD_PATH
            with target.open("a", encoding="utf-8") as f:
                f.write(url + "\n")

            print(f"[{i}/{len(urls)}] {status.upper()} | {reason_code} | {url}")
            if i < len(urls):
                await asyncio.sleep(random.uniform(PACING_MIN, PACING_MAX))

        await context.close()
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
