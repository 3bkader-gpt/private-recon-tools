"""
Bounty Target Filter & Classifier (Main CLI)
============================================
Unified tool to classify HackerOne & Bugcrowd private/embedded programs.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import random
import sys
from pathlib import Path
from typing import List

import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from core.bugcrowd import classify_bugcrowd_url
from core.discovery import discover_bugcrowd_urls, discover_hackerone_urls
from core.hackerone import classify_hackerone_url
from core.models import Classification

console = Console(legacy_windows=False, force_terminal=True)



def banner():
    console.print(
        Panel.fit(
            "[bold cyan]🎯 Bug Bounty Target Classifier & Filter[/bold cyan]\n"
            "[dim]Automated validation for HackerOne & Bugcrowd Embedded Programs[/dim]\n"
            "[yellow]Version: 2.0.0 (Modernized)[/yellow]",
            border_style="cyan",
        )
    )


def load_urls(path: Path) -> List[str]:
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {path}")
        return []
    raw = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip().replace("\ufeff", "") for ln in raw if ln.strip() and not ln.startswith("#")]


def save_results(out_dir: Path, prefix: str, results: List[Classification]):
    out_dir.mkdir(parents=True, exist_ok=True)
    active = [r.url for r in results if r.status == "active"]
    dead = [r.url for r in results if r.status == "dead"]
    error = [r.url for r in results if r.status == "error"]

    (out_dir / f"{prefix}_active.txt").write_text("\n".join(active), encoding="utf-8")
    (out_dir / f"{prefix}_dead.txt").write_text("\n".join(dead), encoding="utf-8")
    (out_dir / f"{prefix}_errors.txt").write_text("\n".join(error), encoding="utf-8")

    csv_path = out_dir / f"{prefix}_classified.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "platform", "status", "reason_code", "reason", "response_pct", "bounty_eligible"])
        for r in results:
            writer.writerow([r.url, r.platform, r.status, r.reason_code, r.reason, r.response_pct or "", r.bounty_eligible if r.bounty_eligible is not None else ""])

    # Render summary table
    table = Table(title=f"Results Summary: {prefix.upper()}", border_style="green")
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")

    total = len(results)
    table.add_row("[green]Active (Eligible)[/green]", str(len(active)), f"{(len(active)/total*100):.1f}%" if total else "0%")
    table.add_row("[red]Dead / Inactive[/red]", str(len(dead)), f"{(len(dead)/total*100):.1f}%" if total else "0%")
    table.add_row("[yellow]Errors / Blocked[/yellow]", str(len(error)), f"{(len(error)/total*100):.1f}%" if total else "0%")
    table.add_row("[bold]Total[/bold]", str(total), "100%")

    console.print(table)
    console.print(f"[dim]Outputs saved in: [cyan]{out_dir.resolve()}[/cyan][/dim]\n")


async def run_pipeline(
    urls: List[str],
    platform: str,
    concurrency: int = 3,
    min_response_pct: int = 100,
    timeout: int = 25,
    artifacts_dir: Path = Path("artifacts"),
) -> List[Classification]:
    from playwright.async_api import async_playwright

    results: List[Classification | None] = [None] * len(urls)
    semaphore = asyncio.Semaphore(concurrency)
    timeout_ms = timeout * 1000

    async with async_playwright() as p:
        console.print("[dim]Launching headless browser context...[/dim]")
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            extra_http_headers={"Referer": "https://bugcrowd.com/"} if platform == "bugcrowd" else {},
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {platform} targets...", total=len(urls))

            async def worker(idx: int, url: str):
                async with semaphore:
                    try:
                        if platform == "bugcrowd" or "bugcrowd.com" in url:
                            res = await classify_bugcrowd_url(context, url, timeout_ms=timeout_ms)
                        else:
                            res = await classify_hackerone_url(
                                context,
                                url,
                                timeout_ms=timeout_ms,
                                min_response_pct=min_response_pct,
                                artifacts_dir=artifacts_dir,
                            )
                        results[idx] = res
                    except Exception as e:
                        results[idx] = Classification(
                            url=url,
                            status="error",
                            reason_code="unhandled_exception",
                            reason=str(e),
                            platform=platform,
                        )
                    finally:
                        progress.update(task, advance=1)
                        # Small pacing
                        await asyncio.sleep(random.uniform(0.3, 0.7))

            tasks = [asyncio.create_task(worker(i, u)) for i, u in enumerate(urls)]
            await asyncio.gather(*tasks, return_exceptions=True)

        await context.close()
        await browser.close()

    return [r if r else Classification(urls[i], "error", "cancelled", "Processing cancelled", platform=platform) for i, r in enumerate(results)]


def main():
    banner()
    parser = argparse.ArgumentParser(description="Bug Bounty Target Classifier & Filter CLI")
    parser.add_argument("--platform", "-p", choices=["hackerone", "bugcrowd", "all"], default="hackerone", help="Target platform (default: hackerone)")
    parser.add_argument("--input", "-i", type=Path, help="Custom input text file with URLs")
    parser.add_argument("--output-dir", "-o", type=Path, default=Path("."), help="Output directory")
    parser.add_argument("--concurrency", "-c", type=int, default=3, help="Concurrent workers")
    parser.add_argument("--sample", "-s", type=int, default=0, help="Run on first N targets only")
    parser.add_argument("--min-response-pct", type=int, default=100, help="Minimum response percentage for HackerOne (default: 100)")
    parser.add_argument("--discover", action="store_true", help="Discover new URLs from web archives")

    args = parser.parse_args()

    if args.discover:
        console.print("[bold yellow]Running URL discovery from archives...[/bold yellow]")
        if args.platform in ("hackerone", "all"):
            h1_urls = discover_hackerone_urls()
            h1_path = args.output_dir / "hackerone_discovered.txt"
            h1_path.write_text("\n".join(h1_urls), encoding="utf-8")
            console.print(f"[green]Discovered {len(h1_urls)} HackerOne URLs -> {h1_path}[/green]")
        if args.platform in ("bugcrowd", "all"):
            bc_urls = discover_bugcrowd_urls()
            bc_path = args.output_dir / "bugcrowd_discovered.txt"
            bc_path.write_text("\n".join(bc_urls), encoding="utf-8")
            console.print(f"[green]Discovered {len(bc_urls)} Bugcrowd URLs -> {bc_path}[/green]")
        return

    platforms_to_run = ["hackerone", "bugcrowd"] if args.platform == "all" else [args.platform]

    for plat in platforms_to_run:
        default_file = Path(f"{plat}_urls.txt")
        input_file = args.input if args.input else default_file
        urls = load_urls(input_file)
        if not urls:
            console.print(f"[yellow]No URLs found for {plat}. Skipping.[/yellow]")
            continue

        if args.sample > 0:
            urls = urls[: args.sample]

        console.print(f"\n[bold]Starting Scan: [cyan]{plat.upper()}[/cyan] ({len(urls)} URLs)[/bold]")
        console.print(f"[dim]Concurrency: {args.concurrency} | Min Response: {args.min_response_pct}%[/dim]\n")

        results = asyncio.run(
            run_pipeline(
                urls=urls,
                platform=plat,
                concurrency=args.concurrency,
                min_response_pct=args.min_response_pct,
                artifacts_dir=args.output_dir / "artifacts",
            )
        )

        save_results(args.output_dir, plat, results)


if __name__ == "__main__":
    main()
