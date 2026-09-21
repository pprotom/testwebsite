#!/usr/bin/env python3
"""
website-security-auditor CLI Entry Point
เครื่องมือตรวจสอบความปลอดภัยเว็บไซต์อัตโนมัติ สำหรับ Linux
"""

import argparse
import os
import sys

# Ensure package directory is in sys.path so modules import reliably from anywhere
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

from auditor.config import ConfigError, load_config
from auditor.runner import AuditRunner


def print_banner():
    banner_text = """[bold cyan]
╔═══════════════════════════════════════════════════════════════════════╗
║                  WEBSITE SECURITY AUDITOR v1.0.0                      ║
║     Automated 5-Module Defensive Security Auditing Engine (Linux)    ║
║        Strict Empirical Verification & Non-Destructive Scanning       ║
╚═══════════════════════════════════════════════════════════════════════╝[/bold cyan]"""
    if HAS_RICH:
        console.print(banner_text)
    else:
        print("=================================================================")
        print("                 WEBSITE SECURITY AUDITOR v1.0.0                 ")
        print("=================================================================")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Website Security Auditor for Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--only",
        choices=["recon", "files", "weblayer", "infra", "supply"],
        help="Run only a single specific module",
    )
    parser.add_argument(
        "--rerun",
        action="store_true",
        help="Skip recon phase if previous results are fresh (< 24 hours old)",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Regenerate reports directly from existing evidence without rescanning",
    )
    parser.add_argument(
        "--compare",
        help="Path to a previous report-*.json to generate a comparative Delta Report",
    )
    parser.add_argument(
        "--allow-risky",
        action="append",
        default=[],
        help="Authorize execution of aggressive scanning tools (e.g. --allow-risky sqlmap)",
    )
    parser.add_argument(
        "--confirm-large-scan",
        action="store_true",
        help="Confirm scanning of > 1000 ports if configured",
    )

    args = parser.parse_args()

    print_banner()

    # โหลด configuration
    try:
        cfg = load_config(args.config)
    except ConfigError as ce:
        msg = f"[bold red]Configuration Error:[/bold red] {ce}"
        if HAS_RICH:
            console.print(msg)
        else:
            print(f"Configuration Error: {ce}")
        sys.exit(1)

    # อัปเดต CLI overrides
    if args.allow_risky:
        for r in args.allow_risky:
            if r.lower() not in cfg.allow_risky:
                cfg.allow_risky.append(r.lower())

    if args.confirm_large_scan:
        cfg.confirm_large_port_scan = True

    if HAS_RICH:
        console.print(f"[bold green]▶ Target:[/bold green] {cfg.url} ([cyan]{cfg.domain}[/cyan])")
        console.print(f"[bold green]▶ Scope:[/bold green] {', '.join(cfg.allowed_domains)}")
        console.print(f"[bold green]▶ Safe Mode:[/bold green] {'ENABLED' if cfg.safe_mode else 'DISABLED'}")
        if args.only:
            console.print(f"[bold yellow]▶ Module Filter:[/bold yellow] Only running '{args.only}'")
        if args.rerun:
            console.print("[bold yellow]▶ Rerun Mode:[/bold yellow] Re-using recon cache if < 24h")
        if args.report_only:
            console.print("[bold yellow]▶ Report Only Mode:[/bold yellow] Generating report from cache")
        console.print("")

    runner = AuditRunner(
        config=cfg,
        only_module=args.only,
        rerun_mode=args.rerun,
        report_only=args.report_only,
        compare_path=args.compare,
    )

    try:
        results = runner.execute()
    except Exception as e:
        if HAS_RICH:
            console.print(f"[bold red]Fatal Execution Error:[/bold red] {e}")
        else:
            print(f"Fatal Execution Error: {e}")
        sys.exit(2)

    report = results["report"]
    verdict = report.get("verdict", "UNKNOWN")
    coverage = report.get("coverage_pct", 0.0)
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    # แสดงผลทาง Terminal สวยงาม
    if HAS_RICH:
        verdict_color = "red" if verdict == "NOT PASS" else "green"
        console.print(Panel(
            f"[bold {verdict_color}]AUDIT VERDICT: {verdict}[/bold {verdict_color}]\n"
            f"Coverage Score: [bold cyan]{coverage:.1f}%[/bold cyan]\n"
            f"Summary: PASS: {summary.get('pass')} | FAIL: {summary.get('fail')} | UNKNOWN: {summary.get('unknown')}",
            title="[bold]Summary Assessment[/bold]",
            border_style=verdict_color,
        ))

        # ตาราง Findings
        if findings:
            f_table = Table(title="Security Findings", show_header=True, header_style="bold magenta")
            f_table.add_column("Severity", width=10)
            f_table.add_column("Title", width=40)
            f_table.add_column("Affected", width=25)
            f_table.add_column("Impact", width=35)

            for f in findings:
                sev = f.get("severity", "P2")
                s_style = "bold red" if sev == "P0" else ("bold yellow" if sev == "P1" else "cyan")
                f_table.add_row(
                    f"[{s_style}]{sev}[/{s_style}]",
                    f.get("title", ""),
                    f.get("affected", ""),
                    f.get("impact", "")[:60] + "...",
                )
            console.print(f_table)

        console.print(f"\n[bold green]✔ Saved Markdown Report:[/bold green] {results['md_path']}")
        console.print(f"[bold green]✔ Saved JSON Report:[/bold green]     {results['json_path']}")

        if results.get("delta_md_path"):
            console.print(f"[bold yellow]✔ Saved Delta Report:[/bold yellow]    {results['delta_md_path']}")

    else:
        print(f"\nAUDIT VERDICT: {verdict} (Coverage: {coverage:.1f}%)")
        print(f"Markdown Report: {results['md_path']}")
        print(f"JSON Report:     {results['json_path']}")
        if results.get("delta_md_path"):
            print(f"Delta Report:    {results['delta_md_path']}")

    # Exit code: 0 if PASS, 1 if NOT PASS
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
