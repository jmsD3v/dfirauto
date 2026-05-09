"""
DFIR-Auto CLI

Commands:
  dfirauto triage       -- run full triage on live system
  dfirauto analyze      -- analyze previously saved triage JSON
  dfirauto report       -- generate HTML/PDF report from triage JSON
  dfirauto collect      -- run a specific collector only
  dfirauto demo         -- run triage on synthetic evidence

Usage:
  dfirauto triage --no-ai --output triage.json
  dfirauto triage --evtx Security.evtx --output report.html --format html
  dfirauto collect process
  dfirauto collect network
  dfirauto collect filesystem
  dfirauto collect persistence
  dfirauto report triage.json --output report.html
  dfirauto demo
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

app = typer.Typer(
    name="dfirauto",
    help="F-01 DFIR-Auto — automated forensic triage with AI incident reconstruction.",
    add_completion=False,
)
console = Console()


def _banner() -> None:
    console.print(Panel(
        "[bold red]DFIR-Auto[/bold red]  [bright_black]v0.1.0 — Automated Forensic Triage[/bright_black]\n"
        "[bright_black]F-01 — Forensic portfolio project | Process + Network + Files + Persistence + EVTX[/bright_black]",
        border_style="bright_black", padding=(0, 2),
    ))


def _print_report(report) -> None:
    s = report.summary
    console.print(
        f"\n[bold]Triage complete:[/bold] "
        f"[red]{s['critical']} critical[/red]  "
        f"[dark_orange]{s['high']} high[/dark_orange]  "
        f"[yellow]{s['medium']} medium[/yellow]  "
        f"[bright_black]{s['total_artifacts']} total artifacts[/bright_black]  "
        f"({report.duration_seconds:.1f}s)\n"
    )

    artifacts = report.sorted_artifacts()
    if not artifacts:
        console.print("[yellow]No notable artifacts found.[/yellow]")
        return

    table = Table(title=f"Artifacts — {len(artifacts)} total", show_header=True, header_style="bold")
    table.add_column("Sev", width=9)
    table.add_column("Type", width=16)
    table.add_column("Collector", width=12)
    table.add_column("Name", width=30)
    table.add_column("Description")

    for a in artifacts[:30]:
        c = a.severity.color
        table.add_row(
            f"[{c}]{a.severity.value.upper()}[/{c}]",
            a.artifact_type.value,
            a.collector,
            a.name[:30],
            a.description[:60],
        )
    console.print(table)

    if report.ai_narrative:
        console.print()
        console.print(Panel(
            report.ai_narrative,
            title="[purple]AI Incident Narrative[/purple]",
            border_style="purple",
        ))
        if report.recommendations:
            console.print("\n[bold]Recommendations:[/bold]")
            for rec in report.recommendations:
                console.print(f"  [cyan]->[/cyan] {rec}")


@app.command()
def triage(
    evtx: Optional[Path] = typer.Option(None, "--evtx", help="Path to .evtx file or directory"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    fmt: str = typer.Option("json", "--format", "-f", help="json|html|pdf"),
    max_files: int = typer.Option(300, "--max-files", help="Max files to scan in temp dirs"),
) -> None:
    """Run full forensic triage on this system."""
    _banner()
    console.print("[cyan]Starting triage...[/cyan]\n")

    from dfirauto.core.triage import run_triage

    report = asyncio.run(run_triage(
        evtx_path=evtx,
        use_ai=not no_ai,
        max_files=max_files,
    ))

    _print_report(report)
    _save_output(report, output, fmt)


@app.command()
def collect(
    collector_name: str = typer.Argument(..., help="process|network|filesystem|persistence|evtx"),
    evtx: Optional[Path] = typer.Option(None, "--evtx"),
    no_ai: bool = typer.Option(True, "--no-ai"),
) -> None:
    """Run a single collector and show results."""
    _banner()

    collectors_map = {
        "process": lambda: __import__("dfirauto.collectors.process_collector", fromlist=["ProcessCollector"]).ProcessCollector(),
        "network": lambda: __import__("dfirauto.collectors.network_collector", fromlist=["NetworkCollector"]).NetworkCollector(),
        "filesystem": lambda: __import__("dfirauto.collectors.filesystem_collector", fromlist=["FilesystemCollector"]).FilesystemCollector(),
        "persistence": lambda: __import__("dfirauto.collectors.persistence_collector", fromlist=["PersistenceCollector"]).PersistenceCollector(),
        "evtx": lambda: __import__("dfirauto.collectors.evtx_collector", fromlist=["EvtxCollector"]).EvtxCollector(evtx_path=evtx),
    }

    if collector_name not in collectors_map:
        console.print(f"[red]Unknown collector. Choose: {', '.join(collectors_map.keys())}[/red]")
        raise typer.Exit(1)

    collector = collectors_map[collector_name]()
    console.print(f"[cyan]Running {collector_name} collector...[/cyan]")

    result = asyncio.run(collector.collect())

    console.print(f"\n[bold]Status:[/bold] {result.status.value}")
    console.print(f"[bold]Duration:[/bold] {result.duration_seconds:.2f}s")
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    if result.artifacts:
        table = Table(title=f"{collector_name} artifacts ({len(result.artifacts)})",
                      show_header=True, header_style="bold")
        table.add_column("Sev", width=9)
        table.add_column("Name", width=30)
        table.add_column("Description")
        for a in sorted(result.artifacts, key=lambda x: x.severity.weight, reverse=True):
            c = a.severity.color
            table.add_row(
                f"[{c}]{a.severity.value.upper()}[/{c}]",
                a.name[:30],
                a.description[:70],
            )
        console.print(table)
    else:
        console.print("[yellow]No artifacts found.[/yellow]")


@app.command()
def report(
    triage_json: Path = typer.Argument(..., help="Path to triage JSON output"),
    output: Path = typer.Option(Path("dfirauto-report.html"), "--output", "-o"),
    fmt: str = typer.Option("html", "--format", "-f"),
) -> None:
    """Generate HTML/PDF report from saved triage JSON."""
    _banner()

    if not triage_json.exists():
        console.print(f"[red]File not found: {triage_json}[/red]")
        raise typer.Exit(1)

    raw = json.loads(triage_json.read_text(encoding="utf-8"))
    # Build minimal TriageReport from JSON for report generation
    from dfirauto.types.artifacts import TriageReport, ForensicArtifact, ArtifactType, Severity
    from datetime import datetime, timezone

    rpt = TriageReport(
        case_id=raw.get("case_id", "?"),
        hostname=raw.get("hostname", "?"),
        ai_narrative=raw.get("ai_narrative", ""),
        ai_ioc_summary=raw.get("ai_ioc_summary", ""),
        recommendations=raw.get("recommendations", []),
    )
    try:
        rpt.started_at = datetime.fromisoformat(raw.get("started_at", ""))
    except Exception:
        pass

    from dfirauto.report.generator import generate_html, generate_pdf
    if fmt == "pdf":
        out = generate_pdf(rpt, raw, output.with_suffix(".pdf"))
    else:
        out = generate_html(rpt, raw, output.with_suffix(".html"))
    console.print(f"\n[green]Report saved -> {out}[/green]")


@app.command()
def demo(
    no_ai: bool = typer.Option(False, "--no-ai"),
    output: Optional[Path] = typer.Option(Path("dfirauto-demo-report.html"), "--output", "-o"),
) -> None:
    """Run live triage (process + network + filesystem + persistence) and show results."""
    _banner()
    console.print("[cyan]Running live triage demo (no EVTX on demo mode)...[/cyan]\n")

    from dfirauto.core.triage import run_triage

    report = asyncio.run(run_triage(use_ai=not no_ai, max_files=100))
    _print_report(report)

    if output:
        _save_output(report, output, "html")


def _save_output(report, output: Optional[Path], fmt: str) -> None:
    if not output:
        return
    if fmt == "json":
        output.with_suffix(".json").write_text(
            json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8"
        )
        console.print(f"\n[green]JSON saved -> {output.with_suffix('.json')}[/green]")
    else:
        from dfirauto.report.generator import generate_html, generate_pdf
        raw = report.to_dict()
        if fmt == "pdf":
            out = generate_pdf(report, raw, output.with_suffix(".pdf"))
        else:
            out = generate_html(report, raw, output.with_suffix(".html"))
        console.print(f"\n[green]Report saved -> {out}[/green]")


if __name__ == "__main__":
    app()
