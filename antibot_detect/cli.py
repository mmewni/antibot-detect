"""Command-line interface for antibot-detect.

Usage:
    antibot-detect <url> [--json] [--all] [--timeout SECS] [--verbose]
"""
from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from antibot_detect import __version__
from antibot_detect.core import AnalysisResult, FetchError, analyze
from antibot_detect.detectors.base import Confidence
from antibot_detect.fetcher import DEFAULT_TIMEOUT

_err = Console(stderr=True)

_CONFIDENCE_STYLE = {
    Confidence.HIGH: "bold green",
    Confidence.MEDIUM: "yellow",
    Confidence.LOW: "dim",
}


def _confidence_text(confidence: Confidence) -> Text:
    return Text(confidence.value, style=_CONFIDENCE_STYLE.get(confidence, ""))


def _render_verbose(console: Console, result: AnalysisResult) -> None:
    fetch = result.fetch
    lines = [
        f"[bold]Requested:[/bold] {fetch.requestedUrl}",
        f"[bold]Final URL:[/bold] {fetch.finalUrl}",
        f"[bold]Status:[/bold]    {fetch.status}",
        f"[bold]Body size:[/bold] {len(fetch.body):,} chars",
    ]

    if fetch.redirectChain:
        lines.append("")
        lines.append("[bold]Redirect chain:[/bold]")
        for hop in fetch.redirectChain:
            lines.append(f"  {hop.status} -> {hop.url}")
        lines.append(f"  {fetch.status} -> {fetch.finalUrl}")

    interesting = [
        "server",
        "cf-ray",
        "cf-cache-status",
        "x-iinfo",
        "x-cdn",
        "via",
        "set-cookie",
    ]
    sampled = [(name, fetch.header(name)) for name in interesting]
    sampled = [(n, v) for n, v in sampled if v]
    if sampled:
        lines.append("")
        lines.append("[bold]Sampled headers:[/bold]")
        for name, value in sampled:
            shown = value if len(value) <= 100 else value[:99] + "…"
            lines.append(f"  {name}: {shown}")

    cookies = list(fetch.all_cookies())
    if cookies:
        lines.append("")
        lines.append(f"[bold]Cookies:[/bold] {', '.join(cookies)}")

    console.print(Panel("\n".join(lines), title="Fetch details", border_style="cyan"))


def _render_table(console: Console, result: AnalysisResult, showAll: bool) -> None:
    if result.detections:
        table = Table(
            title="Detected bot-management / anti-bot solutions",
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("Solution", style="bold", no_wrap=True)
        table.add_column("Confidence", no_wrap=True)
        table.add_column("Evidence")

        for d in result.detections:
            table.add_row(
                d.name,
                _confidence_text(d.confidence),
                "\n".join(d.evidence) or "—",
            )
        console.print(table)
    else:
        console.print(
            Panel(
                "No known anti-bot / bot-management solution detected via passive "
                "fingerprinting.\n[dim]Note: a negative result is not proof of "
                "absence — JS-only defenses may not be visible without rendering.[/dim]",
                title="Result",
                border_style="yellow",
            )
        )

    if showAll and result.notDetected:
        console.print(
            "\n[dim]Not detected:[/dim] " + ", ".join(result.notDetected)
        )


def _emit_json(result: AnalysisResult, showAll: bool) -> None:
    payload = result.to_dict(includeAll=showAll)
    payload["tool"] = "antibot-detect"
    payload["version"] = __version__
    click.echo(json.dumps(payload, indent=2))


@click.command(
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.argument("url")
@click.option("--json", "asJson", is_flag=True, help="Output machine-readable JSON.")
@click.option(
    "--all",
    "showAll",
    is_flag=True,
    help="Also list detectors that did not match.",
)
@click.option(
    "--timeout",
    type=int,
    default=DEFAULT_TIMEOUT,
    show_default=True,
    metavar="SECS",
    help="Request timeout in seconds.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Show fetch details (status, redirect chain, sampled headers).",
)
@click.version_option(__version__, "-V", "--version", prog_name="antibot-detect")
def main(
    url: str,
    asJson: bool,
    showAll: bool,
    timeout: int,
    verbose: bool,
) -> None:
    """Identify which anti-bot / bot-management solution a website uses.

    Detection only — this tool never attempts to bypass any protection.
    """
    console = Console()

    try:
        result = analyze(url, timeout=timeout)
    except FetchError as exc:
        if asJson:
            click.echo(json.dumps({"error": str(exc)}, indent=2))
        else:
            _err.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)
    except KeyboardInterrupt:
        _err.print("[yellow]Interrupted.[/yellow]")
        sys.exit(130)

    if asJson:
        _emit_json(result, showAll)
        return

    if verbose:
        _render_verbose(console, result)
    _render_table(console, result, showAll)


if __name__ == "__main__":
    main()
