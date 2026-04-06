"""Rich-powered terminal report generation.

Design highlights
-----------------
* ``Formatter`` is a ``typing.Protocol`` — any object with a ``render`` method
  satisfies it.  ``RichFormatter`` and ``JsonFormatter`` are two concrete
  implementations; callers can swap them via dependency injection.
* ``ReportBuilder`` uses the Builder pattern to assemble an ``AuditReport``
  incrementally: ``builder.with_entropy().with_breach().build()``.  This keeps
  optional report sections truly optional without parameter explosion.
* All Rich construction is data-driven (loops over dataclass fields and
  dictionaries) rather than a wall of hard-coded ``table.add_row(...)`` calls.
* ``make_progress()`` is a factory that returns a pre-configured Rich
  ``Progress`` widget; callers use it as a context manager without knowing its
  internals.
"""
from __future__ import annotations

import json
from dataclasses import asdict, fields
from typing import Protocol, runtime_checkable

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from pas.models import (
    AuditReport,
    BreachResult,
    CrackResult,
    ScoreResult,
    StrengthLabel,
)

__all__ = [
    "Formatter",
    "RichFormatter",
    "JsonFormatter",
    "print_crack_results",
    "print_score_result",
    "print_breach_results",
    "print_audit_report",
    "make_progress",
]

# ---------------------------------------------------------------------------
# Default console (module-level singleton; redirect for testing)
# ---------------------------------------------------------------------------

_CONSOLE = Console(legacy_windows=False)


def get_console() -> Console:
    """Return the module-level console.  Replace for testing or file output."""
    return _CONSOLE


# ---------------------------------------------------------------------------
# Strength colour mapping
# ---------------------------------------------------------------------------

_STRENGTH_STYLE: dict[StrengthLabel, str] = {
    StrengthLabel.VERY_WEAK:   "bold red",
    StrengthLabel.WEAK:        "red",
    StrengthLabel.FAIR:        "yellow",
    StrengthLabel.STRONG:      "green",
    StrengthLabel.VERY_STRONG: "bold green",
}


def _strength_text(label: StrengthLabel) -> Text:
    return Text(label.value, style=_STRENGTH_STYLE[label])


def _score_bar(score: int, width: int = 24) -> str:
    filled = int((score / 100) * width)
    return "█" * filled + "░" * (width - filled)


# ---------------------------------------------------------------------------
# Formatter Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class Formatter(Protocol):
    """Structural protocol for report renderers."""

    def render(self, report: AuditReport) -> None:
        """Render *report* to whatever output medium this formatter targets."""
        ...


# ---------------------------------------------------------------------------
# Rich formatter
# ---------------------------------------------------------------------------

class RichFormatter:
    """Renders an ``AuditReport`` as Rich tables and panels to the console."""

    def __init__(self, console: Console | None = None) -> None:
        self._con = console or get_console()

    def render(self, report: AuditReport) -> None:
        print_audit_report(report, console=self._con)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JsonFormatter:
    """Serialises an ``AuditReport`` to JSON (stdout or a file path)."""

    def __init__(self, path: str | None = None, indent: int = 2) -> None:
        self._path = path
        self._indent = indent

    def render(self, report: AuditReport) -> None:
        def _default(obj: object) -> object:
            if hasattr(obj, "value"):          # enum
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)             # type: ignore[arg-type]
            return str(obj)

        payload = json.dumps(asdict(report), default=_default, indent=self._indent)  # type: ignore[arg-type]
        if self._path:
            with open(self._path, "w", encoding="utf-8") as fh:
                fh.write(payload)
        else:
            print(payload)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class ReportBuilder:
    """Incrementally assemble an :class:`~pas.models.AuditReport`.

    Usage
    -----
    >>> report = (
    ...     ReportBuilder(total_hashes=100, elapsed=12.3)
    ...     .with_crack_results(crack_results)
    ...     .with_score_results(score_results)
    ...     .with_breach_results(breach_results)
    ...     .with_recommendations(["Upgrade to Argon2."])
    ...     .build()
    ... )
    """

    def __init__(self, total_hashes: int, elapsed: float = 0.0) -> None:
        self._total = total_hashes
        self._elapsed = elapsed
        self._crack: list[CrackResult] = []
        self._scores: list[ScoreResult] = []
        self._breach: list[BreachResult] = []
        self._recs: list[str] = []
        self._algo_tally: dict[str, int] = {}
        self._pattern_tally: dict[str, int] = {}

    def with_crack_results(self, results: list[CrackResult]) -> ReportBuilder:
        self._crack = results
        self._algo_tally = {}
        for r in results:
            key = r.algorithm.value
            self._algo_tally[key] = self._algo_tally.get(key, 0) + 1
        return self

    def with_score_results(self, results: list[ScoreResult]) -> ReportBuilder:
        self._scores = results
        self._pattern_tally = {}
        for sr in results:
            for match in sr.patterns_found:
                key = match.label.split("(")[0]  # type: ignore[union-attr]
                self._pattern_tally[key] = self._pattern_tally.get(key, 0) + 1
        return self

    def with_breach_results(self, results: list[BreachResult]) -> ReportBuilder:
        self._breach = results
        return self

    def with_recommendations(self, recs: list[str]) -> ReportBuilder:
        self._recs = recs
        return self

    def build(self) -> AuditReport:
        cracked = len(self._crack)
        return AuditReport(
            total_hashes=self._total,
            cracked=cracked,
            crack_rate=cracked / self._total if self._total else 0.0,
            crack_results=self._crack,
            score_results=self._scores,
            breach_results=self._breach,
            pattern_tally=self._pattern_tally,
            algorithm_tally=self._algo_tally,
            elapsed=self._elapsed,
            recommendations=self._recs,
        )


# ---------------------------------------------------------------------------
# Standalone render functions (used by both RichFormatter and CLI)
# ---------------------------------------------------------------------------

def print_crack_results(
    results: list[CrackResult],
    *,
    console: Console | None = None,
) -> None:
    """Render cracked hashes as a Rich table."""
    con = console or get_console()
    if not results:
        con.print("[dim]No hashes cracked.[/dim]")
        return

    table = Table(
        title="[bold cyan]Cracked Hashes[/bold cyan]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Hash (truncated)", style="dim", no_wrap=True, max_width=22)
    table.add_column("Algorithm",        style="cyan")
    table.add_column("Plaintext",        style="bold yellow")
    table.add_column("Method",           style="magenta")
    table.add_column("Attempts",         justify="right")
    table.add_column("Elapsed (s)",      justify="right")

    for r in results:
        table.add_row(
            r.hash_value[:20] + ("…" if len(r.hash_value) > 20 else ""),
            r.algorithm.value,
            r.plaintext,
            r.method,
            f"{r.attempts:,}",
            f"{r.elapsed:.3f}",
        )

    con.print(table)


def print_score_result(
    result: ScoreResult,
    *,
    console: Console | None = None,
) -> None:
    """Render a single :class:`~pas.models.ScoreResult` as a Rich panel."""
    con = console or get_console()
    style = _STRENGTH_STYLE[result.strength]
    bar = _score_bar(result.score)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="bold")
    grid.add_column()

    num_classes = bin(result.pool.value).count("1")

    grid.add_row("Password",       f"[bold]{result.password!r}[/bold]")
    grid.add_row("Length",         str(result.length))
    grid.add_row("Char classes",   f"{num_classes} ({result.pool})")
    grid.add_row("Shannon H",      f"{result.shannon_entropy:.2f} bits/char")
    grid.add_row("Search space",   f"{result.search_space_bits:.1f} bits")
    grid.add_row("Score",          f"[{style}]{result.score}/100  {bar}[/{style}]")
    grid.add_row("Strength",       _strength_text(result.strength))

    if result.patterns_found:
        pattern_str = ", ".join(
            getattr(m, "label", str(m)) for m in result.patterns_found
        )
        grid.add_row("[yellow]Patterns[/yellow]", f"[yellow]{pattern_str}[/yellow]")

    if result.policy_violations:
        grid.add_row(
            "[red]Violations[/red]",
            "[red]" + " · ".join(result.policy_violations) + "[/red]",
        )

    if result.recommendations:
        recs_str = "\n".join(f"• {r}" for r in result.recommendations)
        grid.add_row("[green]Tips[/green]", f"[green]{recs_str}[/green]")

    con.print(Panel(grid, title="[bold]Password Analysis[/bold]", border_style="blue"))


def print_breach_results(
    results: list[BreachResult],
    *,
    console: Console | None = None,
) -> None:
    """Render HIBP lookup results as a Rich table."""
    con = console or get_console()

    table = Table(
        title="[bold cyan]HIBP Breach Check[/bold cyan]",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Password")
    table.add_column("Breached?", justify="center")
    table.add_column("Occurrences", justify="right")

    for r in results:
        if r.is_breached:
            status = Text("YES", style="bold red")
            count  = Text(f"{r.count:,}", style="red")
        else:
            status = Text("No",  style="green")
            count  = Text("0",   style="dim green")
        table.add_row(r.password, status, count)

    con.print(table)


def print_audit_report(
    report: AuditReport,
    *,
    console: Console | None = None,
) -> None:
    """Render a complete audit report: summary, algorithm tally, patterns, cracks."""
    con = console or get_console()

    # --- Summary ---
    rate = report.crack_rate
    rate_colour = "bold red" if rate > 0.5 else "yellow" if rate > 0.2 else "green"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(justify="right", style="bold")
    summary.add_column()

    summary.add_row("Total hashes",  str(report.total_hashes))
    summary.add_row("Cracked",       f"[{rate_colour}]{report.cracked}[/{rate_colour}]")
    summary.add_row("Not cracked",   str(report.total_hashes - report.cracked))
    summary.add_row("Crack rate",    f"[{rate_colour}]{rate:.1%}[/{rate_colour}]")
    summary.add_row("Elapsed",       f"{report.elapsed:.2f} s")

    con.print(Panel(summary, title="[bold]Audit Summary[/bold]", border_style="cyan"))

    # --- Algorithm distribution ---
    if report.algorithm_tally:
        alg_table = Table(title="Algorithm Distribution", box=box.SIMPLE)
        alg_table.add_column("Algorithm")
        alg_table.add_column("Count", justify="right")

        danger_algos = {"md5", "sha1", "ntlm"}
        for alg, cnt in sorted(report.algorithm_tally.items(), key=lambda x: -x[1]):
            style = "red" if alg in danger_algos else ""
            alg_table.add_row(Text(alg, style=style), str(cnt))

        con.print(alg_table)

    # --- Pattern frequency bar chart ---
    if report.pattern_tally:
        max_count = max(report.pattern_tally.values(), default=1)
        pat_table = Table(title="Pattern Frequency", box=box.SIMPLE)
        pat_table.add_column("Pattern")
        pat_table.add_column("Count", justify="right")
        pat_table.add_column("Bar")

        for pat, cnt in sorted(report.pattern_tally.items(), key=lambda x: -x[1])[:12]:
            bar_w = max(1, int((cnt / max_count) * 22))
            pat_table.add_row(pat, str(cnt), f"[magenta]{'█' * bar_w}[/magenta]")

        con.print(pat_table)

    # --- Cracked hashes ---
    if report.crack_results:
        print_crack_results(report.crack_results, console=con)

    # --- Breach summary ---
    breached = [r for r in report.breach_results if r.is_breached]
    if breached:
        con.print(
            f"[bold red]{len(breached)}[/bold red] cracked password(s) "
            f"appear in known breach databases."
        )

    # --- Recommendations ---
    if report.recommendations:
        recs_body = "\n".join(
            f"  [green]•[/green] {r}" for r in report.recommendations
        )
        con.print(
            Panel(recs_body, title="[bold]Recommendations[/bold]", border_style="green")
        )


# ---------------------------------------------------------------------------
# Progress bar factory
# ---------------------------------------------------------------------------

def make_progress() -> Progress:
    """Return a pre-configured Rich :class:`Progress` for cracking runs."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        refresh_per_second=10,
    )
