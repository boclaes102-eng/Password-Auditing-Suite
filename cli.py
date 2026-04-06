"""Password Auditing Suite -- command-line interface.

All business logic lives in the ``pas`` package.  This module is intentionally
thin: parse arguments -> call domain functions -> pass results to a formatter.
State shared between options and the formatter is carried in ``AppContext``,
a typed dataclass passed via ``click.pass_context``.

Commands
--------
  identify   Heuristically identify the algorithm of one or more hashes.
  crack      Offline dictionary/mutation attack against a hash file.
  score      Analyse a password's entropy and policy compliance.
  breach     Check passwords against the HIBP k-anonymity API.
  mutate     Stream wordlist mutations to stdout or a file.
  audit      Full pipeline: crack -> score -> breach-check -> report.
"""
from __future__ import annotations

import io
import sys
import time

# On Windows the default stdout encoding is cp1252, which cannot represent Rich's
# Unicode box-drawing characters.  Re-wrap stdout/stderr with UTF-8 before any
# output happens.  This is a no-op on macOS/Linux.
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from dataclasses import dataclass, field
from pathlib import Path

import click
from rich.console import Console

# Force modern Windows Terminal rendering; prevents cp1252 box-drawing errors
# on legacy cmd.exe consoles.  Has no effect on macOS/Linux.
_RICH_CONSOLE_KWARGS = {"legacy_windows": False}

# ---------------------------------------------------------------------------
# Shared context object
# ---------------------------------------------------------------------------

@dataclass
class AppContext:
    """Typed context object passed through the click group."""
    console: Console = field(default_factory=lambda: Console(legacy_windows=False))
    verbose: bool = False
    json_output: bool = False


pass_ctx = click.make_pass_decorator(AppContext, ensure=True)

# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    package_name="password-auditing-suite",
    prog_name="pas",
    message="%(prog)s %(version)s",
)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable verbose output.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output results as JSON.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, json_output: bool) -> None:
    """Password Auditing Suite -- expert-grade offline credential analysis.

    \b
    Quick-start examples:
      pas identify 5f4dcc3b5aa765d61d8327deb882cf99
      pas score 'P@ssw0rd!' --min-length 12
      pas breach 'hunter2' 'password123'
      pas crack hashes.txt --wordlist rockyou.txt
      pas audit hashes.txt --wordlist rockyou.txt
    """
    ctx.ensure_object(AppContext)
    ctx.obj.verbose = verbose
    ctx.obj.json_output = json_output


# ---------------------------------------------------------------------------
# identify
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("hashes", nargs=-1, required=True, metavar="HASH...")
@click.option(
    "--top", "-n",
    default=3,
    show_default=True,
    help="Show top-N candidates per hash.",
)
@pass_ctx
def identify(ctx: AppContext, hashes: tuple[str, ...], top: int) -> None:
    """Identify the hash algorithm(s) for one or more HASH strings."""
    from pas.identifier import identify as _identify
    from pas.exceptions import HashIdentificationError

    con = ctx.console
    for h in hashes:
        try:
            candidates = _identify(h)[:top]
        except HashIdentificationError as exc:
            con.print(f"[red]Error:[/red] {exc}")
            continue

        display = h[:32] + ("..." if len(h) > 32 else "")
        con.rule(f"[bold]{display}[/bold]")
        for i, c in enumerate(candidates, 1):
            stars = "*" * round(c.confidence * 5)
            empty = "-" * (5 - round(c.confidence * 5))
            con.print(
                f"  {i}. [cyan]{c.algorithm.value:<20}[/cyan] "
                f"[yellow]{c.confidence:>5.0%}[/yellow]  {stars}{empty}  "
                f"[dim]{c.rationale}[/dim]"
            )
        con.print()


# ---------------------------------------------------------------------------
# crack
# ---------------------------------------------------------------------------

@cli.command()
@click.argument(
    "hashfile",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--wordlist", "-w",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a plaintext wordlist (one entry per line).",
)
@click.option(
    "--algorithm", "-a",
    default=None,
    metavar="ALG",
    help="Force a specific algorithm (e.g. sha256).  Auto-detected if omitted.",
)
@click.option(
    "--mutate/--no-mutate",
    default=True,
    show_default=True,
    help="Apply mutation rules to the wordlist.",
)
@click.option(
    "--format", "-f", "fmt",
    default="hash",
    type=click.Choice(["hash", "user:hash"]),
    show_default=True,
    help="Input file format.",
)
@click.option(
    "--workers",
    default=4,
    show_default=True,
    help="Thread count (mainly benefits bcrypt/Argon2).",
)
@click.option(
    "--timeout",
    default=3600.0,
    show_default=True,
    help="Wall-clock timeout in seconds.",
)
@pass_ctx
def crack(
    ctx: AppContext,
    hashfile: Path,
    wordlist: Path,
    algorithm: str | None,
    mutate: bool,
    fmt: str,
    workers: int,
    timeout: float,
) -> None:
    """Crack hashes in HASHFILE using a dictionary / mutation attack."""
    from pas.cracker import Cracker, CrackProgress, DictionaryAttack, MutationAttack
    from pas.identifier import identify as _identify
    from pas.models import HashAlgorithm
    from pas.reporter import print_crack_results, make_progress
    from pas.exceptions import HashIdentificationError

    con = ctx.console

    # --- Parse hash file ---
    raw_hashes = _parse_hash_file(hashfile, fmt)
    if not raw_hashes:
        con.print("[red]No hashes found in file.[/red]")
        sys.exit(1)

    con.print(
        f"[bold]Loaded [cyan]{len(raw_hashes)}[/cyan] hash(es) "
        f"from [yellow]{hashfile.name}[/yellow][/bold]"
    )

    # --- Algorithm resolution ---
    hash_algo_map: dict[str, HashAlgorithm] = {}
    for h in raw_hashes:
        if algorithm:
            try:
                algo = HashAlgorithm(algorithm)
            except ValueError:
                con.print(f"[red]Unknown algorithm: {algorithm!r}[/red]")
                sys.exit(1)
        else:
            try:
                candidates = _identify(h)
                algo = candidates[0].algorithm
                if ctx.verbose:
                    con.print(
                        f"  [dim]{h[:20]}...[/dim] -> [cyan]{algo.value}[/cyan] "
                        f"({candidates[0].confidence:.0%} confidence)"
                    )
            except HashIdentificationError:
                algo = HashAlgorithm.UNKNOWN
        hash_algo_map[h] = algo

    # --- Build strategies ---
    strategies = [DictionaryAttack(str(wordlist))]
    if mutate:
        strategies.append(MutationAttack(str(wordlist)))

    progress = CrackProgress(total_hashes=len(raw_hashes))
    cracker = Cracker(
        hashes=hash_algo_map,
        strategies=strategies,
        progress=progress,
        workers=workers,
        timeout=timeout,
    )

    # --- Run with Rich progress ---
    t0 = time.perf_counter()
    with make_progress() as prog:
        task = prog.add_task("Cracking...", total=None)
        results = cracker.run()
        prog.update(task, total=progress.attempts, completed=progress.attempts)
    elapsed = time.perf_counter() - t0

    crack_rate = len(results) / len(raw_hashes) if raw_hashes else 0.0
    rate_colour = "bold red" if crack_rate > 0.5 else "yellow" if crack_rate > 0.2 else "green"

    con.print(
        f"\nCracked [green]{len(results)}[/green]/[cyan]{len(raw_hashes)}[/cyan] "
        f"([{rate_colour}]{crack_rate:.1%}[/{rate_colour}]) "
        f"in [magenta]{elapsed:.2f}s[/magenta] "
        f"({progress.attempts:,} candidates tried)"
    )
    print_crack_results(results, console=con)


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("passwords", nargs=-1, required=True, metavar="PASSWORD...")
@click.option("--min-length",     default=8,     show_default=True, help="Minimum required length.")
@click.option("--max-length",     default=128,   show_default=True, help="Maximum allowed length.")
@click.option("--min-classes",    default=1,     show_default=True, help="Minimum character classes.")
@click.option("--max-repeat",     default=3,     show_default=True, help="Block runs longer than N.")
@click.option("--block-common/--no-block-common", default=True, show_default=True,
              help="Block commonly-used passwords.")
@pass_ctx
def score(
    ctx: AppContext,
    passwords: tuple[str, ...],
    min_length: int,
    max_length: int,
    min_classes: int,
    max_repeat: int,
    block_common: bool,
) -> None:
    """Analyse PASSWORD entropy and policy compliance."""
    from pas.scorer import score_password, PasswordPolicy
    from pas.scorer import (
        MinLengthRule, MaxLengthRule, MaxRepeatRule, PoolRule, BlockedPatternRule
    )
    from pas.reporter import print_score_result

    rules = [
        MinLengthRule(min_length),
        MaxLengthRule(max_length),
        MaxRepeatRule(max_repeat),
        PoolRule(min_classes),
    ]
    if block_common:
        rules.append(BlockedPatternRule(min_severity=0.9))

    policy = PasswordPolicy(rules=rules)  # type: ignore[arg-type]

    for pw in passwords:
        result = score_password(pw, policy)
        print_score_result(result, console=ctx.console)


# ---------------------------------------------------------------------------
# breach
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("passwords", nargs=-1, required=True, metavar="PASSWORD...")
@pass_ctx
def breach(ctx: AppContext, passwords: tuple[str, ...]) -> None:
    """Check PASSWORDs against the HIBP k-anonymity breach database.

    Only the first 5 hex characters of each password's SHA-1 hash are sent
    to the API -- the plaintext and full hash never leave this machine.
    """
    from pas.breach import check_many
    from pas.reporter import print_breach_results

    con = ctx.console
    with con.status("[bold blue]Querying HIBP (k-anonymity)...[/bold blue]"):
        results = check_many(list(passwords))

    print_breach_results(results, console=con)

    breached = sum(1 for r in results if r.is_breached)
    if breached:
        con.print(
            f"\n[bold red]!  {breached} password(s) found in known breach databases.[/bold red]"
        )
    else:
        con.print("\n[green]v  No passwords found in breach databases.[/green]")


# ---------------------------------------------------------------------------
# mutate
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("wordlist", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(dir_okay=False),
    help="Write mutations to FILE instead of stdout.",
)
@click.option(
    "--rules", "-r",
    multiple=True,
    type=click.Choice(["leet", "case", "suffix", "prefix", "date", "reverse", "double", "keyboard"]),
    help="Restrict to specific rule(s).  May be repeated.  Default: all rules.",
)
@click.option("--max-leet",  default=64,  show_default=True, help="Cap on leet-speak combinations per word.")
@click.option("--max-dates", default=200, show_default=True, help="Cap on date-token variants per word.")
@pass_ctx
def mutate(
    ctx: AppContext,
    wordlist: str,
    output: str | None,
    rules: tuple[str, ...],
    max_leet: int,
    max_dates: int,
) -> None:
    """Stream wordlist mutations (leet, dates, keyboard walks, case variants...).

    Output goes to stdout unless --output is specified.
    """
    from pas.mutator import MutationPipeline, mutate_wordlist, MutationConfig

    config = MutationConfig(max_leet_combinations=max_leet, max_date_tokens=max_dates)
    pipeline = (
        MutationPipeline.from_names(list(rules), config)
        if rules
        else MutationPipeline(config=config)
    )

    sink = open(output, "w", encoding="utf-8") if output else sys.stdout
    count = 0
    try:
        for word in mutate_wordlist(wordlist, pipeline):
            sink.write(word + "\n")
            count += 1
    finally:
        if output and not sink.closed:
            sink.close()

    if output:
        ctx.console.print(
            f"[green]Wrote [bold]{count:,}[/bold] mutations to [yellow]{output}[/yellow][/green]"
        )
    elif ctx.verbose:
        ctx.console.print(f"[dim]{count:,} mutations written to stdout[/dim]", file=sys.stderr)


# ---------------------------------------------------------------------------
# audit (full pipeline)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument(
    "hashfile",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--wordlist", "-w",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Wordlist path.",
)
@click.option("--breach-check/--no-breach-check", default=True, show_default=True)
@click.option("--mutate/--no-mutate", default=True, show_default=True)
@click.option(
    "--format", "-f", "fmt",
    default="hash",
    type=click.Choice(["hash", "user:hash"]),
    show_default=True,
)
@click.option("--workers", default=4, show_default=True)
@click.option("--timeout", default=3600.0, show_default=True)
@pass_ctx
def audit(
    ctx: AppContext,
    hashfile: Path,
    wordlist: Path,
    breach_check: bool,
    mutate: bool,
    fmt: str,
    workers: int,
    timeout: float,
) -> None:
    """Full audit pipeline: crack -> score plaintexts -> breach-check -> report.

    This command chains every module in the suite and produces a structured
    summary report.  Use ``--no-breach-check`` if offline-only is required.
    """
    from pas.cracker import Cracker, CrackProgress, DictionaryAttack, MutationAttack
    from pas.identifier import identify as _identify
    from pas.models import HashAlgorithm
    from pas.scorer import score_password
    from pas.breach import check_many
    from pas.reporter import ReportBuilder, RichFormatter, JsonFormatter, make_progress

    con = ctx.console

    # --- Parse ---
    raw_hashes = _parse_hash_file(hashfile, fmt)
    if not raw_hashes:
        con.print("[red]No hashes found.[/red]")
        sys.exit(1)

    con.print(f"\n[bold]Auditing [cyan]{len(raw_hashes)}[/cyan] hash(es)...[/bold]\n")

    # --- Identify algorithms ---
    hash_algo_map: dict[str, HashAlgorithm] = {}
    algo_tally: dict[str, int] = {}
    for h in raw_hashes:
        try:
            candidates = _identify(h)
            algo = candidates[0].algorithm
        except Exception:
            algo = HashAlgorithm.UNKNOWN
        hash_algo_map[h] = algo
        algo_tally[algo.value] = algo_tally.get(algo.value, 0) + 1

    # --- Crack ---
    strategies = [DictionaryAttack(str(wordlist))]
    if mutate:
        strategies.append(MutationAttack(str(wordlist)))

    progress = CrackProgress(total_hashes=len(raw_hashes))
    cracker = Cracker(
        hashes=hash_algo_map,
        strategies=strategies,
        progress=progress,
        workers=workers,
        timeout=timeout,
    )

    t0 = time.perf_counter()
    with make_progress() as prog:
        prog.add_task("Cracking...", total=None)
        crack_results = cracker.run()
    elapsed = time.perf_counter() - t0

    # --- Score ---
    plaintexts = [r.plaintext for r in crack_results]
    score_results = [score_password(pw) for pw in plaintexts]

    # --- Breach ---
    breach_results = []
    if breach_check and plaintexts:
        with con.status("[bold blue]Querying HIBP...[/bold blue]"):
            try:
                breach_results = check_many(plaintexts)
            except Exception as exc:
                con.print(f"[yellow]Breach check failed: {exc}[/yellow]")

    # --- Build recommendations ---
    recommendations = _generate_recommendations(
        crack_results, score_results, breach_results, raw_hashes, algo_tally
    )

    # --- Render ---
    report = (
        ReportBuilder(total_hashes=len(raw_hashes), elapsed=elapsed)
        .with_crack_results(crack_results)
        .with_score_results(score_results)
        .with_breach_results(breach_results)
        .with_recommendations(recommendations)
        .build()
    )
    # Override algo_tally from identification (includes un-cracked hashes)
    report.algorithm_tally.update(algo_tally)

    if ctx.json_output:
        JsonFormatter().render(report)
    else:
        RichFormatter(console=con).render(report)


# ---------------------------------------------------------------------------
# Shared helpers (module-private)
# ---------------------------------------------------------------------------

def _parse_hash_file(path: Path, fmt: str) -> list[str]:
    """Read a hash file and return a list of raw hash strings."""
    hashes: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if fmt == "user:hash" and ":" in line:
            line = line.split(":", 1)[1].strip()
        if line:
            hashes.append(line)
    return hashes


def _generate_recommendations(
    crack_results: list,
    score_results: list,
    breach_results: list,
    raw_hashes: list[str],
    algo_tally: dict[str, int],
) -> list[str]:
    recs: list[str] = []
    total = len(raw_hashes)
    cracked = len(crack_results)
    crack_rate = cracked / total if total else 0.0

    if crack_rate > 0.5:
        recs.append(
            f"{crack_rate:.0%} of hashes were cracked -- enforce stronger password policies immediately."
        )
    elif crack_rate > 0.2:
        recs.append(
            f"{crack_rate:.0%} crack rate is concerning -- review your password policy."
        )

    breached_count = sum(1 for r in breach_results if r.is_breached)
    if breached_count:
        recs.append(
            f"{breached_count} cracked password(s) appear in known breach databases -- "
            f"force resets and invalidate sessions."
        )

    dangerous_algos = {"md5", "sha1", "ntlm"}
    for alg in dangerous_algos:
        if algo_tally.get(alg, 0) > 0:
            recs.append(
                f"Unsalted {alg.upper()} hashes detected -- migrate to Argon2id or bcrypt immediately. "
                f"Unsalted hashes are trivially rainbow-table cracked."
            )

    weak_passwords = [sr for sr in score_results if sr.score < 40]
    if weak_passwords:
        recs.append(
            f"{len(weak_passwords)} cracked password(s) scored Weak or Very Weak -- "
            f"enforce minimum strength requirements at registration."
        )

    pattern_counts: dict[str, int] = {}
    for sr in score_results:
        for m in sr.patterns_found:
            key = getattr(m, "label", str(m)).split("(")[0]
            pattern_counts[key] = pattern_counts.get(key, 0) + 1

    if pattern_counts.get("keyboard-walk", 0) > max(1, total * 0.05):
        recs.append(
            "High prevalence of keyboard-walk patterns -- add a real-time pattern checker "
            "to your password input validator."
        )
    if pattern_counts.get("common-password", 0) > 0:
        recs.append(
            "Common passwords detected -- integrate a blocked-password list at registration "
            "(see NIST SP 800-63B S5.1.1)."
        )

    if not recs:
        recs.append("Password hygiene looks acceptable.  Continue monitoring with periodic audits.")

    return recs


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
