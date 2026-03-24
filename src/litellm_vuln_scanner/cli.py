"""CLI entry point for litellm-vuln-scanner."""

from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from .scanner import FindingKind, GitHubScanner, ScanResult

app = typer.Typer(
    name="litellm-scan",
    help=(
        "Scan GitHub repos for the litellm supply chain compromise.\n\n"
        "Compromised versions: 1.82.7, 1.82.8 (PyPI, 2026-03-23)\n"
        "Reference: https://github.com/BerriAI/litellm/issues/24518"
    ),
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _get_token() -> str:
    """Resolve a GitHub token from env or gh CLI."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        err_console.print(
            "[red]Error:[/red] No GitHub token found. "
            "Set GITHUB_TOKEN or install/authenticate the gh CLI."
        )
        raise typer.Exit(1)


def _print_results(results: list[ScanResult], show_all: bool) -> int:
    """Pretty-print scan results. Returns exit code (1 if compromised found)."""
    compromised: list[tuple[ScanResult, object]] = []
    unpinned: list[tuple[ScanResult, object]] = []
    lockfile: list[tuple[ScanResult, object]] = []
    errors: list[ScanResult] = []

    for r in results:
        if r.error:
            errors.append(r)
        for f in r.findings:
            if f.kind == FindingKind.COMPROMISED:
                compromised.append((r, f))
            elif f.kind == FindingKind.UNPINNED:
                unpinned.append((r, f))
            elif f.kind == FindingKind.LOCKFILE:
                lockfile.append((r, f))

    # ── Compromised (critical) ────────────────────────────────────────────────
    if compromised:
        console.print("\n[bold red]╔══ CRITICAL: COMPROMISED VERSIONS FOUND ══╗[/bold red]")
        t = Table(show_header=True, header_style="bold red")
        t.add_column("Repo", style="bold")
        t.add_column("File")
        t.add_column("Version", style="red bold")
        t.add_column("Line")
        for _, f in compromised:
            t.add_row(f.repo, f.filepath, f.version, f.raw_line[:80])
        console.print(t)
        console.print(
            "\n[bold red]ACTION REQUIRED:[/bold red]\n"
            "  1. Pin litellm to >=1.82.9 or <=1.82.6 immediately\n"
            "  2. Rotate ALL secrets on affected systems (API keys, AWS, SSH)\n"
            "  3. Check cloud audit logs for unauthorized access\n"
            "  4. Search deployed envs for: litellm_init.pth in site-packages\n"
        )

    # ── Unbounded / unpinned ──────────────────────────────────────────────────
    if unpinned and (show_all or compromised):
        console.print("\n[bold yellow]⚠  UNPINNED (may have resolved to compromised version):[/bold yellow]")
        t = Table(show_header=True, header_style="bold yellow")
        t.add_column("Repo", style="bold")
        t.add_column("File")
        t.add_column("Constraint")
        t.add_column("Line")
        for _, f in unpinned:
            t.add_row(f.repo, f.filepath, f.version, f.raw_line[:80])
        console.print(t)
        console.print(
            "  If these repos ran [italic]pip install[/italic] between 2026-03-23 and 2026-03-24,\n"
            "  they may have installed the compromised version. Check deployment logs.\n"
        )
    elif unpinned:
        console.print(
            f"\n[yellow]⚠  {len(unpinned)} repo(s) use litellm with no upper bound "
            f"(run with --show-all to see details)[/yellow]"
        )

    # ── Lock file findings ────────────────────────────────────────────────────
    if lockfile and show_all:
        console.print("\n[dim]Lock file entries:[/dim]")
        t = Table(show_header=True, header_style="dim")
        t.add_column("Repo")
        t.add_column("File")
        t.add_column("Resolved Version")
        for _, f in lockfile:
            color = "red" if f.version in ("1.82.7", "1.82.8") else "green"
            t.add_row(f.repo, f.filepath, f"[{color}]{f.version}[/{color}]")
        console.print(t)

    # ── Errors ────────────────────────────────────────────────────────────────
    if errors and show_all:
        console.print("\n[dim]Scan errors (partial results):[/dim]")
        for r in errors:
            console.print(f"  [dim]{r.repo}:[/dim] {r.error}")

    # ── Summary ───────────────────────────────────────────────────────────────
    total = len(results)
    console.print(
        f"\n[bold]Summary:[/bold] scanned {total} repos — "
        f"[red]{len(compromised)} compromised[/red], "
        f"[yellow]{len(unpinned)} unpinned[/yellow], "
        f"[green]{total - len(compromised) - len(unpinned)} clean[/green]\n"
    )

    return 1 if compromised else 0


@app.command()
def scan(
    org: Optional[str] = typer.Option(None, "--org", "-o", help="GitHub org to scan"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="GitHub user to scan"),
    token: Optional[str] = typer.Option(
        None, "--token", "-t",
        help="GitHub token (defaults to GITHUB_TOKEN env var or gh CLI)",
    ),
    workers: int = typer.Option(10, "--workers", "-w", help="Parallel repo scan workers"),
    code_search_only: bool = typer.Option(
        False, "--fast", "-f",
        help="Run only the fast GitHub code search (skips per-file lockfile scanning)",
    ),
    show_all: bool = typer.Option(
        False, "--show-all", "-a",
        help="Show all findings including unpinned constraints and lockfile entries",
    ),
):
    """
    Scan GitHub repos for litellm supply chain compromise (v1.82.7 / v1.82.8).

    Examples:\n
      litellm-scan --org fanatics-gaming\n
      litellm-scan --user myusername --show-all\n
      litellm-scan --org myorg --user me --fast\n
    """
    if not org and not user:
        err_console.print("[red]Error:[/red] Specify at least one of --org or --user.")
        raise typer.Exit(1)

    gh_token = token or _get_token()

    with GitHubScanner(gh_token) as scanner:
        # ── Fast code search pass ─────────────────────────────────────────────
        console.print("\n[bold cyan]Phase 1: GitHub code search (fast pass)...[/bold cyan]")
        fast_findings: list = []

        if org:
            console.print(f"  Searching org: [bold]{org}[/bold]")
            try:
                fast_findings.extend(scanner.code_search_compromised(org=org))
            except Exception as exc:
                err_console.print(f"[yellow]Code search failed for org {org}: {exc}[/yellow]")

        if user:
            console.print(f"  Searching user: [bold]{user}[/bold]")
            try:
                fast_findings.extend(scanner.code_search_compromised(user=user))
            except Exception as exc:
                err_console.print(f"[yellow]Code search failed for user {user}: {exc}[/yellow]")

        if fast_findings:
            console.print(f"  [red]Found {len(fast_findings)} code search hit(s)![/red]")
            for f in fast_findings:
                rprint(f"  [red]  COMPROMISED:[/red] {f.repo} → {f.filepath} ({f.version})")

        if code_search_only:
            if not fast_findings:
                console.print("[green]✓ No compromised versions found via code search.[/green]")
            raise typer.Exit(1 if fast_findings else 0)

        # ── Per-repo file scan ────────────────────────────────────────────────
        console.print("\n[bold cyan]Phase 2: Per-repo file scan (lockfiles + pyproject)...[/bold cyan]")

        repos: list[str] = []
        if org:
            console.print(f"  Fetching repo list for org: [bold]{org}[/bold]")
            try:
                repos.extend(scanner.iter_org_repos(org))
            except Exception as exc:
                err_console.print(f"[red]Failed to list repos for {org}: {exc}[/red]")

        if user:
            console.print(f"  Fetching repo list for user: [bold]{user}[/bold]")
            try:
                repos.extend(scanner.iter_user_repos(user))
            except Exception as exc:
                err_console.print(f"[red]Failed to list repos for {user}: {exc}[/red]")

        console.print(f"  Scanning [bold]{len(repos)}[/bold] repos with {workers} workers...")

        results: list[ScanResult] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(scanner.scan_repo, repo): repo for repo in repos}
            with console.status("[dim]Scanning...[/dim]") as status:
                for done in as_completed(futures):
                    repo = futures[done]
                    try:
                        result = done.result()
                        results.append(result)
                        if result.findings:
                            status.update(f"[yellow]Hit in {repo}[/yellow]")
                    except Exception as exc:
                        results.append(ScanResult(repo=repo, error=str(exc)))

    exit_code = _print_results(results, show_all=show_all)
    raise typer.Exit(exit_code)


if __name__ == "__main__":
    app()
