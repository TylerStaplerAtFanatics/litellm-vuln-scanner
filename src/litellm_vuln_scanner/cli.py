"""CLI entry point for litellm-vuln-scanner."""

from __future__ import annotations

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from .scanner import (
    FindingKind,
    GitHubScanner,
    ScanResult,
    COMPROMISE_WINDOW_START,
    COMPROMISE_WINDOW_END,
    COMPROMISED_VERSIONS,
    JobAnalysis,
)

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
    """
    Resolve a GitHub token. Prefers the gh CLI so that its full OAuth scopes
    are used. Falls back to GITHUB_TOKEN / GH_TOKEN env vars.
    """
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True
        )
        token = result.stdout.strip()
        if token:
            return token
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token

    err_console.print(
        "[red]Error:[/red] No GitHub token found. "
        "Run [bold]gh auth login[/bold] or set GITHUB_TOKEN."
    )
    raise typer.Exit(1)


def _build_report(
    results: list[ScanResult],
    org: str | None,
    user: str | None,
    repos_with_litellm: int,
    total_repos_scanned: int,
) -> str:
    """Generate a markdown infosec report from scan results."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scope = ", ".join(filter(None, [f"org:{org}" if org else None, f"user:{user}" if user else None]))

    compromised = [f for r in results for f in r.findings if f.kind == FindingKind.COMPROMISED]
    unpinned    = [f for r in results for f in r.findings if f.kind == FindingKind.UNPINNED]
    lockfile    = [f for r in results for f in r.findings if f.kind == FindingKind.LOCKFILE]
    ci_runs     = [run for r in results for run in r.workflow_runs]

    status = "🔴 CRITICAL" if compromised else ("🟡 REVIEW REQUIRED" if (unpinned and ci_runs) else "🟢 CLEAN")

    lines: list[str] = [
        "# LiteLLM Supply Chain Compromise — Scan Report",
        "",
        f"**Scan date:** {now}  ",
        f"**Scope:** {scope}  ",
        f"**Status:** {status}  ",
        f"**Reference:** [BerriAI/litellm#24518](https://github.com/BerriAI/litellm/issues/24518)",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total repos scanned | {total_repos_scanned} |",
        f"| Repos referencing litellm | {repos_with_litellm} |",
        f"| **Compromised version pinned** | **{len(set(f.repo for f in compromised))}** |",
        f"| Unpinned (unbounded constraint) | {len(set(f.repo for f in unpinned))} |",
        f"| CI runs during compromise window | {len(ci_runs)} |",
        "",
    ]

    if compromised:
        lines += [
            "## ⛔ CRITICAL: Compromised Versions Found",
            "",
            "These repos are pinned to a known-malicious litellm version.",
            "**Immediate action required: rotate all secrets.**",
            "",
            "| Repo | File | Version |",
            "|------|------|---------|",
        ]
        for f in compromised:
            lines.append(f"| `{f.repo}` | `{f.filepath}` | `{f.version}` |")
        lines += ["", "### Required Actions", ""]
        lines += [
            "1. Pin litellm to `>=1.82.9` or `==1.82.6` immediately",
            "2. Rotate **all secrets** accessible from affected systems (API keys, AWS, SSH keys, DB passwords)",
            "3. Check cloud provider audit logs for unauthorized access",
            "4. Search deployed environments for `litellm_init.pth` in Python site-packages",
            "5. Review git history for unexpected changes made during the exposure window",
            "",
        ]

    if unpinned:
        lines += [
            "## ⚠️ Unpinned litellm Dependencies",
            "",
            "These repos use `litellm>=X` with no upper bound. If `pip install` or `uv sync`",
            f"ran between **{COMPROMISE_WINDOW_START.strftime('%Y-%m-%d')}** and **{COMPROMISE_WINDOW_END.strftime('%Y-%m-%d')}**,",
            "the compromised version may have been installed.",
            "",
            "| Repo | File | Constraint |",
            "|------|------|------------|",
        ]
        for f in unpinned:
            lines.append(f"| `{f.repo}` | `{f.filepath}` | `{f.version}` |")
        lines.append("")

    if ci_runs:
        any_compromised_ci = any(
            job.resolved_version in COMPROMISED_VERSIONS
            for run in ci_runs for job in run.jobs if job.resolved_version
        )
        any_litellm_ci = any(job.installed_litellm for run in ci_runs for job in run.jobs)

        section_icon = "🚨" if any_compromised_ci else ("⚠️" if any_litellm_ci else "🔍")
        lines += [
            f"## {section_icon} CI Runs During Compromise Window",
            "",
            f"Runs between **{COMPROMISE_WINDOW_START.strftime('%Y-%m-%d %H:%M UTC')}** "
            f"and **{COMPROMISE_WINDOW_END.strftime('%Y-%m-%d %H:%M UTC')}** "
            "on repos with unbounded litellm dependencies.",
            "",
        ]

        if any_compromised_ci:
            lines += [
                "> **CRITICAL**: A compromised litellm version was confirmed installed by CI.",
                "> Rotate all secrets accessible from affected environments immediately.",
                "",
            ]

        for run in ci_runs:
            litellm_jobs = [j for j in run.jobs if j.installed_litellm]
            status_icon = "🚨" if any(
                j.resolved_version in COMPROMISED_VERSIONS for j in litellm_jobs if j.resolved_version
            ) else ("⚠️" if litellm_jobs else "ℹ️")

            lines += [
                f"### {status_icon} [{run.repo}]({run.run_url}) — {run.workflow_name}",
                "",
                f"- **Branch**: `{run.head_branch}`",
                f"- **Started**: {run.started_at.strftime('%Y-%m-%d %H:%M UTC')}",
                f"- **Conclusion**: {run.conclusion or 'in-progress'}",
                f"- **Run URL**: {run.run_url}",
                "",
            ]

            if run.jobs:
                lines += [
                    "| Job | pip/uv ran? | litellm installed? | Version | Evidence |",
                    "|-----|------------|-------------------|---------|----------|",
                ]
                for job in run.jobs:
                    ver = job.resolved_version or "—"
                    ver_fmt = f"**{ver}** ⛔" if ver in COMPROMISED_VERSIONS else ver
                    evidence = "; ".join(job.evidence_lines[:2])[:120] if job.evidence_lines else "—"
                    lines.append(
                        f"| [{job.job_name}]({job.job_url}) "
                        f"| {'yes' if job.ran_installer else 'no'} "
                        f"| {'**YES**' if job.installed_litellm else 'no'} "
                        f"| `{ver_fmt}` "
                        f"| `{evidence}` |"
                    )
                lines.append("")
            else:
                lines += ["*(Log analysis unavailable for this run)*", ""]
    elif unpinned:
        lines += [
            "## ✅ CI Runs During Compromise Window",
            "",
            f"No GitHub Actions runs detected between "
            f"{COMPROMISE_WINDOW_START.strftime('%Y-%m-%d')} and "
            f"{COMPROMISE_WINDOW_END.strftime('%Y-%m-%d')} "
            "for repos with unbounded litellm dependencies.",
            "",
        ]

    if lockfile:
        lines += [
            "## Lock File Resolved Versions",
            "",
            "| Repo | File | Resolved Version |",
            "|------|------|-----------------|",
        ]
        for f in lockfile:
            flag = " ⛔" if f.version in COMPROMISED_VERSIONS else ""
            lines.append(f"| `{f.repo}` | `{f.filepath}` | `{f.version}`{flag} |")
        lines.append("")

    lines += [
        "---",
        "",
        f"*Generated by [litellm-vuln-scanner](https://github.com/TylerStaplerAtFanatics/litellm-vuln-scanner) on {now}*",
    ]
    return "\n".join(lines)


def _print_results(
    results: list[ScanResult],
    show_all: bool,
    repos_with_litellm: int,
    total_repos_scanned: int,
) -> int:
    """Pretty-print scan results. Returns exit code (1 if compromised found)."""
    compromised: list[tuple[ScanResult, object]] = []
    unpinned:    list[tuple[ScanResult, object]] = []
    lockfile:    list[tuple[ScanResult, object]] = []
    errors:      list[ScanResult] = []

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

    # ── Workflow runs during compromise window ────────────────────────────────
    runs_with_findings = [(r, r.workflow_runs) for r in results if r.workflow_runs]
    if runs_with_findings:
        window = (
            f"{COMPROMISE_WINDOW_START.strftime('%Y-%m-%d %H:%M UTC')} – "
            f"{COMPROMISE_WINDOW_END.strftime('%Y-%m-%d %H:%M UTC')}"
        )
        # Determine worst-case across all runs
        any_litellm_installed = any(
            job.installed_litellm
            for _, runs in runs_with_findings
            for run in runs
            for job in run.jobs
        )
        any_compromised_version = any(
            job.resolved_version in COMPROMISED_VERSIONS
            for _, runs in runs_with_findings
            for run in runs
            for job in run.jobs
            if job.resolved_version
        )

        header_color = "bold red" if any_compromised_version else (
            "bold yellow" if any_litellm_installed else "bold yellow"
        )
        console.print(f"\n[{header_color}]⚠  CI RUNS DURING COMPROMISE WINDOW ({window}):[/{header_color}]")

        for scan_result, runs in runs_with_findings:
            for run in runs:
                has_jobs = bool(run.jobs)
                litellm_jobs = [j for j in run.jobs if j.installed_litellm]
                run_color = "red" if any(
                    j.resolved_version in COMPROMISED_VERSIONS for j in litellm_jobs if j.resolved_version
                ) else ("yellow" if litellm_jobs else "dim")

                conclusion_color = {"success": "green", "failure": "red", "cancelled": "dim"}.get(
                    run.conclusion or "", "yellow"
                )
                console.print(
                    f"\n  [{run_color}]● {scan_result.repo}[/{run_color}]  "
                    f"[dim]{run.workflow_name[:60]}[/dim]  "
                    f"branch=[italic]{run.head_branch}[/italic]  "
                    f"started={run.started_at.strftime('%Y-%m-%d %H:%M UTC')}  "
                    f"[{conclusion_color}]{run.conclusion or 'in-progress'}[/{conclusion_color}]  "
                    f"[link={run.run_url}]view run[/link]"
                )

                if not has_jobs:
                    console.print("    [dim](log analysis unavailable)[/dim]")
                    continue

                # Print job-level detail
                t = Table(show_header=True, header_style="dim", box=None, padding=(0, 2))
                t.add_column("Job")
                t.add_column("pip/uv ran?")
                t.add_column("litellm installed?")
                t.add_column("Version")
                t.add_column("Evidence")

                for job in run.jobs:
                    pip_ran   = "[green]yes[/green]" if job.ran_installer else "[dim]no[/dim]"
                    installed = "[bold red]YES[/bold red]" if job.installed_litellm else "[dim]no[/dim]"
                    ver_str   = f"[{'red' if job.resolved_version in COMPROMISED_VERSIONS else 'green'}]{job.resolved_version}[/{'red' if job.resolved_version in COMPROMISED_VERSIONS else 'green'}]" if job.resolved_version else "[dim]—[/dim]"
                    evidence  = ("\n".join(job.evidence_lines[:2]))[:80] if job.evidence_lines else "—"
                    t.add_row(job.job_name[:40], pip_ran, installed, ver_str, evidence)

                console.print(t)

                if litellm_jobs:
                    for job in litellm_jobs:
                        if job.resolved_version in COMPROMISED_VERSIONS:
                            console.print(
                                f"    [bold red]CONFIRMED: litellm {job.resolved_version} "
                                f"was installed by job '{job.job_name}' — ROTATE ALL SECRETS[/bold red]"
                            )
                        elif job.resolved_version:
                            console.print(
                                f"    [green]litellm {job.resolved_version} installed "
                                f"(not a compromised version)[/green]"
                            )
                        else:
                            console.print(
                                f"    [yellow]litellm installation detected in job '{job.job_name}' "
                                f"but version could not be determined — inspect logs manually[/yellow]"
                            )

        if any_compromised_version:
            console.print(
                "\n[bold red]CRITICAL: Compromised litellm version was installed via CI.\n"
                "Rotate ALL secrets immediately.[/bold red]\n"
            )
        elif any_litellm_installed:
            console.print(
                "\n[yellow]litellm was installed during the window but no compromised version detected.[/yellow]\n"
            )
        else:
            console.print(
                "\n[green]CI ran during the window but no litellm installation detected in job logs.[/green]\n"
            )

    elif any(f.kind == FindingKind.UNPINNED for r in results for f in r.findings):
        console.print(
            "\n[green]✓ No CI runs detected during the compromise window "
            f"({COMPROMISE_WINDOW_START.strftime('%Y-%m-%d')} – "
            f"{COMPROMISE_WINDOW_END.strftime('%Y-%m-%d')})[/green]"
        )

    # ── Lock file findings ────────────────────────────────────────────────────
    if lockfile and show_all:
        console.print("\n[dim]Lock file entries:[/dim]")
        t = Table(show_header=True, header_style="dim")
        t.add_column("Repo")
        t.add_column("File")
        t.add_column("Resolved Version")
        for _, f in lockfile:
            color = "red" if f.version in COMPROMISED_VERSIONS else "green"
            t.add_row(f.repo, f.filepath, f"[{color}]{f.version}[/{color}]")
        console.print(t)

    # ── Errors ────────────────────────────────────────────────────────────────
    if errors and show_all:
        console.print("\n[dim]Scan errors (partial results):[/dim]")
        for r in errors:
            console.print(f"  [dim]{r.repo}:[/dim] {r.error}")

    # ── Summary ───────────────────────────────────────────────────────────────
    console.print(
        f"\n[bold]Summary:[/bold] {total_repos_scanned} repos scanned "
        f"({repos_with_litellm} reference litellm) — "
        f"[red]{len(compromised)} compromised[/red], "
        f"[yellow]{len(unpinned)} unpinned[/yellow], "
        f"[green]{total_repos_scanned - len(set(f.repo for _, f in compromised)) - len(set(f.repo for _, f in unpinned))} clean[/green]\n"
    )

    return 1 if compromised else 0


@app.command()
def scan(
    org: Optional[str] = typer.Option(None, "--org", "-o", help="GitHub org to scan"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Scan personal repos for the authenticated user"),
    token: Optional[str] = typer.Option(
        None, "--token", "-t",
        help="GitHub token (defaults to gh CLI, then GITHUB_TOKEN env var)",
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
    check_runs: bool = typer.Option(
        True, "--check-runs/--no-check-runs",
        help="Check GitHub Actions runs during the compromise window for repos with unbounded litellm deps",
    ),
    check_logs: bool = typer.Option(
        True, "--check-logs/--no-check-logs",
        help="Fetch and analyse job logs for CI runs in the compromise window (slower but definitive)",
    ),
    report: Optional[Path] = typer.Option(
        None, "--report", "-r",
        help="Write a markdown infosec report to this file path",
    ),
):
    """
    Scan GitHub repos for litellm supply chain compromise (v1.82.7 / v1.82.8).

    Examples:\n
      litellm-scan --org fanatics-gaming\n
      litellm-scan --org fanatics-gaming --user --show-all\n
      litellm-scan --org myorg --report report.md\n
    """
    if not org and not user:
        err_console.print("[red]Error:[/red] Specify at least one of --org or --user.")
        raise typer.Exit(1)

    gh_token = token or _get_token()

    with GitHubScanner(gh_token) as scanner:
        # ── Phase 1: Fast code search for exact compromised pins ──────────────
        console.print("\n[bold cyan]Phase 1: Checking for exact compromised version pins...[/bold cyan]")
        fast_findings: list = []

        if org:
            console.print(f"  Searching org: [bold]{org}[/bold]")
            try:
                fast_findings.extend(scanner.code_search_compromised(org=org))
            except Exception as exc:
                err_console.print(f"[yellow]Code search failed for org {org}: {exc}[/yellow]")

        if user:
            console.print(f"  Searching authenticated user's repos...")
            try:
                fast_findings.extend(scanner.code_search_compromised(user="@me"))
            except Exception as exc:
                err_console.print(f"[yellow]Code search failed for user repos: {exc}[/yellow]")

        if fast_findings:
            console.print(f"  [red]Found {len(fast_findings)} code search hit(s)![/red]")
            for f in fast_findings:
                rprint(f"  [red]  COMPROMISED:[/red] {f.repo} → {f.filepath} ({f.version})")

        if code_search_only:
            if not fast_findings:
                console.print("[green]✓ No compromised versions found via code search.[/green]")
            raise typer.Exit(1 if fast_findings else 0)

        # ── Phase 2: Filter to repos that actually reference litellm ──────────
        console.print("\n[bold cyan]Phase 2: Filtering repos with litellm via code search...[/bold cyan]")

        repos: set[str] = set()
        search_failed = False

        if org:
            console.print(f"  Searching org [bold]{org}[/bold] for litellm in dependency files...")
            try:
                found = scanner.search_repos_with_litellm(org=org)
                repos.update(found)
                console.print(f"  [bold]{len(found)}[/bold] repo(s) reference litellm in {org}")
            except Exception as exc:
                err_console.print(f"[yellow]Filter search failed for {org}: {exc} — falling back to full org scan[/yellow]")
                search_failed = True

        if user:
            console.print(f"  Searching authenticated user's repos for litellm...")
            try:
                found = scanner.search_repos_with_litellm(user="@me")
                repos.update(found)
                console.print(f"  [bold]{len(found)}[/bold] personal repo(s) reference litellm")
            except Exception as exc:
                err_console.print(f"[yellow]Filter search failed for user repos: {exc} — falling back to full user scan[/yellow]")
                search_failed = True

        repos_with_litellm = len(repos)

        # Fallback: list all repos if code search failed
        if search_failed:
            console.print("  [dim]Falling back to complete repo listing...[/dim]")
            if org:
                try:
                    repos.update(scanner.iter_org_repos(org))
                except Exception as exc:
                    err_console.print(f"[red]Failed to list repos for {org}: {exc}[/red]")
            if user:
                try:
                    repos.update(scanner.iter_user_repos())
                except Exception as exc:
                    err_console.print(f"[red]Failed to list user repos: {exc}[/red]")

        total_repos_scanned = len(repos)

        # ── Phase 3: Deep-scan filtered repos ─────────────────────────────────
        console.print(f"\n[bold cyan]Phase 3: Deep-scanning {len(repos)} repo(s) with {workers} workers...[/bold cyan]")

        results: list[ScanResult] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(scanner.scan_repo, repo, check_runs, check_logs): repo for repo in repos}
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

    exit_code = _print_results(results, show_all=show_all,
                                repos_with_litellm=repos_with_litellm,
                                total_repos_scanned=total_repos_scanned)

    if report:
        md = _build_report(results, org=org, user=user,
                           repos_with_litellm=repos_with_litellm,
                           total_repos_scanned=total_repos_scanned)
        report.write_text(md)
        console.print(f"[green]Report written to:[/green] {report}")

    raise typer.Exit(exit_code)


if __name__ == "__main__":
    app()
