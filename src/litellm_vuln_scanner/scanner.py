"""Core scanner logic for detecting compromised litellm versions."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator

import httpx

# Versions confirmed compromised via PyPI supply chain attack (2026-03-23)
# Reference: https://github.com/BerriAI/litellm/issues/24518
COMPROMISED_VERSIONS = {"1.82.7", "1.82.8"}

# Window during which the compromised packages were live on PyPI.
# Start: when v1.82.7 was first published (2026-03-23)
# End:   conservative end of exposure window (2026-03-24 EOD UTC)
COMPROMISE_WINDOW_START = datetime(2026, 3, 23, 0, 0, 0, tzinfo=timezone.utc)
COMPROMISE_WINDOW_END   = datetime(2026, 3, 25, 0, 0, 0, tzinfo=timezone.utc)

# Dependency files to scan in each repo
DEPENDENCY_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
    "requirements/dev.txt",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
]

# Regex: matches litellm pin to a specific version in requirements-style files
_LITELLM_PIN_RE = re.compile(
    r"litellm\s*[=~^<>!]+\s*(?P<ver>[0-9]+\.[0-9]+\.[0-9]+[^\s,;\"']*)",
    re.IGNORECASE,
)

# Matches TOML-style: "litellm>=1.30.0" or litellm = ">=1.30.0"
_LITELLM_TOML_RE = re.compile(
    r'litellm[^"\']*["\']([^"\']+)["\']|litellm\s*[=~^<>!]+\s*([0-9][^\s,\n]+)',
    re.IGNORECASE,
)

# poetry.lock / uv.lock block
_LOCK_NAME_RE = re.compile(r'^name\s*=\s*"litellm"', re.MULTILINE)
_LOCK_VERSION_RE = re.compile(r'^version\s*=\s*"(?P<ver>[^"]+)"', re.MULTILINE)


class FindingKind(str, Enum):
    COMPROMISED = "COMPROMISED"   # Pinned to 1.82.7 or 1.82.8
    UNPINNED = "UNPINNED"         # Uses litellm but no upper bound — could have resolved to bad version
    LOCKFILE = "LOCKFILE"         # Version found in a lock file


@dataclass
class Finding:
    repo: str
    filepath: str
    kind: FindingKind
    version: str          # Exact version found, or constraint string
    raw_line: str = ""    # The matching line(s) for context


@dataclass
class WorkflowRunFinding:
    """A GitHub Actions run that executed during the compromise window."""
    repo: str
    workflow_name: str
    run_id: int
    run_url: str
    started_at: datetime
    conclusion: str | None   # "success", "failure", "cancelled", None (in-progress)
    head_branch: str


@dataclass
class ScanResult:
    repo: str
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    workflow_runs: list[WorkflowRunFinding] = field(default_factory=list)
    error: str | None = None


def _decode_content(encoded: str) -> str:
    """Decode base64 GitHub API file content."""
    return base64.b64decode(encoded.replace("\n", "")).decode("utf-8", errors="replace")


def _extract_versions_from_content(filepath: str, content: str) -> list[tuple[str, str]]:
    """
    Return list of (version_string, raw_line) tuples found in the file content.
    version_string may be an exact version or a constraint like >=1.30.0.
    """
    results: list[tuple[str, str]] = []

    if "poetry.lock" in filepath or "uv.lock" in filepath:
        # Find the litellm block and extract its version
        for block_match in re.finditer(
            r'name\s*=\s*"litellm".*?(?=\n\[\[|\n\[|\Z)', content, re.DOTALL
        ):
            block = block_match.group()
            ver_match = _LOCK_VERSION_RE.search(block)
            if ver_match:
                results.append((ver_match.group("ver"), block[:120]))
    else:
        for line in content.splitlines():
            if "litellm" not in line.lower():
                continue
            m = _LITELLM_PIN_RE.search(line)
            if m:
                results.append((m.group("ver"), line.strip()))
            else:
                # Capture the line even if we can't parse an exact version
                if re.search(r"litellm", line, re.IGNORECASE):
                    results.append(("(unparsed)", line.strip()))

    return results


def _classify_version(version: str) -> FindingKind:
    """Classify a version string into a FindingKind."""
    # Strip constraint operators to get base version
    clean = re.sub(r"[=~^<>!]", "", version).strip().split(",")[0]
    if clean in COMPROMISED_VERSIONS:
        return FindingKind.COMPROMISED
    return FindingKind.UNPINNED


class GitHubScanner:
    """Scans GitHub repositories for compromised litellm versions."""

    def __init__(self, token: str, timeout: float = 30.0):
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=timeout,
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ── Repo listing ──────────────────────────────────────────────────────────

    def iter_org_repos(self, org: str) -> Iterator[str]:
        """Yield full repo names (org/repo) for all repos in an org."""
        page = 1
        while True:
            resp = self._client.get(
                f"/orgs/{org}/repos",
                params={"per_page": 100, "page": page, "type": "all"},
            )
            resp.raise_for_status()
            repos = resp.json()
            if not repos:
                break
            for r in repos:
                yield r["full_name"]
            if len(repos) < 100:
                break
            page += 1

    def iter_user_repos(self, username: str) -> Iterator[str]:
        """Yield full repo names for all repos owned by a user."""
        page = 1
        while True:
            resp = self._client.get(
                f"/users/{username}/repos",
                params={"per_page": 100, "page": page, "type": "owner"},
            )
            resp.raise_for_status()
            repos = resp.json()
            if not repos:
                break
            for r in repos:
                yield r["full_name"]
            if len(repos) < 100:
                break
            page += 1

    # ── Code search (fast broad pass) ────────────────────────────────────────

    def code_search_compromised(
        self, *, org: str | None = None, user: str | None = None
    ) -> list[Finding]:
        """
        Use GitHub code search to quickly find any exact pins to compromised versions.
        This is faster than per-repo scanning but may miss lockfile resolutions.
        """
        findings: list[Finding] = []
        scope = f"org:{org}" if org else f"user:{user}"

        for ver in COMPROMISED_VERSIONS:
            query = f"litellm=={ver} {scope}"
            resp = self._client.get(
                "/search/code",
                params={"q": query, "per_page": 100},
            )
            if resp.status_code == 422:
                continue  # Query not valid for this scope
            resp.raise_for_status()

            for item in resp.json().get("items", []):
                findings.append(
                    Finding(
                        repo=item["repository"]["full_name"],
                        filepath=item["path"],
                        kind=FindingKind.COMPROMISED,
                        version=ver,
                        raw_line=f"litellm=={ver}",
                    )
                )

        return findings

    # ── Per-file scanning ─────────────────────────────────────────────────────

    def _fetch_file(self, repo: str, path: str) -> str | None:
        """Fetch file content from GitHub. Returns decoded text or None."""
        resp = self._client.get(f"/repos/{repo}/contents/{path}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return None  # It's a directory
        encoded = data.get("content", "")
        return _decode_content(encoded)

    def _list_workflow_files(self, repo: str) -> list[str]:
        """List .yml/.yaml files under .github/workflows/."""
        resp = self._client.get(f"/repos/{repo}/contents/.github/workflows")
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            return []
        return [
            f".github/workflows/{item['name']}"
            for item in data
            if item["name"].endswith((".yml", ".yaml"))
        ]

    # ── Workflow run validation ────────────────────────────────────────────────

    def check_workflow_runs(self, repo: str) -> list[WorkflowRunFinding]:
        """
        Return any GitHub Actions runs for *repo* that started during the
        compromise window (2026-03-23 00:00 UTC – 2026-03-25 00:00 UTC).

        A workflow run during this window on a repo with an unbounded litellm
        dependency means pip/uv may have resolved to the compromised version.
        """
        created_filter = (
            f"{COMPROMISE_WINDOW_START.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            f".."
            f"{COMPROMISE_WINDOW_END.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        runs: list[WorkflowRunFinding] = []
        page = 1

        while True:
            resp = self._client.get(
                f"/repos/{repo}/actions/runs",
                params={
                    "created": created_filter,
                    "per_page": 100,
                    "page": page,
                },
            )
            if resp.status_code in (403, 404):
                break
            resp.raise_for_status()

            data = resp.json()
            batch = data.get("workflow_runs", [])
            if not batch:
                break

            for run in batch:
                started_raw = run.get("run_started_at") or run.get("created_at", "")
                try:
                    started_at = datetime.fromisoformat(
                        started_raw.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    started_at = COMPROMISE_WINDOW_START  # fallback

                runs.append(
                    WorkflowRunFinding(
                        repo=repo,
                        workflow_name=run.get("name") or run.get("display_title", ""),
                        run_id=run["id"],
                        run_url=run.get("html_url", ""),
                        started_at=started_at,
                        conclusion=run.get("conclusion"),
                        head_branch=run.get("head_branch", ""),
                    )
                )

            if len(batch) < 100:
                break
            page += 1

        return runs

    def scan_repo(self, repo: str, check_runs: bool = True) -> ScanResult:
        """
        Scan a single repo for all known dependency file paths.

        When *check_runs* is True (default), repos with COMPROMISED or UNPINNED
        findings are also checked for GitHub Actions runs during the compromise
        window to determine if the bad version may have been installed.
        """
        result = ScanResult(repo=repo)

        # Build the list of files to scan (static + dynamic workflow list)
        files_to_scan = list(DEPENDENCY_FILES)
        try:
            files_to_scan.extend(self._list_workflow_files(repo))
        except httpx.HTTPStatusError:
            pass

        for filepath in files_to_scan:
            try:
                content = self._fetch_file(repo, filepath)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in (404, 403):
                    result.error = str(exc)
                continue

            if content is None or "litellm" not in content.lower():
                continue

            result.scanned_files.append(filepath)

            for version, raw_line in _extract_versions_from_content(filepath, content):
                kind = _classify_version(version)
                # For lock files, always record the finding
                if "poetry.lock" in filepath or "uv.lock" in filepath:
                    kind = FindingKind.LOCKFILE
                result.findings.append(
                    Finding(
                        repo=repo,
                        filepath=filepath,
                        kind=kind,
                        version=version,
                        raw_line=raw_line,
                    )
                )

        # For repos with concerning findings, check whether CI ran during the
        # compromise window — those runs may have pip-installed the bad version.
        if check_runs and any(
            f.kind in (FindingKind.COMPROMISED, FindingKind.UNPINNED)
            for f in result.findings
        ):
            try:
                result.workflow_runs = self.check_workflow_runs(repo)
            except httpx.HTTPStatusError:
                pass

        return result
