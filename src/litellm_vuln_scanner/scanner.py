"""Core scanner logic for detecting compromised litellm versions."""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

import httpx

# Versions confirmed compromised via PyPI supply chain attack (2026-03-23)
# Reference: https://github.com/BerriAI/litellm/issues/24518
COMPROMISED_VERSIONS = {"1.82.7", "1.82.8"}

# Window during which the compromised packages were live on PyPI.
COMPROMISE_WINDOW_START = datetime(2026, 3, 23, 0, 0, 0, tzinfo=timezone.utc)
COMPROMISE_WINDOW_END   = datetime(2026, 3, 25, 0, 0, 0, tzinfo=timezone.utc)

# Dependency files to deep-scan in each repo
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
    # Script/Makefile installs (e.g. `uv tool install litellm[proxy]`)
    "Makefile",
]

# Basenames used to filter broad code-search results client-side
_DEPENDENCY_BASENAMES = {f.split("/")[-1] for f in DEPENDENCY_FILES}

# Files fetched per repo via GraphQL batch queries.
# Omits subdirectory variants (requirements/base.txt etc.) — those are
# checked via REST fallback only when the broad files show litellm.
_GRAPHQL_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "Makefile",
]

# Repos fetched per GraphQL batch request.
# GitHub GraphQL complexity budget is 500 000 nodes/hour; 20 repos × 9 files
# = 180 nodes per request, well within budget.
_GRAPHQL_BATCH_SIZE = 20

_LITELLM_PIN_RE = re.compile(
    r"litellm\s*[=~^<>!]+\s*(?P<ver>[0-9]+\.[0-9]+\.[0-9]+[^\s,;\"']*)",
    re.IGNORECASE,
)
_LOCK_VERSION_RE = re.compile(r'^version\s*=\s*"(?P<ver>[^"]+)"', re.MULTILINE)

# ── Log analysis patterns ──────────────────────────────────────────────────────

# pip: "Successfully installed litellm-1.82.7 ..."
_PIP_INSTALLED_RE = re.compile(
    r"Successfully installed\b.*?\blitellm-(?P<ver>[0-9]+\.[0-9]+\.[0-9]+\S*)",
    re.IGNORECASE,
)
# pip: "Collecting litellm==1.82.7" or "Downloading litellm-1.82.7"
_PIP_COLLECTING_RE = re.compile(
    r"(?:Collecting|Downloading)\s+litellm[-=](?P<ver>[0-9]+\.[0-9]+\.[0-9]+\S*)",
    re.IGNORECASE,
)
# uv: "   + litellm==1.82.7" (uv sync/add output)
_UV_ADDED_RE = re.compile(
    r"\+\s+litellm[=@]?(?P<ver>[0-9]+\.[0-9]+\.[0-9]+\S*)",
    re.IGNORECASE,
)
# Any line that clearly invokes a package installer with litellm
_INSTALLER_CMD_RE = re.compile(
    r"(?:pip|pip3|uv pip|uv sync|uv add|poetry install|pipenv install)"
    r".*litellm|litellm.*(?:pip|uv)",
    re.IGNORECASE,
)

# Script/Makefile: `uv tool install litellm[proxy]`, `pip install litellm`, etc.
# These indicate litellm is installed as a system tool (no lockfile), making
# version pinning impossible to verify from the repo alone.
_SCRIPT_INSTALL_RE = re.compile(
    r"(?:uv\s+tool\s+(?:install|run)|pip3?\s+install|poetry\s+add)\s+\S*litellm",
    re.IGNORECASE,
)

# Basenames of files where script-install patterns are meaningful
_SCRIPT_BASENAMES = {"Makefile", "makefile"}

# Lines to collect as context (cap to avoid huge output)
_MAX_CONTEXT_LINES = 5


# ── Rate limit handling ───────────────────────────────────────────────────────

def _rate_limit_sleep(resp: httpx.Response) -> None:
    """
    Inspect GitHub rate-limit response headers and sleep as needed.

    GitHub uses two rate-limit mechanisms:
    - Primary:   X-RateLimit-Remaining / X-RateLimit-Reset (per resource bucket,
                 e.g. 5 000 REST req/hr, 10 search req/min)
    - Secondary: Retry-After (abuse / concurrency protection, returned on 403/429)

    This function is called both as an httpx response hook (for proactive
    primary-limit sleeping) and after detecting 403/429 (for secondary limits).
    """
    # Secondary rate limit: Retry-After takes absolute priority
    retry_after = resp.headers.get("Retry-After")
    if retry_after and resp.status_code in (403, 429):
        time.sleep(float(retry_after) + 1)
        return

    # Primary rate limit: sleep until reset when the bucket is exhausted
    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset      = resp.headers.get("X-RateLimit-Reset")
    if remaining is not None and int(remaining) == 0 and reset is not None:
        wait = max(1.0, float(reset) - time.time() + 1)
        time.sleep(wait)


# ── Data models ───────────────────────────────────────────────────────────────

class FindingKind(str, Enum):
    COMPROMISED = "COMPROMISED"
    UNPINNED    = "UNPINNED"
    LOCKFILE    = "LOCKFILE"


@dataclass
class Finding:
    repo:     str
    filepath: str
    kind:     FindingKind
    version:  str
    raw_line: str = ""


@dataclass
class JobAnalysis:
    """Log analysis for a single GitHub Actions job."""
    job_id:           int
    job_name:         str
    job_url:          str
    conclusion:       str | None
    # Did the job install any Python packages at all?
    ran_installer:    bool = False
    # Was litellm specifically installed?
    installed_litellm: bool = False
    # Resolved version if we could determine it from log output
    resolved_version: str | None = None
    # Matching log lines (capped) for evidence
    evidence_lines:   list[str] = field(default_factory=list)


def analyze_log(log_text: str) -> tuple[bool, bool, str | None, list[str]]:
    """
    Parse raw job log text for litellm installation evidence.

    Returns:
        ran_installer:     True if any pip/uv/poetry invocation was detected
        installed_litellm: True if litellm was specifically installed
        resolved_version:  Version string if determinable from output
        evidence_lines:    Relevant log lines (up to _MAX_CONTEXT_LINES)
    """
    ran_installer = False
    installed_litellm = False
    resolved_version: str | None = None
    evidence: list[str] = []

    for line in log_text.splitlines():
        # Strip GitHub Actions timestamp prefix (e.g. "2026-03-23T10:00:00.0000000Z ")
        clean = re.sub(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s*", "", line).strip()
        if not clean:
            continue

        # Detect installer invocations
        if _INSTALLER_CMD_RE.search(clean):
            ran_installer = True
            if len(evidence) < _MAX_CONTEXT_LINES:
                evidence.append(clean)

        # pip: successfully installed
        m = _PIP_INSTALLED_RE.search(clean)
        if m:
            installed_litellm = True
            resolved_version = m.group("ver")
            if len(evidence) < _MAX_CONTEXT_LINES:
                evidence.append(clean)
            continue

        # pip: collecting / downloading
        m = _PIP_COLLECTING_RE.search(clean)
        if m:
            installed_litellm = True
            if resolved_version is None:
                resolved_version = m.group("ver")
            if len(evidence) < _MAX_CONTEXT_LINES:
                evidence.append(clean)
            continue

        # uv: + litellm==X
        m = _UV_ADDED_RE.search(clean)
        if m:
            ran_installer = True
            installed_litellm = True
            if resolved_version is None:
                resolved_version = m.group("ver")
            if len(evidence) < _MAX_CONTEXT_LINES:
                evidence.append(clean)

    return ran_installer, installed_litellm, resolved_version, evidence


@dataclass
class WorkflowRunFinding:
    repo:          str
    workflow_name: str
    run_id:        int
    run_url:       str
    started_at:    datetime
    conclusion:    str | None
    head_branch:   str
    jobs:          list[JobAnalysis] = field(default_factory=list)


@dataclass
class ScanResult:
    repo:           str
    findings:       list[Finding]            = field(default_factory=list)
    scanned_files:  list[str]                = field(default_factory=list)
    workflow_runs:  list[WorkflowRunFinding] = field(default_factory=list)
    error:          str | None               = None


# ── Content parsing ───────────────────────────────────────────────────────────

def _decode_content(encoded: str) -> str:
    return base64.b64decode(encoded.replace("\n", "")).decode("utf-8", errors="replace")


def _extract_versions(filepath: str, content: str) -> list[tuple[str, str]]:
    """
    Return [(version_or_constraint, raw_line), ...] for litellm entries.

    Rules per file type:
    - Lock files (uv.lock, poetry.lock): extract the resolved version block
    - Makefile / .sh scripts: only report lines that invoke an installer
    - Dependency declarations (requirements.txt, pyproject.toml, etc.):
        only report lines with an actual version specifier
    - Everything else (README, docs, configs): skip — no actionable findings
    """
    results: list[tuple[str, str]] = []
    basename = filepath.split("/")[-1]

    if "poetry.lock" in filepath or "uv.lock" in filepath:
        # Extract the locked version from the package block
        for block in re.finditer(
            r'name\s*=\s*"litellm".*?(?=\n\[\[|\n\[|\Z)', content, re.DOTALL
        ):
            ver = _LOCK_VERSION_RE.search(block.group())
            if ver:
                results.append((ver.group("ver"), block.group()[:120]))

    elif basename in _SCRIPT_BASENAMES or filepath.endswith(".sh"):
        # Makefile / shell scripts: only flag actual install invocations
        for line in content.splitlines():
            if "litellm" not in line.lower():
                continue
            if _SCRIPT_INSTALL_RE.search(line):
                m = _LITELLM_PIN_RE.search(line)
                results.append((m.group("ver") if m else "(script install, no pin)", line.strip()))

    elif basename in _DEPENDENCY_BASENAMES or filepath.startswith(".github/workflows/"):
        # Dependency declarations and workflow YAML: report version pins and
        # bare `litellm` dependency lines (completely unpinned).
        for line in content.splitlines():
            stripped = line.strip()
            if "litellm" not in stripped.lower():
                continue
            # Skip comment lines
            if stripped.startswith(("#", "//", "--")):
                continue
            m = _LITELLM_PIN_RE.search(stripped)
            if m:
                results.append((m.group("ver"), stripped))
            elif re.match(r"^litellm\s*(?:\[.*?\])?\s*$", stripped, re.IGNORECASE):
                # Bare `litellm` or `litellm[proxy]` with no version constraint
                results.append(("(no version constraint)", stripped))

    # All other files (README, docs, config, etc.): no findings returned

    return results


def _classify(version: str) -> FindingKind:
    clean = re.sub(r"[=~^<>!]", "", version).strip().split(",")[0]
    return FindingKind.COMPROMISED if clean in COMPROMISED_VERSIONS else FindingKind.UNPINNED


# ── Scanner ───────────────────────────────────────────────────────────────────

class GitHubScanner:
    """Scans GitHub repositories for compromised litellm versions."""

    def __init__(self, token: str, timeout: float = 30.0):
        self._token = token
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=timeout,
            # Proactively sleep when the primary rate-limit bucket is exhausted
            event_hooks={"response": [_rate_limit_sleep]},
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ── Low-level request helpers ─────────────────────────────────────────────

    def _get(self, url: str, **kwargs) -> httpx.Response:
        """
        GET with automatic retry on secondary rate limits (403/429 + Retry-After).
        The primary rate-limit hook handles sleep before we see the response;
        this loop handles the retry after secondary-limit sleeps.
        """
        while True:
            resp = self._client.get(url, **kwargs)
            if resp.status_code in (403, 429) and resp.headers.get("Retry-After"):
                # Hook already slept; retry
                continue
            return resp

    def _graphql(self, query: str, variables: dict | None = None) -> dict:
        """
        Execute a GitHub GraphQL query. Retries on secondary rate limits.
        Returns the 'data' dict from the response.
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        while True:
            resp = httpx.post(
                "https://api.github.com/graphql",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
                timeout=60.0,
            )
            _rate_limit_sleep(resp)
            if resp.status_code in (403, 429) and resp.headers.get("Retry-After"):
                continue
            resp.raise_for_status()
            body = resp.json()
            if "errors" in body:
                # Surface GraphQL errors but don't crash — caller handles None data
                raise httpx.HTTPStatusError(
                    str(body["errors"]), request=resp.request, response=resp
                )
            return body.get("data", {})

    # ── Repo listing ──────────────────────────────────────────────────────────

    def iter_org_repos(self, org: str) -> Iterator[str]:
        page = 1
        while True:
            resp = self._get(f"/orgs/{org}/repos",
                             params={"per_page": 100, "page": page, "type": "all"})
            resp.raise_for_status()
            repos = resp.json()
            if not repos:
                break
            for r in repos:
                yield r["full_name"]
            if len(repos) < 100:
                break
            page += 1

    def iter_user_repos(self) -> Iterator[str]:
        """Yield repos owned by the authenticated user (includes private repos)."""
        page = 1
        while True:
            resp = self._get("/user/repos",
                             params={"per_page": 100, "page": page, "type": "owner"})
            resp.raise_for_status()
            repos = resp.json()
            if not repos:
                break
            for r in repos:
                yield r["full_name"]
            if len(repos) < 100:
                break
            page += 1

    def iter_public_user_repos(self, username: str) -> Iterator[str]:
        """Yield public repos for any GitHub user by username."""
        page = 1
        while True:
            resp = self._get(f"/users/{username}/repos",
                             params={"per_page": 100, "page": page, "type": "owner"})
            resp.raise_for_status()
            repos = resp.json()
            if not repos:
                break
            for r in repos:
                yield r["full_name"]
            if len(repos) < 100:
                break
            page += 1

    # ── Code search (REST) ────────────────────────────────────────────────────

    def _code_search(self, query: str) -> list[dict]:
        """Paginated GitHub code search with automatic rate-limit retry."""
        items: list[dict] = []
        page = 1
        while True:
            resp = self._get("/search/code",
                             params={"q": query, "per_page": 100, "page": page})
            if resp.status_code == 422:
                break
            if resp.status_code in (403, 429):
                # Secondary limit: hook slept, retry
                continue
            resp.raise_for_status()
            batch = resp.json().get("items", [])
            items.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return items

    def search_repos_with_litellm(
        self, *, org: str | None = None, user: str | None = None
    ) -> dict[str, set[str]]:
        """
        Broad code search for 'litellm' in any file in the given scope.
        Returns {repo_full_name: {file_paths_where_litellm_was_found}} for
        every repo that mentions litellm — docs, configs, scripts, dep files,
        etc. — so the deep-scanner decides what's actionable.
        Issues ONE query to stay within the 10 req/min search rate limit.
        """
        scope = f"org:{org}" if org else f"user:{user}"
        repos: dict[str, set[str]] = {}
        for item in self._code_search(f"litellm {scope}"):
            repo = item["repository"]["full_name"]
            repos.setdefault(repo, set()).add(item["path"])
        return repos

    def code_search_compromised(
        self, *, org: str | None = None, user: str | None = None
    ) -> list[Finding]:
        """Fast search for exact pins to compromised versions."""
        findings: list[Finding] = []
        scope = f"org:{org}" if org else f"user:{user}"
        for ver in COMPROMISED_VERSIONS:
            for item in self._code_search(f"litellm=={ver} {scope}"):
                findings.append(Finding(
                    repo=item["repository"]["full_name"],
                    filepath=item["path"],
                    kind=FindingKind.COMPROMISED,
                    version=ver,
                    raw_line=f"litellm=={ver}",
                ))
        return findings

    # ── GraphQL batch file fetching ───────────────────────────────────────────

    def _build_file_fragment(self, file_alias: str, path: str) -> str:
        """GraphQL fragment for a single file expression."""
        return f'{file_alias}: object(expression: "HEAD:{path}") {{ ... on Blob {{ text }} }}'

    def fetch_files_batch(
        self, repos: list[str], files: list[str] = _GRAPHQL_FILES
    ) -> dict[str, dict[str, str | None]]:
        """
        Fetch dependency file contents for multiple repos in a single GraphQL
        query, batched in groups of _GRAPHQL_BATCH_SIZE.

        Returns: {repo_full_name: {filepath: content_or_None}}
        """
        results: dict[str, dict[str, str | None]] = {}

        for i in range(0, len(repos), _GRAPHQL_BATCH_SIZE):
            batch = repos[i : i + _GRAPHQL_BATCH_SIZE]
            repo_fragments: list[str] = []

            for j, full_name in enumerate(batch):
                owner, name = full_name.split("/", 1)
                # Sanitise name for use as a GraphQL alias (no hyphens/dots)
                alias = f"r{j}"
                file_fragments = "\n        ".join(
                    self._build_file_fragment(f"f{k}", path)
                    for k, path in enumerate(files)
                )
                repo_fragments.append(
                    f'{alias}: repository(owner: "{owner}", name: "{name}") {{\n'
                    f"        {file_fragments}\n"
                    f"      }}"
                )

            query = "{\n  " + "\n  ".join(repo_fragments) + "\n}"

            try:
                data = self._graphql(query)
            except Exception:
                # GraphQL failed for this batch — fall back to REST for these repos
                for full_name in batch:
                    results[full_name] = {f: self._fetch_file_rest(full_name, f) for f in files}
                continue

            for j, full_name in enumerate(batch):
                alias = f"r{j}"
                repo_data = data.get(alias) or {}
                file_map: dict[str, str | None] = {}
                for k, path in enumerate(files):
                    node = repo_data.get(f"f{k}") or {}
                    file_map[path] = node.get("text")
                results[full_name] = file_map

        return results

    # ── REST file fetching (fallback / subdirectory paths) ────────────────────

    def _fetch_file_rest(self, repo: str, path: str) -> str | None:
        resp = self._get(f"/repos/{repo}/contents/{path}")
        if resp.status_code in (404, 403):
            return None
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return None
        return _decode_content(data.get("content", ""))

    def _list_workflow_files(self, repo: str) -> list[str]:
        resp = self._get(f"/repos/{repo}/contents/.github/workflows")
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

    # ── Job log analysis ──────────────────────────────────────────────────────

    def fetch_job_logs(self, repo: str, job_id: int) -> str:
        """
        Fetch plain-text log for a single job.
        The API returns a 302 redirect; httpx follows it automatically.
        Returns empty string on 404/403 (logs expired or no access).
        """
        resp = self._client.get(
            f"/repos/{repo}/actions/jobs/{job_id}/logs",
            follow_redirects=True,
        )
        if resp.status_code in (404, 403, 410):
            return ""
        resp.raise_for_status()
        return resp.text

    def analyze_run_jobs(
        self, repo: str, run_id: int
    ) -> list[JobAnalysis]:
        """
        List all jobs for a run, fetch their logs, and analyse each for
        evidence of litellm installation.
        """
        resp = self._get(
            f"/repos/{repo}/actions/runs/{run_id}/jobs",
            params={"per_page": 100, "filter": "all"},
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()

        analyses: list[JobAnalysis] = []
        for job in resp.json().get("jobs", []):
            job_id   = job["id"]
            job_name = job.get("name", "")
            job_url  = job.get("html_url", "")
            conclusion = job.get("conclusion")

            log_text = self.fetch_job_logs(repo, job_id)
            ran_installer, installed_litellm, resolved_version, evidence = analyze_log(log_text)

            analyses.append(JobAnalysis(
                job_id=job_id,
                job_name=job_name,
                job_url=job_url,
                conclusion=conclusion,
                ran_installer=ran_installer,
                installed_litellm=installed_litellm,
                resolved_version=resolved_version,
                evidence_lines=evidence,
            ))

        return analyses

    # ── Workflow run validation ────────────────────────────────────────────────

    def check_workflow_runs(self, repo: str, check_logs: bool = True) -> list[WorkflowRunFinding]:
        """Return Actions runs that started during the compromise window."""
        created_filter = (
            f"{COMPROMISE_WINDOW_START.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            f".."
            f"{COMPROMISE_WINDOW_END.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        runs: list[WorkflowRunFinding] = []
        page = 1
        while True:
            resp = self._get(
                f"/repos/{repo}/actions/runs",
                params={"created": created_filter, "per_page": 100, "page": page},
            )
            if resp.status_code in (403, 404):
                break
            resp.raise_for_status()
            batch = resp.json().get("workflow_runs", [])
            if not batch:
                break
            for run in batch:
                raw = run.get("run_started_at") or run.get("created_at", "")
                try:
                    started_at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    started_at = COMPROMISE_WINDOW_START

                run_finding = WorkflowRunFinding(
                    repo=repo,
                    workflow_name=run.get("name") or run.get("display_title", ""),
                    run_id=run["id"],
                    run_url=run.get("html_url", ""),
                    started_at=started_at,
                    conclusion=run.get("conclusion"),
                    head_branch=run.get("head_branch", ""),
                )
                if check_logs:
                    run_finding.jobs = self.analyze_run_jobs(repo, run["id"])
                runs.append(run_finding)
            if len(batch) < 100:
                break
            page += 1
        return runs

    # ── Per-repo scanning ─────────────────────────────────────────────────────

    def _analyze_files(
        self, repo: str, file_map: dict[str, str | None]
    ) -> ScanResult:
        """Build a ScanResult from a {filepath: content} map."""
        result = ScanResult(repo=repo)
        for filepath, content in file_map.items():
            if not content or "litellm" not in content.lower():
                continue
            result.scanned_files.append(filepath)
            for version, raw_line in _extract_versions(filepath, content):
                kind = _classify(version)
                if "poetry.lock" in filepath or "uv.lock" in filepath:
                    kind = FindingKind.LOCKFILE
                result.findings.append(Finding(
                    repo=repo, filepath=filepath,
                    kind=kind, version=version, raw_line=raw_line,
                ))
        return result

    def scan_repo(
        self,
        repo: str,
        check_runs: bool = True,
        check_logs: bool = True,
        extra_files: set[str] | None = None,
    ) -> ScanResult:
        """
        Scan a single repo. GraphQL is used for the main dependency files;
        REST fills in subdirectory paths, workflow files, and any additional
        paths surfaced by code search.
        When check_runs=True, repos with COMPROMISED or UNPINNED findings are
        also checked for Actions runs during the compromise window.
        """
        # Primary: GraphQL batch fetch for standard dep files
        batch_result = self.fetch_files_batch([repo])
        file_map = batch_result.get(repo, {})

        # Supplement: REST for subdirectory requirements paths + workflow files
        # + any additional files from code search that aren't in _GRAPHQL_FILES
        extra_paths = [
            p for p in DEPENDENCY_FILES if p not in _GRAPHQL_FILES
        ]
        try:
            extra_paths += self._list_workflow_files(repo)
        except httpx.HTTPStatusError:
            pass
        if extra_files:
            extra_paths += [p for p in extra_files if p not in file_map]

        for path in extra_paths:
            if path not in file_map:
                file_map[path] = self._fetch_file_rest(repo, path)

        result = self._analyze_files(repo, file_map)

        if check_runs and any(
            f.kind in (FindingKind.COMPROMISED, FindingKind.UNPINNED)
            for f in result.findings
        ):
            try:
                result.workflow_runs = self.check_workflow_runs(repo, check_logs=check_logs)
            except httpx.HTTPStatusError:
                pass

        return result
