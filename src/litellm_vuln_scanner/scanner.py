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
class WorkflowRunFinding:
    repo:          str
    workflow_name: str
    run_id:        int
    run_url:       str
    started_at:    datetime
    conclusion:    str | None
    head_branch:   str


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
    """Return [(version_or_constraint, raw_line), ...] for litellm entries."""
    results: list[tuple[str, str]] = []

    if "poetry.lock" in filepath or "uv.lock" in filepath:
        for block in re.finditer(
            r'name\s*=\s*"litellm".*?(?=\n\[\[|\n\[|\Z)', content, re.DOTALL
        ):
            ver = _LOCK_VERSION_RE.search(block.group())
            if ver:
                results.append((ver.group("ver"), block.group()[:120]))
    else:
        for line in content.splitlines():
            if "litellm" not in line.lower():
                continue
            m = _LITELLM_PIN_RE.search(line)
            results.append((m.group("ver") if m else "(unparsed)", line.strip()))

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
    ) -> set[str]:
        """
        Single broad code search for 'litellm' in the given scope, filtered
        client-side to dependency-file basenames. Issues ONE query instead of
        one-per-filename, keeping well within the 10 req/min search rate limit.
        """
        scope = f"org:{org}" if org else f"user:{user}"
        repos: set[str] = set()
        for item in self._code_search(f"litellm {scope}"):
            basename = item["path"].split("/")[-1]
            if basename in _DEPENDENCY_BASENAMES:
                repos.add(item["repository"]["full_name"])
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

    # ── Workflow run validation ────────────────────────────────────────────────

    def check_workflow_runs(self, repo: str) -> list[WorkflowRunFinding]:
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
                runs.append(WorkflowRunFinding(
                    repo=repo,
                    workflow_name=run.get("name") or run.get("display_title", ""),
                    run_id=run["id"],
                    run_url=run.get("html_url", ""),
                    started_at=started_at,
                    conclusion=run.get("conclusion"),
                    head_branch=run.get("head_branch", ""),
                ))
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

    def scan_repo(self, repo: str, check_runs: bool = True) -> ScanResult:
        """
        Scan a single repo. GraphQL is used for the main dependency files;
        REST fills in subdirectory paths and workflow files.
        When check_runs=True, repos with COMPROMISED or UNPINNED findings are
        also checked for Actions runs during the compromise window.
        """
        # Primary: GraphQL batch fetch for standard dep files
        batch_result = self.fetch_files_batch([repo])
        file_map = batch_result.get(repo, {})

        # Supplement: REST for subdirectory requirements paths + workflow files
        extra_paths = [
            p for p in DEPENDENCY_FILES if p not in _GRAPHQL_FILES
        ]
        try:
            extra_paths += self._list_workflow_files(repo)
        except httpx.HTTPStatusError:
            pass

        for path in extra_paths:
            if path not in file_map:
                file_map[path] = self._fetch_file_rest(repo, path)

        result = self._analyze_files(repo, file_map)

        if check_runs and any(
            f.kind in (FindingKind.COMPROMISED, FindingKind.UNPINNED)
            for f in result.findings
        ):
            try:
                result.workflow_runs = self.check_workflow_runs(repo)
            except httpx.HTTPStatusError:
                pass

        return result
