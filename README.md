# litellm-vuln-scanner

Scan GitHub organizations and user repos for the **litellm supply chain compromise** (PyPI versions 1.82.7 and 1.82.8, published 2026-03-23).

> **Reference**: [BerriAI/litellm#24518](https://github.com/BerriAI/litellm/issues/24518#issuecomment-4119478134)

## What Was Compromised

The maintainer's PyPI account was hijacked. Malicious code was injected into `litellm` v1.82.7 and v1.82.8 that exfiltrated:

- SSH keys
- Environment variables (API keys, secrets)
- AWS / GCP / Azure / Kubernetes credentials
- Crypto wallet files
- Database passwords
- SSL private keys
- Shell history
- CI/CD configs

Data was encrypted (AES-256-CBC + RSA-4096) and POSTed to an attacker-controlled domain.

**v1.82.8** also dropped `litellm_init.pth` into site-packages, which activates on *any* Python startup — not just litellm imports.

## Quick Local Check

**`litellm_init.pth` activates on *every* Python startup** — including the startup that runs this scanner. Always use the shell one-liner first to confirm Python is clean before running any Python on the machine.

### Step 1: Shell one-liner (no Python, always safe)

```bash
find \
  ~/.local/lib ~/.pyenv/versions ~/.venv \
  /usr/local/lib /usr/lib /opt/homebrew/lib \
  -name "litellm_init.pth" 2>/dev/null \
| while read f; do
    echo "COMPROMISED: $f — remove with: rm '$f'"
  done \
&& echo "litellm_init.pth not found"
```

Uses only `find` — does not start Python. Safe to run on any machine.

### Step 2: Scanner CLI (only after Step 1 confirms clean)

```bash
litellm-scan check-local
```

Checks all Python site-packages (active env, user site, uv tool venvs, common system dirs), `uv tool list`, and `pip show litellm` for compromised versions. Exit codes: `0` = clean, `2` = compromised.

> **Note**: This command starts Python. Only run it after Step 1 confirms no `litellm_init.pth` exists on the machine.

If `litellm_init.pth` is found at any point, **treat the machine as compromised**: remove the file, rotate all secrets, and check cloud audit logs.

## Installation

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
# Run directly without installing (fastest)
uvx --from git+https://github.com/TylerStaplerAtFanatics/litellm-vuln-scanner litellm-scan --help

# Install as a persistent uv tool
uv tool install git+https://github.com/TylerStaplerAtFanatics/litellm-vuln-scanner
litellm-scan --help

# From source (for development)
git clone https://github.com/TylerStaplerAtFanatics/litellm-vuln-scanner
cd litellm-vuln-scanner
uv sync
uv run litellm-scan --help
```

All dependencies are strictly pinned in `uv.lock` for reproducible, trustworthy installs.

## Usage

Requires a GitHub token with `repo` and `read:org` scopes. The tool will auto-detect one from:
1. `GITHUB_TOKEN` / `GH_TOKEN` environment variables
2. The `gh` CLI (`gh auth token`)

```bash
# Check whether the local machine is compromised (run first)
litellm-scan check-local

# Scan an organization
litellm-scan scan --org fanatics-gaming

# Scan personal repos
litellm-scan scan --user myusername

# Scan both
litellm-scan scan --org fanatics-gaming --user myusername

# Fast mode: code search only (skips lockfile scanning)
litellm-scan scan --org fanatics-gaming --fast

# Show all findings including unpinned constraints and lockfile versions
litellm-scan scan --org fanatics-gaming --show-all

# Skip checking GitHub Actions run history (faster, less thorough)
litellm-scan scan --org fanatics-gaming --no-check-runs
```

## Output

The scanner reports three finding types:

| Kind | Meaning | Action |
|------|---------|--------|
| `COMPROMISED` | Exact pin to 1.82.7 or 1.82.8 | Immediate: rotate secrets, upgrade |
| `UNPINNED` | `litellm>=X` with no upper bound | Check if installed between 2026-03-23/24 |
| `LOCKFILE` | Version resolved in poetry.lock / uv.lock | Review resolved version |
| CI run alert | Workflow ran during compromise window | Inspect run logs for resolved version |

For repos with `UNPINNED` dependencies, the scanner also checks GitHub Actions history. Any workflow run between **2026-03-23 and 2026-03-25 UTC** is flagged — those runs may have resolved `pip install litellm` to the compromised version. Inspect the run logs to confirm the actual resolved version.

Exit code is `1` if any `COMPROMISED` findings are present, `0` otherwise (useful in CI).

## Remediation

If compromised versions are found:

1. **Pin to a safe version**: `litellm==1.82.6` (last confirmed clean version on PyPI)
2. **Rotate all secrets** accessible from affected systems
3. **Audit cloud provider logs** for unauthorized access
4. **Check deployed environments** for `litellm_init.pth` in site-packages
5. **Review git history** for unexpected changes made by CI jobs

## License

MIT
