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

Before scanning repos, verify your own machine:

```bash
# Check installed version
pip show litellm

# Look for the malicious .pth file (indicator of compromise)
find $(python3 -c "import site; print(' '.join(site.getsitepackages()))") \
  -name "litellm_init.pth" 2>/dev/null
```

If you find `litellm_init.pth`, **treat the machine as compromised** and rotate all secrets immediately.

## Installation

```bash
# From PyPI (once published)
pip install litellm-vuln-scanner

# From source
git clone https://github.com/TylerStaplerAtFanatics/litellm-vuln-scanner
cd litellm-vuln-scanner
pip install -e .
```

## Usage

Requires a GitHub token with `repo` and `read:org` scopes. The tool will auto-detect one from:
1. `GITHUB_TOKEN` / `GH_TOKEN` environment variables
2. The `gh` CLI (`gh auth token`)

```bash
# Scan an organization
litellm-scan --org fanatics-gaming

# Scan personal repos
litellm-scan --user myusername

# Scan both
litellm-scan --org fanatics-gaming --user myusername

# Fast mode: code search only (skips lockfile scanning)
litellm-scan --org fanatics-gaming --fast

# Show all findings including unpinned constraints and lockfile versions
litellm-scan --org fanatics-gaming --show-all
```

## Output

The scanner reports three finding types:

| Kind | Meaning | Action |
|------|---------|--------|
| `COMPROMISED` | Exact pin to 1.82.7 or 1.82.8 | Immediate: rotate secrets, upgrade |
| `UNPINNED` | `litellm>=X` with no upper bound | Check if installed between 2026-03-23/24 |
| `LOCKFILE` | Version resolved in poetry.lock / uv.lock | Review resolved version |

Exit code is `1` if any `COMPROMISED` findings are present, `0` otherwise (useful in CI).

## Remediation

If compromised versions are found:

1. **Pin to a safe version**: `litellm>=1.82.9` or `litellm==1.82.6`
2. **Rotate all secrets** accessible from affected systems
3. **Audit cloud provider logs** for unauthorized access
4. **Check deployed environments** for `litellm_init.pth` in site-packages
5. **Review git history** for unexpected changes made by CI jobs

## License

MIT
