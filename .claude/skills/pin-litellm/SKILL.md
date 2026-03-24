---
name: pin-litellm
description: >
  Create PRs to pin litellm away from compromised versions (1.82.7, 1.82.8)
  based on litellm-vuln-scanner findings. Use when you have scan results showing
  unpinned or compromised litellm and want to automatically fix each affected repo.
---

# Pin litellm Security Fix — PR Creation Skill

Creates GitHub pull requests to pin litellm away from compromised versions
`1.82.7` and `1.82.8` (PyPI supply chain attack, 2026-03-23).

Reference: https://github.com/BerriAI/litellm/issues/24518

## Overview

For each repo with an unpinned or compromised litellm finding, this skill:
1. Determines which files need modification and what change to make
2. Clones the repo to a temp directory
3. Applies the constraint fix
4. Creates a branch, commits, and opens a PR

## Safe Version Constraint

The recommended fix depends on context:
- **Compromised pin** (`==1.82.7` or `==1.82.8`): upgrade to `>=1.82.9`
- **Unpinned / unbounded** (`>=X.Y.Z` with no upper bound): add `!=1.82.7,!=1.82.8`
- **Script install** (`uv tool install litellm[proxy]`): pin to `>=1.82.9`
- **No constraint at all** (bare `litellm`): add `!=1.82.7,!=1.82.8`

## Step-by-Step Workflow

### 1. Get Findings

Either read an existing report file or run the scanner:

```bash
# Option A: run scanner and save report
litellm-scan --org <org> [--user <user>] --show-all --report /tmp/litellm-scan-$(date +%Y%m%d-%H%M).md

# Option B: read existing report
cat /tmp/litellm-scan-report.md
```

Parse the **Unpinned** and **Compromised** tables to extract:
- `repo`: full name (e.g., `my-org/my-repo`)
- `filepath`: file to modify (e.g., `requirements.txt`)
- `constraint`: current value (e.g., `>=1.68.0`, `(script install, no pin)`)

### 2. Fix Logic Per File Type

Apply the appropriate transformation based on the file:

#### requirements.txt / requirements-dev.txt / requirements/*.txt / setup.cfg

```bash
# Unpinned: litellm>=1.0.0  →  litellm>=1.0.0,!=1.82.7,!=1.82.8
sed -i 's/litellm\(>=.*\)/litellm\1,!=1.82.7,!=1.82.8/g' requirements.txt

# Compromised exact pin: litellm==1.82.7  →  litellm>=1.82.9
sed -i 's/litellm==1\.82\.[78]/litellm>=1.82.9/g' requirements.txt

# Bare litellm (no version):  litellm  →  litellm!=1.82.7,!=1.82.8
sed -i 's/^litellm$/litellm!=1.82.7,!=1.82.8/' requirements.txt
```

#### pyproject.toml (PEP 621 dependencies array)

```bash
# In [project] dependencies list:
# "litellm>=1.68.0"  →  "litellm>=1.68.0,!=1.82.7,!=1.82.8"
sed -i 's/"litellm>=\([^"]*\)"/"litellm>=\1,!=1.82.7,!=1.82.8"/g' pyproject.toml

# Poetry-style [tool.poetry.dependencies]:
# litellm = ">=1.68.0"  →  litellm = ">=1.68.0,!=1.82.7,!=1.82.8"
sed -i 's/litellm = "\(>=.*\)"/litellm = "\1,!=1.82.7,!=1.82.8"/g' pyproject.toml
```

#### Makefile (uv tool install)

```bash
# uv tool install litellm[proxy]  →  uv tool install "litellm[proxy]>=1.82.9"
sed -i 's/uv tool install litellm\(\[proxy\]\)\?/uv tool install "litellm[proxy]>=1.82.9"/g' Makefile
```

#### Pipfile

```bash
# litellm = "*"  →  litellm = "!=1.82.7,!=1.82.8"
# litellm = ">=1.0.0"  →  litellm = ">=1.0.0,!=1.82.7,!=1.82.8"
sed -i 's/litellm = "\*"/litellm = "!=1.82.7,!=1.82.8"/' Pipfile
sed -i 's/litellm = "\(>=.*\)"/litellm = "\1,!=1.82.7,!=1.82.8"/' Pipfile
```

### 3. Create the PR

For each repo, execute this sequence:

```bash
REPO="org/repo-name"
BRANCH="security/pin-litellm-cve-2026-03-23"
TMPDIR="/tmp/litellm-pin-fix-$(echo $REPO | tr '/' '-')"

# Clone
gh repo clone "$REPO" "$TMPDIR"
cd "$TMPDIR"

# Create branch
git checkout -b "$BRANCH"

# Apply fix (use the appropriate sed command from Step 2 for each file)
# ...

# Verify the change looks right
git diff

# Commit
git add -A
git commit -m "security: pin litellm away from compromised versions 1.82.7/1.82.8

Supply chain attack on litellm v1.82.7 and v1.82.8 (2026-03-23):
malicious code exfiltrated SSH keys, env vars, API keys, and shell history.
v1.82.8 also dropped litellm_init.pth into site-packages.

Ref: https://github.com/BerriAI/litellm/issues/24518"

# Push and open PR
git push -u origin "$BRANCH"
gh pr create \
  --title "security: pin litellm away from compromised versions 1.82.7/1.82.8" \
  --body "$(cat <<'PREOF'
## Security Fix: litellm Supply Chain Compromise

### Background

On 2026-03-23, the PyPI account for litellm was hijacked and malicious versions
**1.82.7** and **1.82.8** were published. The malware:

- Exfiltrated SSH private keys, shell history, environment variables
- Stole AWS/GCP/Azure credentials and API keys
- v1.82.8 dropped `litellm_init.pth` into Python site-packages (activates on **any** Python startup)

Reference: https://github.com/BerriAI/litellm/issues/24518

### What This PR Does

Adds version exclusions (`!=1.82.7,!=1.82.8`) or upgrades the minimum bound to
`>=1.82.9` so that `pip install` / `uv sync` cannot resolve to a compromised version.

### Action Required

If this repo ran `pip install` or `uv sync` between **2026-03-23 and 2026-03-25**:
1. Check job logs to confirm whether the compromised version was installed
2. Rotate all secrets accessible from that environment
3. Search deployed environments for `litellm_init.pth` in site-packages

### Detected by

[litellm-vuln-scanner](https://github.com/TylerStaplerAtFanatics/litellm-vuln-scanner)
PREOF
)" \
  --label "security" \
  --base main

# Cleanup
cd -
rm -rf "$TMPDIR"
```

### 4. Handle Multiple Repos in Parallel

When there are many repos to fix, process them concurrently:

```bash
# Build a list of repos from the scan report
REPOS=(
  "org/repo-a"
  "org/repo-b"
  "org/repo-c"
)

# Process in parallel (background jobs)
for repo in "${REPOS[@]}"; do
  (
    # Run the clone/fix/PR workflow for each repo
    # Use the Step 3 template above
  ) &
done
wait
echo "All PRs created."
```

## Verification After PRs

After creating PRs, verify they're open:

```bash
gh pr list --search "security pin-litellm" --json url,title,state,repo
```

## Notes

- Always `git diff` before committing to confirm only litellm constraints changed
- If a repo uses `uv.lock` or `poetry.lock`, regenerate the lockfile after updating constraints:
  - uv: `uv lock` then `git add uv.lock`
  - poetry: `poetry lock --no-update` then `git add poetry.lock`
- For repos with CI, the PR will trigger a test run — monitor for failures
- Repos using `uv tool install` install litellm globally (not in lockfile) — the Makefile fix is the only mitigation
