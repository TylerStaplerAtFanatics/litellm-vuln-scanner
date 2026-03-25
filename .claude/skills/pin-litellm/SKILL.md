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
3. Applies the constraint fix + regenerates lockfiles
4. Creates a branch, commits, and opens a PR
5. **Launches a background task to monitor CI checks and review comments** — the skill is not done until all checks pass and all review feedback is addressed

## Safe Version Constraint

**`1.82.6` is the last confirmed clean version on PyPI.** No clean release after
the attack (`1.82.9`+) exists yet — pin to `==1.82.6` in all cases.

- **Compromised pin** (`==1.82.7` or `==1.82.8`): downgrade to `==1.82.6`
- **Unpinned / unbounded** (`>=X.Y.Z` with no upper bound): pin to `==1.82.6`
- **Script install** (`uv tool install litellm[proxy]`): pin to `==1.82.6`
- **No constraint at all** (bare `litellm`): pin to `==1.82.6`

## Step-by-Step Workflow

### 0. Pre-flight Safety Check

**`litellm_init.pth` activates on every Python startup** — including the Python process
that runs this scanner. Always use the shell one-liner first; only run Python commands
after it confirms the machine is clean.

#### Step A: Shell one-liner — always run this first (no Python)

```bash
find \
  ~/.local/lib ~/.pyenv/versions ~/.venv \
  /usr/local/lib /usr/lib /opt/homebrew/lib \
  -name "litellm_init.pth" 2>/dev/null \
| while read f; do
    echo "🚨 COMPROMISED: $f"
    echo "   Remove with: rm '$f'"
  done \
&& echo "✓ litellm_init.pth not found"
```

Uses only `find` — does not start Python. Safe to run on any machine.

#### Step B: Scanner CLI — only after Step A confirms clean

```bash
litellm-scan check-local
```

Checks all Python site-packages directories (active venv, user site, uv tool venvs,
common system dirs), `uv tool list`, and `pip show litellm` for compromised versions
(1.82.7, 1.82.8). Exits with code 0 (clean) or 2 (compromised).

**If `litellm_init.pth` is found at any point:**
1. Remove it immediately: `rm <path>`
2. Rotate **all secrets** the machine had access to
3. Check cloud audit logs for unauthorized API calls
4. Search deployed containers/environments for the same file

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
# Any constraint  →  litellm==1.82.6
sed -i 's/litellm[>=!<~^].*/litellm==1.82.6/' requirements.txt
# Bare litellm
sed -i 's/^litellm$/litellm==1.82.6/' requirements.txt
```

#### pyproject.toml (PEP 621 dependencies array)

```bash
# "litellm>=X.Y.Z"  →  "litellm==1.82.6"
sed -i 's/"litellm[^"]*"/"litellm==1.82.6"/g' pyproject.toml
```

#### Makefile (uv tool install)

```bash
# uv tool install litellm[proxy]  →  uv tool install "litellm[proxy]==1.82.6"
sed -i 's/uv tool install litellm\(\[proxy\]\)\?/uv tool install "litellm[proxy]==1.82.6"/g' Makefile
```

#### Pipfile

```bash
sed -i 's/litellm = "[^"]*"/litellm = "==1.82.6"/' Pipfile
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

### 5. Regenerate Lockfiles

**Always regenerate and commit lockfiles** — without this, `uv sync --frozen` or
cached CI installs will continue using the old (potentially unsafe) resolved version.

```bash
# uv projects
uv lock
git add uv.lock

# poetry projects
poetry lock --no-update
git add poetry.lock
```

Include the updated lockfile in the same commit as the pyproject.toml change.

### 6. Create the PR

Use the template from Step 3. Make sure PR **title and body both reference `==1.82.6`** —
mismatches between the description and the code will be flagged by automated reviewers
and cause unnecessary back-and-forth.

### 7. Monitor CI and Review Feedback (Background Task)

**The skill is not complete until all checks pass and all review threads are resolved.**
After opening each PR, launch a background monitoring loop:

```bash
REPO="org/repo-name"
PR_NUMBER=<number>

# Poll until checks complete and no open review threads remain
while true; do
  # Check CI status
  STATUS=$(gh pr view $PR_NUMBER --repo $REPO \
    --json statusCheckRollup --jq '.statusCheckRollup | map(.conclusion) | unique | @csv')
  echo "CI status: $STATUS"

  # Check for unresolved inline review comments
  OPEN_COMMENTS=$(gh api repos/$REPO/pulls/$PR_NUMBER/comments \
    --jq '[.[] | select(.resolved == false or .resolved == null)] | length')
  echo "Open review comments: $OPEN_COMMENTS"

  # Also check for review-requested-changes state
  REVIEW_STATE=$(gh pr view $PR_NUMBER --repo $REPO \
    --json reviews --jq '[.reviews[] | select(.state == "CHANGES_REQUESTED")] | length')

  if [[ "$STATUS" == *"FAILURE"* ]] || [[ "$STATUS" == *"failure"* ]]; then
    echo "CI FAILED — fetch logs and fix:"
    gh run list --repo $REPO --json databaseId,status,conclusion,url \
      --jq '[.[] | select(.conclusion == "failure")] | .[0].url'
    break  # exit loop to investigate and fix
  fi

  if [[ "$OPEN_COMMENTS" -gt 0 ]] || [[ "$REVIEW_STATE" -gt 0 ]]; then
    echo "$OPEN_COMMENTS open comment(s) / $REVIEW_STATE change request(s) — address them:"
    gh api repos/$REPO/pulls/$PR_NUMBER/comments \
      --jq '[.[] | {author: .user.login, body: .body, path: .path}]'
    break  # exit loop to address feedback
  fi

  if [[ "$STATUS" == *"SUCCESS"* ]] || [[ "$STATUS" == *"success"* ]]; then
    echo "All checks passed, no open comments — PR is ready to merge."
    break
  fi

  echo "Waiting for checks to complete..."
  sleep 60
done
```

**When CI fails**: fetch the failed job logs, fix the root cause (e.g. wrong version,
missing lockfile update, import errors), amend the commit, force-push, and wait again.

**When review comments appear**: read each comment, apply the fix if valid, or reply
with a clear explanation if declining. Update the PR description to stay consistent
with the code.

**The workflow is complete only when**:
- All CI checks show ✅ success
- Zero unresolved inline review comments
- PR title, body, and code all reference the same version

## Notes

- Always `git diff` before committing to confirm only litellm constraints changed
- Repos using `uv tool install` install litellm globally (not in lockfile) — the Makefile fix is the only mitigation; no lockfile to regenerate
- On macOS, use `sed -i ''` (BSD sed); on Linux use `sed -i` (GNU sed)
