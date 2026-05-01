# security-workflows

Centralised reusable GitHub Actions for redactolabs repos. One change here
rolls out to every repo that consumes it.

## What's inside

| Workflow | Purpose |
|---|---|
| `gitleaks.yml` | Secret scanning (gitleaks). Runs on every push and PR. |

## How to consume

Add a small stub workflow to your repo:

```yaml
# .github/workflows/secrets.yml
name: secret scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    uses: redactolabs/security-workflows/.github/workflows/gitleaks.yml@v1
```

That's it. Push to your repo and the workflow appears in Actions.

### Optional: per-repo allowlist

If your repo has known false positives (seed data, fixtures, migrations
with hash-like strings), drop a `.gitleaks.toml` in your repo root.
The workflow auto-detects it. See `.gitleaks.toml` in this repo for a
sensible baseline.

### Optional: pin a specific gitleaks version

```yaml
jobs:
  scan:
    uses: redactolabs/security-workflows/.github/workflows/gitleaks.yml@v1
    with:
      gitleaks-version: "8.18.4"
```

## Versioning

We use semver tags. Consumers should pin to a major version:

- `@v1` — current major. Stable, picks up patch + minor updates.
- `@v1.0.0` — exact version. Pin here for the most paranoid environments.
- `@main` — bleeding edge. **Don't use** in production repos.

When a breaking change lands, we bump to `v2` and consumers migrate on
their own schedule.

## Making a release

```bash
# After landing a change to main:
git tag -a v1.0.1 -m "patch description"
git push origin v1.0.1

# Move the v1 floating tag to the new release:
git tag -fa v1 -m "track latest v1.x"
git push origin v1 --force
```

The `v1` tag is a moving pointer; pinned tags like `v1.0.1` are immutable.

## Required status check

After a consumer repo runs the workflow at least once:

1. Repo Settings → Branches → Add rule for `main`
2. Enable **Require status checks to pass before merging**
3. Search "gitleaks" and check it
4. Optionally enable **Require a pull request before merging**

This turns the workflow from advisory into actual enforcement.

## Org-level settings (one-time, by org admin)

This repo's workflow can be called by any private repo in the org IF:

1. This repo is **public**, OR
2. This repo is private AND its **Settings → Actions → General → Access**
   is set to "Accessible from repositories in the redactolabs organization."

Public is simpler and recommended — the workflow YAML doesn't reveal
anything sensitive.
