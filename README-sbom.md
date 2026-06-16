# SBOM Scanning — Jenkins Shared Library

Centralized SBOM generation + Dependency-Track publishing for all Redacto
repos. This is the Jenkins counterpart to the gitleaks reusable workflow:
one implementation, every repo onboards with a few lines.

It lives in `security-workflows` alongside the GitHub Actions workflows. The
two don't collide — GitHub Actions reads `.github/`, Jenkins reads `vars/`.

## Layout

```
security-workflows/
├── .github/workflows/gitleaks.yml   # GitHub Actions (existing)
├── vars/
│   ├── sbomScan.groovy              # full standalone pipeline  ← most repos
│   └── sbomStage.groovy             # embeddable stage          ← repos with own Jenkinsfile
└── README-sbom.md                   # this file
```

## One-time Jenkins registration

Manage Jenkins → System → **Global Trusted Pipeline Libraries** → Add:

| Field | Value |
|---|---|
| Name | `redacto-security` |
| Default version | `v1` (a git tag — see "Versioning") |
| Retrieval method | Modern SCM → Git |
| Project Repository | `https://github.com/redactolabs/security-workflows.git` |
| Credentials | `github-pat` (needs read access to this repo) |
| Load implicitly | **off** (we want explicit `@Library`) |
| Allow default version to be overridden | on (lets a job pin a tag) |

Trusted (not Untrusted) so it runs without sandbox restrictions. Because
trusted libraries execute unsandboxed Groovy on the controller, protect this
repo: require PR review on `main`, and consume a **tag**, not a moving branch.

## Onboarding a repo (the "three lines")

Create a Pipeline job per repo (`sbom-<repo>`), Definition = Pipeline script:

```groovy
@Library('redacto-security@v1') _
sbomScan(repo: 'redfront', branch: 'staging')
```

That's it. Override defaults as needed:

```groovy
@Library('redacto-security@v1') _
sbomScan(
    repo:           'consent-server',
    branch:         'staging',
    projectName:    'consent-server',     // defaults to repo
    projectVersion: 'staging',            // defaults to branch
    gitCredentials: 'github-pat-sbom',    // see "Credentials" below
    syftVersion:    'v1.45.1'
)
```

For a repo that already has its own Jenkinsfile (redfront), add a stage
instead — see the header of `vars/sbomStage.groovy`.

## Bulk rollout

Creating ~45 jobs by hand is tedious. Two scalable options (pick when ready):

1. **Job DSL seed job** (needs the Job DSL plugin): one seed job reads a repo
   list and generates all `sbom-*` jobs. Onboarding a new repo = add one line
   to the list and re-run the seed.
2. **Folder + a shared job template** if you prefer the UI.

Don't bulk-roll until the library is proven on one repo via `@Library`.

## Credentials note (do before real rollout)

The pilot used `github-pat-sbom` (a personal token) because the service token
`github-pat` couldn't see `redfront`. For durable automation, give the
**service** token (`github-pat`) read access to the target repos and switch
the default — otherwise jobs break when the personal token rotates.

## Versioning

Mirror the gitleaks `@v1` convention. After testing on `main`:

```
git tag v1 && git push origin v1
```

Move the tag forward on releases (`git tag -f v1 && git push -f origin v1`),
or cut `v2` for breaking changes and bump consumers deliberately.

## Hardening backlog (deferred, not blocking)

- Bake `alpine + syft` into an image in your registry so builds don't depend
  on the `get.anchore.io` download each run.
- Enable build gating (`failedTotalCritical: 1`) once the initial finding
  backlog is triaged — start report-only.
- Revisit the DT security-group rule (currently VPC-CIDR) → node SG.
