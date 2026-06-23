#!/usr/bin/env groovy
// =============================================================================
// vars/sbomScan.groovy
//
// Complete, standalone SBOM pipeline for Redacto.  Most repos do NOT carry
// their own Jenkinsfile (they deploy via GitOps/ArgoCD), so this library
// provides the WHOLE pipeline.  A per-repo Jenkins job needs only:
//
//     @Library('redacto-security') _
//     sbomScan(repo: 'redfront', branch: 'staging')
//
// What it does (same proven chain as the pilot):
//   1. Spins a Kubernetes agent pod (alpine + Syft installed at pinned version)
//   2. Clones the target repo
//   3. Generates a CycloneDX SBOM with Syft
//   4. Publishes to Dependency-Track (auto-creates the project; upload is
//      fire-and-forget so a busy DT queue can't red the build)
//   5. Archives the SBOM as a build artifact (audit evidence)
//   6. Re-runs weekly so the DT project stays fresh between deploys
//
// Parameters (all optional except `repo`):
//   repo            (req)  GitHub repo name, e.g. 'redfront'
//   branch                 branch to scan          (default 'staging')
//   gitOrg                 GitHub org              (default 'redactolabs')
//   gitCredentials         Jenkins credential id   (default 'github-pat-sbom')
//   projectName            DT project name         (default = repo)
//   projectVersion         DT project version      (default = branch)
//   syftVersion            pinned Syft release      (default 'v1.45.1')
//   weeklyCron             schedule, '' to disable (default 'H 2 * * 1')
// =============================================================================

def call(Map config = [:]) {
    String repo           = config.repo ?: { error("sbomScan: 'repo' is required, e.g. sbomScan(repo: 'redfront')") }()
    String branch         = config.get('branch', 'staging')
    String gitOrg         = config.get('gitOrg', 'redactolabs')
    String gitCredentials = config.get('gitCredentials', 'github-pat-sbom')
    String projectName    = config.get('projectName', repo)
    String projectVersion = config.get('projectVersion', branch)
    String syftVersion    = config.get('syftVersion', 'v1.45.1')
    String weeklyCron     = config.get('weeklyCron', 'H 2 * * 1')

    pipeline {
        agent {
            kubernetes {
                yaml """
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: syft
    image: alpine:3.20
    command: ["sleep"]
    args: ["infinity"]
    resources:
      requests: { memory: "512Mi", cpu: "250m" }
      limits:   { memory: "1Gi" }
"""
            }
        }

        options {
            timestamps()
            timeout(time: 30, unit: 'MINUTES')
            disableConcurrentBuilds()
        }

        triggers {
            // Weekly re-scan so DT re-evaluates the dependency set even if the
            // repo hasn't been rebuilt. DT also re-checks server-side daily;
            // this catches dependency *changes* between deploys.
            cron(weeklyCron)
        }

        stages {
            stage('Checkout') {
                steps {
                    git url: "https://github.com/${gitOrg}/${repo}.git",
                        branch: branch,
                        credentialsId: gitCredentials
                }
            }

            stage('Generate SBOM') {
                steps {
                    container('syft') {
                        sh """
                            set -euo pipefail
                            # Pinned Syft install (no 'latest' — reproducible builds).
                            # NOTE: this pulls from get.anchore.io each run. Next hardening
                            # step is baking alpine+syft into an image in your registry so
                            # builds don't depend on an external download.
                            if ! command -v syft >/dev/null 2>&1; then
                                wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin ${syftVersion}
                            fi
                            syft version
                            # --source-name/--source-version remove the "no explicit name"
                            # warning and make the SBOM metadata match the DT project.
                            syft scan dir:. \\
                                -o cyclonedx-json=sbom.cdx.json \\
                                --source-name '${projectName}' \\
                                --source-version '${projectVersion}'
                        """
                    }
                }
            }

            stage('Publish to Dependency-Track') {
                steps {
                    // URL + API key come from the global Dependency-Track config
                    // (Manage Jenkins -> System).
                    //
                    // synchronous:false = fire-and-forget. The plugin uploads the
                    // BOM and returns; DT processes asynchronously in the background.
                    // We do NOT poll for findings, so a busy DT queue can't fail an
                    // otherwise-successful build (the "polling limit exceeded" red).
                    //
                    // ---- Build gating (enable later, after triaging backlog) ----
                    // Gating REQUIRES synchronous:true (the plugin must wait for
                    // findings to evaluate thresholds). When you turn gating on,
                    // set synchronous:true AND raise the polling timeout, e.g.:
                    //     synchronous: true
                    //     dependencyTrackPollingTimeout: 25   // minutes
                    //     failedTotalCritical: 1              // FAIL on any critical
                    //     unstableTotalCritical: 1            // or yellow instead of red
                    // Start report-only (no thresholds) — which is this default.
                    dependencyTrackPublisher(
                        artifact:           'sbom.cdx.json',
                        projectName:        projectName,
                        projectVersion:     projectVersion,
                        autoCreateProjects: true,
                        synchronous:        false
                    )
                }
            }
        }

        post {
            always {
                archiveArtifacts artifacts: 'sbom.cdx.json',
                                 allowEmptyArchive: true,
                                 fingerprint: true
            }
        }
    }
}
