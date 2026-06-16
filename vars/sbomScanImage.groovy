#!/usr/bin/env groovy
// =============================================================================
// vars/sbomScanImage.groovy
//
// Container-IMAGE SBOM for Redacto. Complements sbomScan (source tree) by
// scanning what's actually DEPLOYED — base-image OS packages (openssl, glibc,
// busybox, system libs) that never appear in package.json and are invisible to
// a source scan.
//
//   @Library('redacto-security') _
//   sbomScanImage(repo: 'redfront', service: 'web', env: 'staging')
//
// How it works:
//   1. Clones the gitops repo (read-only) and reads the DEPLOYED image ref from
//        gitops/<repo>/<env>/values-aws-<service>.yaml
//      (image.registry / image.repository / image.tag) — so the SBOM reflects
//      what ArgoCD actually deployed, not a build-time guess.
//   2. Logs in to ECR using the agent pod's IRSA role (no stored creds).
//   3. Syft-scans the image -> CycloneDX.
//   4. Publishes to Dependency-Track as  <repo> : <env>-image.
//
// PREREQUISITE (one-time, platform/Terraform):
//   The Jenkins agent pod's service account ('jenkins' in ns 'redacto') needs
//   an IRSA role with ECR read:
//     ecr:GetAuthorizationToken (resource *)
//     ecr:BatchGetImage, ecr:GetDownloadUrlForLayer, ecr:BatchCheckLayerAvailability
//       (scoped to the staging repo ARNs)
//   Trust policy federates cluster OIDC:
//     oidc.eks.ap-south-1.amazonaws.com/id/20F48F024B28FCD5C96DBDF835847A9D
//     subject system:serviceaccount:redacto:jenkins
//   Until that role exists + the pod template uses the 'jenkins' SA, the ECR
//   login step will fail — the rest of the pipeline is correct and ready.
//
// Parameters (all optional except repo + service):
//   repo            (req)  e.g. 'redfront'
//   service         (req)  app variant matching the values filename, e.g. 'web'
//   env                    'staging' | 'production'   (default 'staging')
//   gitOrg                 (default 'redactolabs')
//   gitopsRepo             (default 'gitops')
//   gitopsBranch           branch holding live values  (default 'main')
//   gitCredentials         Jenkins cred id for cloning gitops (default 'github-pat-sbom')
//   awsRegion              (default 'ap-south-1')
//   projectName            DT project name             (default = repo)
//   projectVersion         DT project version          (default = "<env>-image")
//   syftVersion            pinned Syft release          (default 'v1.45.1')
//   weeklyCron             schedule, '' to disable      (default 'H 3 * * 1')
// =============================================================================

def call(Map config = [:]) {
    String repo           = config.repo    ?: { error("sbomScanImage: 'repo' is required")    }()
    String service        = config.service ?: { error("sbomScanImage: 'service' is required (e.g. 'web')") }()
    String env            = config.get('env', 'staging')
    String gitOrg         = config.get('gitOrg', 'redactolabs')
    String gitopsRepo     = config.get('gitopsRepo', 'gitops')
    String gitopsBranch   = config.get('gitopsBranch', 'main')
    String gitCredentials = config.get('gitCredentials', 'github-pat-sbom')
    String awsRegion      = config.get('awsRegion', 'ap-south-1')
    String projectName    = config.get('projectName', repo)
    String projectVersion = config.get('projectVersion', "${env}-image")
    String syftVersion    = config.get('syftVersion', 'v1.45.1')
    String weeklyCron     = config.get('weeklyCron', 'H 3 * * 1')

    String valuesPath = "${repo}/${env}/values-aws-${service}.yaml"

    pipeline {
        agent {
            kubernetes {
                // IMPORTANT: serviceAccount must be the one carrying the ECR
                // IRSA role. Set it here so we don't rely on the cloud default
                // (which may be 'default' and must NOT get ECR rights).
                yaml """
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: jenkins
  containers:
  - name: tools
    image: alpine:3.20
    command: ["sleep"]
    args: ["infinity"]
    resources:
      requests: { memory: "1Gi", cpu: "500m" }
      limits:   { memory: "2Gi" }
"""
            }
        }

        options {
            timeout(time: 30, unit: 'MINUTES')
            disableConcurrentBuilds()
        }

        triggers {
            cron(weeklyCron)
        }

        stages {
            stage('Read deployed image ref') {
                steps {
                    container('tools') {
                        // Clone gitops (read-only) and extract the live image ref.
                        withCredentials([usernamePassword(credentialsId: gitCredentials,
                                                           usernameVariable: 'GIT_USER',
                                                           passwordVariable: 'GIT_TOKEN')]) {
                            sh """
                                set -euo pipefail
                                apk add --no-cache git yq >/dev/null 2>&1 || apk add --no-cache git >/dev/null 2>&1
                                rm -rf gitops
                                git clone --depth 1 --branch ${gitopsBranch} \\
                                    "https://\${GIT_USER}:\${GIT_TOKEN}@github.com/${gitOrg}/${gitopsRepo}.git" gitops
                            """
                        }
                        script {
                            def registry = sh(script: "grep -E '^[[:space:]]*registry:' gitops/${valuesPath} | head -1 | sed -E 's/.*registry:[[:space:]]*\"?([^\"]+)\"?.*/\\1/'", returnStdout: true).trim()
                            def repository = sh(script: "grep -E '^[[:space:]]*repository:' gitops/${valuesPath} | head -1 | sed -E 's/.*repository:[[:space:]]*\"?([^\"]+)\"?.*/\\1/'", returnStdout: true).trim()
                            def tag = sh(script: "grep -E '^[[:space:]]*tag:' gitops/${valuesPath} | head -1 | sed -E 's/.*tag:[[:space:]]*\"?([^\"]+)\"?.*/\\1/'", returnStdout: true).trim()
                            if (!registry || !repository || !tag) {
                                error("Could not parse image ref from gitops/${valuesPath} (registry='${registry}' repository='${repository}' tag='${tag}')")
                            }
                            env.IMAGE_REF = "${registry}/${repository}:${tag}"
                            echo "Deployed image to scan: ${env.IMAGE_REF}"
                        }
                    }
                }
            }

            stage('Generate image SBOM') {
                steps {
                    container('tools') {
                        sh """
                            set -euo pipefail
                            # Tools: aws cli + docker client + syft. (alpine pkgs;
                            # later hardening = bake these into a custom image.)
                            apk add --no-cache aws-cli docker-cli >/dev/null 2>&1
                            if ! command -v syft >/dev/null 2>&1; then
                                wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin ${syftVersion}
                            fi
                            syft version

                            # ECR login via the pod's IRSA role (no stored creds).
                            REGISTRY=\$(echo "${env.IMAGE_REF}" | cut -d/ -f1)
                            aws ecr get-login-password --region ${awsRegion} \\
                                | syft login --username AWS --password-stdin "\$REGISTRY" 2>/dev/null \\
                                || aws ecr get-login-password --region ${awsRegion} \\
                                   | docker login --username AWS --password-stdin "\$REGISTRY"

                            # Scan straight from the registry (no full docker pull needed).
                            syft scan registry:${env.IMAGE_REF} \\
                                -o cyclonedx-json=sbom-image.cdx.json \\
                                --source-name '${projectName}' \\
                                --source-version '${projectVersion}'
                        """
                    }
                }
            }

            stage('Publish to Dependency-Track') {
                steps {
                    dependencyTrackPublisher(
                        artifact:           'sbom-image.cdx.json',
                        projectName:        projectName,
                        projectVersion:     projectVersion,
                        autoCreateProjects: true,
                        synchronous:        true
                    )
                }
            }
        }

        post {
            always {
                archiveArtifacts artifacts: 'sbom-image.cdx.json',
                                 allowEmptyArchive: true,
                                 fingerprint: true
            }
        }
    }
}
