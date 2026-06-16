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
                    // Use the git plugin's checkout (handles auth via GIT_ASKPASS)
                    // instead of a raw https://user:token@ URL. The latter breaks
                    // when the credential username contains characters like '.'
                    // (curl misreads the ':' as a port). Land gitops in a subdir.
                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: "*/${gitopsBranch}"]],
                        userRemoteConfigs: [[
                            url:           "https://github.com/${gitOrg}/${gitopsRepo}.git",
                            credentialsId: gitCredentials
                        ]],
                        extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'gitops']]
                    ])
                    script {
                        // Parse registry/repository/tag from the image: block.
                        // sh runs on the jnlp agent container (has grep/sed); the
                        // checked-out files live in the shared workspace volume.
                        def grabImageField = { String field ->
                            sh(script: "grep -E '^[[:space:]]*${field}:' gitops/${valuesPath} | head -1 | sed -E 's/.*${field}:[[:space:]]*\"?([^\"[:space:]]+)\"?.*/\\1/'",
                               returnStdout: true).trim()
                        }
                        def registry   = grabImageField('registry')
                        def repository = grabImageField('repository')
                        def tag        = grabImageField('tag')
                        if (!registry || !repository || !tag) {
                            error("Could not parse image ref from gitops/${valuesPath} (registry='${registry}' repository='${repository}' tag='${tag}')")
                        }
                        env.IMAGE_REF = "${registry}/${repository}:${tag}"
                        echo "Deployed image to scan: ${env.IMAGE_REF}"
                    }
                }
            }

            stage('Generate image SBOM') {
                steps {
                    container('tools') {
                        sh """
                            set -euo pipefail
                            # Tools: aws cli + syft. (alpine pkgs installed per-run;
                            # hardening step = bake these into a registry image.)
                            apk add --no-cache aws-cli >/dev/null 2>&1
                            if ! command -v syft >/dev/null 2>&1; then
                                wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin ${syftVersion}
                            fi
                            syft version

                            # ECR auth via the pod's IRSA role (no stored creds).
                            # Syft reads ~/.docker/config.json (go-containerregistry),
                            # so we write the auth directly — no docker daemon/CLI needed.
                            REGISTRY=\$(echo "${env.IMAGE_REF}" | cut -d/ -f1)
                            PASSWORD=\$(aws ecr get-login-password --region ${awsRegion})
                            AUTH=\$(printf 'AWS:%s' "\$PASSWORD" | base64 | tr -d '\\n')
                            mkdir -p "\$HOME/.docker"
                            cat > "\$HOME/.docker/config.json" <<JSON
{"auths":{"\$REGISTRY":{"auth":"\$AUTH"}}}
JSON

                            # Scan straight from the registry (no full docker pull).
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
