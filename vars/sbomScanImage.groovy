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
    String repo           = config.repo ?: { error("sbomScanImage: 'repo' is required") }()
    // service is OPTIONAL: monorepos (e.g. redfront) use values-aws-<service>.yaml
    // and need it; single-service repos use a plain values-aws.yaml and omit it.
    String service        = config.get('service', '')
    String env            = config.get('env', 'staging')
    String gitOrg         = config.get('gitOrg', 'redactolabs')
    String gitopsRepo     = config.get('gitopsRepo', 'gitops')
    String gitopsBranch   = config.get('gitopsBranch', 'main')
    String gitCredentials = config.get('gitCredentials', 'github-pat-sbom')
    String awsRegion      = config.get('awsRegion', 'ap-south-1')
    String projectName    = config.get('projectName', repo)
    // Version carries the service so a monorepo's services don't overwrite each
    // other's DT project (redfront : staging-image-web vs ...-academy). Single-
    // service repos stay clean (ropa-agent : staging-image).
    String projectVersion = config.get('projectVersion',
                                       service ? "${env}-image-${service}" : "${env}-image")
    String syftVersion    = config.get('syftVersion', 'v1.45.1')
    String weeklyCron     = config.get('weeklyCron', 'H 3 * * 1')

    // Filename differs by repo layout: with a service suffix for monorepos,
    // plain values-aws.yaml otherwise.
    String valuesFile = service ? "values-aws-${service}.yaml" : "values-aws.yaml"
    String valuesPath = "${repo}/${env}/${valuesFile}"

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
      requests: { memory: "2Gi", cpu: "500m" }
      limits:   { memory: "6Gi" }
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
            stage('Read tag & scan image') {
                steps {
                    // Plugin checkout (GIT_ASKPASS auth, no creds in URL).
                    // gitops lands in ./gitops in the shared workspace volume,
                    // readable from the tools container too.
                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: "*/${gitopsBranch}"]],
                        userRemoteConfigs: [[
                            url:           "https://github.com/${gitOrg}/${gitopsRepo}.git",
                            credentialsId: gitCredentials
                        ]],
                        extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'gitops']]
                    ])
                    container('tools') {
                        // Everything stays in shell — the image ref is a shell
                        // variable, never a Groovy/env value. This deliberately
                        // avoids the CPS quirk where `env.X = ...` inside a vars/
                        // declarative script block misresolves `env`.
                        sh """
                            set -euo pipefail

                            VALUES="gitops/${valuesPath}"
                            # grep -m1 (stop at first match) instead of '| head -1'
                            # so pipefail doesn't trip on SIGPIPE. '|| true' lets us
                            # emit a friendly error if a field is genuinely missing.
                            REGISTRY=\$(grep -m1 -E '^[[:space:]]*registry:'   "\$VALUES" | sed -E 's/.*registry:[[:space:]]*\"?([^\"[:space:]]+)\"?.*/\\1/'   || true)
                            REPOSITORY=\$(grep -m1 -E '^[[:space:]]*repository:' "\$VALUES" | sed -E 's/.*repository:[[:space:]]*\"?([^\"[:space:]]+)\"?.*/\\1/' || true)
                            TAG=\$(grep -m1 -E '^[[:space:]]*tag:'              "\$VALUES" | sed -E 's/.*tag:[[:space:]]*\"?([^\"[:space:]]+)\"?.*/\\1/'        || true)
                            if [ -z "\$REGISTRY" ] || [ -z "\$REPOSITORY" ] || [ -z "\$TAG" ]; then
                                echo "ERROR: could not parse image ref from \$VALUES (registry='\$REGISTRY' repository='\$REPOSITORY' tag='\$TAG')" >&2
                                exit 1
                            fi
                            IMAGE_REF="\$REGISTRY/\$REPOSITORY:\$TAG"
                            echo "Deployed image to scan: \$IMAGE_REF"

                            # Tools: aws cli + syft (installed per-run; hardening
                            # step = bake these into a registry image).
                            apk add --no-cache aws-cli >/dev/null 2>&1
                            if ! command -v syft >/dev/null 2>&1; then
                                wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin ${syftVersion}
                            fi
                            syft version

                            # ECR auth via the pod's IRSA role (no stored creds).
                            # Syft reads ~/.docker/config.json (go-containerregistry),
                            # so write the auth directly — no docker daemon/CLI needed.
                            #
                            # set +x: Jenkins' sh step traces commands (set -x) by
                            # default, which would print the ECR token + the base64
                            # auth into the build console. Disable tracing for this
                            # block so the credential never hits the log.
                            set +x
                            PASSWORD=\$(aws ecr get-login-password --region ${awsRegion})
                            AUTH=\$(printf 'AWS:%s' "\$PASSWORD" | base64 | tr -d '\\n')
                            mkdir -p "\$HOME/.docker"
                            cat > "\$HOME/.docker/config.json" <<JSON
{"auths":{"\$REGISTRY":{"auth":"\$AUTH"}}}
JSON
                            unset PASSWORD AUTH
                            echo "ECR auth configured for \$REGISTRY"
                            set -x

                            # Scan straight from the registry (no full docker pull).
                            syft scan "registry:\$IMAGE_REF" \\
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
