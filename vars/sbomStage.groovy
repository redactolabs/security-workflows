#!/usr/bin/env groovy
// =============================================================================
// vars/sbomStage.groovy
//
// Embeddable variant for repos that ALREADY have their own Jenkinsfile and
// want to bolt on SBOM generation as one extra stage, rather than run the
// whole standalone pipeline. (Today that's basically just redfront.)
//
// Usage inside an existing declarative Jenkinsfile that uses a k8s agent:
//
//     @Library('redacto-security') _
//     pipeline {
//       agent { kubernetes { ... your existing pod ... } }
//       stages {
//         // ... your existing build/test stages ...
//         stage('SBOM') {
//           steps {
//             container('syft') {            // a container with a shell + internet
//               sbomStage(projectName: 'redfront', projectVersion: 'staging')
//             }
//           }
//         }
//       }
//     }
//
// Requirements of the surrounding container:
//   - a POSIX shell + wget (alpine works; the distroless anchore/syft image
//     does NOT — it has no shell)
//   - outbound internet to get.anchore.io (first run only, then cached if the
//     container persists)
//
// Parameters:
//   projectName    (req)  DT project name
//   projectVersion        DT project version  (default 'staging')
//   syftVersion           pinned Syft release  (default 'v1.45.1')
//   scanDir               path to scan         (default '.')
// =============================================================================

def call(Map config = [:]) {
    String projectName    = config.projectName ?: { error("sbomStage: 'projectName' is required") }()
    String projectVersion = config.get('projectVersion', 'staging')
    String syftVersion    = config.get('syftVersion', 'v1.45.1')
    String scanDir        = config.get('scanDir', '.')

    sh """
        set -euo pipefail
        if ! command -v syft >/dev/null 2>&1; then
            wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin ${syftVersion}
        fi
        syft version
        syft scan dir:${scanDir} \\
            -o cyclonedx-json=sbom.cdx.json \\
            --source-name '${projectName}' \\
            --source-version '${projectVersion}'
    """

    dependencyTrackPublisher(
        artifact:           'sbom.cdx.json',
        projectName:        projectName,
        projectVersion:     projectVersion,
        autoCreateProjects: true,
        synchronous:        true
    )

    archiveArtifacts artifacts: 'sbom.cdx.json', allowEmptyArchive: true, fingerprint: true
}
