#!/usr/bin/env groovy

@Library('jarvis') _
node("westeros-agent") {
  checkout scm
  setReleaseSSHkey()
  def packageName = "eve-jwt-auth"

  gazrInitAndCleanWorkspace {
    stage("quality") {
      parallel(
              test: {
                gazrTest {
                  junit "reports/report_unit_tests.xml"
                }
              },
              complexity: {
                gazrComplexity()
              },
              style: {
                gazrStyle()
              },
              "security-sast": {
                gazrSecuritySast()
              }
      )
    }

    isBranch("master") {
      stage("SonarQube") {
        codexSonarQube()
      }
    }

    def isMaster = isBranch("master")
    if (isMaster) {
      def version = getPackageVersion()

      stage("Building artifact") {
        pypiBuild()
      }

      if (!pypiCheckVersion(packageName, version)) {
        stage("Publish ${packageName} to prod") {
          pypiPublish(packageName)
        }

        stage("Tagging ${version}") {
          packageTag(version)
        }
      }
    } else {
      def version = getPackageSandboxVersion()

      stage("Set version and build version ${version}") {
        setPackageVersion(version)
        pypiBuild()
      }

      if (env.JOB_BASE_NAME.startsWith("PR-")) {
        stage("Publish ${version}") {
          pypiPublish(packageName, "sandbox")
        }
      }
    }
  }
}
