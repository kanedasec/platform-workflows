# Application workflow contract

Application repositories keep only small caller workflows. Replace
`WORKFLOW_COMMIT_SHA` with the full commit SHA that introduced the reusable
workflow files. Never use `main` as the reference.

## CI caller

```yaml
name: CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  standard-ci:
    uses: kanedasec/platform-workflows/.github/workflows/ci-python-node.yaml@WORKFLOW_COMMIT_SHA
    with:
      python_working_directory: backend
      python_requirements_file: requirements-dev.txt
      python_cache_dependency_path: |
        backend/requirements.txt
        backend/requirements-dev.txt
      python_test_path: tests
      node_working_directory: frontend
      node_lockfile: frontend/package-lock.json
      node_run_tests: false
      node_build_script: build
```

The profile intentionally accepts structured versions, paths, and npm script
names rather than arbitrary shell commands. Add another reviewed platform
profile when an application stack requires materially different behavior.

## Security caller

```yaml
name: Security

on:
  pull_request:
    branches: [main]

permissions:
  actions: read
  contents: read

jobs:
  pipeline-config:
    name: Security pipeline configuration
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    environment:
      name: security-policy
    permissions:
      contents: read
    outputs:
      gates: ${{ steps.resolve.outputs.gates }}
    steps:
      - name: Resolve central security pipeline
        id: resolve
        uses: kanedasec/platform-workflows/actions/sgp-pipeline-config@WORKFLOW_COMMIT_SHA
        env:
          SGP_MANAGER_API_KEY: ${{ secrets.SGP_MANAGER_API_KEY }}

      - name: Preserve resolved pipeline evidence
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: sgp-pipeline-configuration
          path: ${{ steps.resolve.outputs.configuration_path }}
          if-no-files-found: error
          retention-days: 7

  security-scans:
    name: Full repository security
    needs: pipeline-config
    uses: kanedasec/platform-workflows/.github/workflows/security.yaml@WORKFLOW_COMMIT_SHA
    with:
      gates: ${{ needs.pipeline-config.outputs.gates }}

  policy-gate:
    name: Security policy (SGP Manager)
    if: always()
    needs: [pipeline-config, security-scans]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    environment:
      name: security-policy
    permissions:
      actions: read
      contents: read
    steps:
      - name: Require successful pipeline discovery and scanners
        env:
          PIPELINE_RESULT: ${{ needs.pipeline-config.result }}
          SCANNER_RESULT: ${{ needs.security-scans.result }}
        run: |
          if [[ "$PIPELINE_RESULT" != "success" || "$SCANNER_RESULT" != "success" ]]; then
            echo "Security prerequisites failed: pipeline=$PIPELINE_RESULT scanners=$SCANNER_RESULT"
            exit 1
          fi

      - name: Apply centralized security policies
        uses: kanedasec/platform-workflows/actions/sgp-policy-from-artifacts@WORKFLOW_COMMIT_SHA
        env:
          SGP_MANAGER_API_KEY: ${{ secrets.SGP_MANAGER_API_KEY }}
        with:
          gates: ${{ needs.pipeline-config.outputs.gates }}
```

The preflight and policy jobs run without checking out pull-request source and
bind directly to the protected environment. The scanners receive only the
validated gate list and no application secret. Both pinned composite actions
derive the SGP application slug from the caller repository name. The repository
name must therefore match its active application slug in SGP Manager.

Each caller repository must have a `security-policy` environment containing the
shared `SGP_MANAGER_API_KEY` environment secret. The API key is not stored in
this repository, passed as an action input, or made available to scanner jobs.
When pull requests can be opened by untrusted developers, this environment must
require trusted approval before releasing the secret; CODEOWNERS alone does not
prevent a modified pull-request workflow from requesting it. Environment and
branch rules remain configured in the caller repository.

Caller-controlled `.gitleaksignore`, `.trivyignore`, `gitleaks:allow`, and
`nosemgrep` suppressions do not weaken these scans. Exceptions should be added
through a reviewed central policy process.
