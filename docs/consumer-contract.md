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
  differential-security:
    uses: kanedasec/platform-workflows/.github/workflows/security-differential.yaml@WORKFLOW_COMMIT_SHA
```

The security workflow derives the SGP application slug from the caller
repository name. The repository name must therefore match its application slug
in SGP Manager.

Each caller repository must have a `security-policy` environment containing the
shared `SGP_MANAGER_API_KEY` environment secret. The API key is not stored in
this repository and is not passed as a workflow input. Environment approval and
branch rules remain configured in the caller repository.

Caller-controlled `.gitleaksignore`, `.trivyignore`, `gitleaks:allow`, and
`nosemgrep` suppressions do not weaken these scans. Exceptions should be added
through a reviewed central policy process.
