# platform-workflows

Reusable CI/CD and DevSecOps building blocks for `kanedasec` application
repositories.

This repository centralizes scanner configuration, differential-report helpers,
and SGP Manager policy enforcement. Application repositories will retain only
small caller workflows and application-specific build metadata.

## Trust model

- Application workflows call released revisions by a full Git commit SHA.
- Third-party GitHub Actions are pinned to full commit SHAs.
- Scanner steps produce evidence; SGP Manager decides which severities block.
- Secret-scan exceptions are centrally reviewed; caller-controlled
  `.gitleaksignore` files and inline `gitleaks:allow` comments are ignored.
- The SGP API key remains in each caller repository's protected
  `security-policy` environment. GitHub does not automatically expose secrets
  stored in this repository to callers.
- The application identifier is derived from the caller repository name, not
  supplied by application code.

Changes to `.github/`, `actions/`, and `tests/` require code-owner review once
the repository ruleset is enabled.

## Versioning

Consumers must pin reusable workflows to an immutable full commit SHA. A human
readable release tag may document a version, but tags are not the security pin.

See [the application workflow contract](docs/consumer-contract.md) for caller
examples and required repository configuration.
