# platform-workflows

Reusable CI/CD and DevSecOps building blocks for `kanedasec` application
repositories.

Repository-specific implementation and security rules for coding agents are
documented in [`AGENTS.md`](AGENTS.md).

This repository centralizes full-repository scanner configuration and SGP
Manager policy enforcement. Application repositories retain only small caller
workflows and application-specific build metadata.

SGP Manager supplies each application's assigned ordered security pipeline. A
fail-closed preflight action validates that selection before any scanner job is
eligible to run; scanner jobs never receive the SGP API credential.

The current executable gate registry maps `sast` to Semgrep, `secrets` to
Gitleaks, and `sca` to Trivy. Selected scanners run in parallel against the
complete current pull-request snapshot and only their artifacts are evaluated.

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
- Deployment credentials remain in each caller's protected environment. The
  central deployment action uses an ephemeral, narrowly tagged Tailscale node
  and a pinned SSH host key to invoke one forced server-side command.

Changes to `.github/`, `actions/`, and `tests/` require code-owner review once
the repository ruleset is enabled.

## Versioning

Consumers must pin reusable workflows to an immutable full commit SHA. A human
readable release tag may document a version, but tags are not the security pin.

See [the application workflow contract](docs/consumer-contract.md) for caller
examples and required repository configuration.

See [the container publishing contract](docs/container-publishing.md) for GHCR
image naming, permissions, and tagging conventions.

See [the Tailscale SSH deployment contract](docs/deployment.md) for protected
environment configuration and the restricted deployment caller.
