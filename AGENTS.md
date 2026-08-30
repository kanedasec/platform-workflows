# Platform Workflows instructions for agents

## Repository role

This public repository is the reusable CI/CD trust root for `kanedasec`
application repositories. It contains GitHub reusable workflows, composite
actions, scanner/report adapters, policy enforcement, container publishing,
and the ephemeral Tailscale/SSH deployment client.

Application repositories execute code from this repository using immutable
full commit SHAs. A defect or compromise here can affect every consumer that
adopts that revision. Treat changes with the same care as changes to a build
system, package registry credential broker, or deployment control plane.

## Required architecture

```text
Application pull request
  |-> reusable language CI
  `-> differential scanners
        |-> Semgrep JSON
        |-> redacted Gitleaks JSON
        `-> differential Trivy JSON
              -> SGP Manager policy evaluation
              -> PASS or BLOCK

Protected application main
  -> reusable CI
  -> validated container build
  -> GHCR sha-<full-commit> image
  -> protected application environment
  -> ephemeral tag:github-deploy Tailscale node
  -> pinned-host-key SSH as deployer
  -> forced server-side deployment command
```

GitHub-hosted runners build and validate. This repository must never require a
persistent general-purpose runner or direct access to a VPS Docker socket.

## Non-negotiable trust rules

1. Pin every external action to a full 40-character commit SHA. Tags, branches,
   and floating major versions are not security pins.
2. Never use `pull_request_target` to check out or execute pull-request code.
3. Set workflow permissions to the minimum required. The default is
   `contents: read`; grant `packages: write` only to image-publishing jobs.
4. Use `persist-credentials: false` for every checkout.
5. Do not accept arbitrary caller-provided shell commands, script paths, runner
   labels, registry names, deployment hosts, or privileged Docker options.
6. Do not expose platform or deployment secrets to pull-request code.
7. Do not put Tailscale, SSH, SGP Manager, registry, or application credentials
   in this repository, artifacts, fixtures, logs, or examples.
8. Do not install or target self-hosted runners from reusable application CI.
9. Do not let application repositories weaken central scanner configuration or
   provide their own secret-scan suppressions.
10. Treat malformed reports, unknown severities, stale policy responses,
    authentication failures, timeouts, and schema mismatches as gate errors—not
    authorization to proceed.
11. Never deploy `latest` or `dev`. Deployment accepts only
    `sha-<40 lowercase hexadecimal characters>`.
12. Do not broaden `tag:github-deploy`; the Tailnet policy must independently
    restrict it to the deployment target's TCP/22.

## Directory contracts

`.github/workflows/ci-python-node.yaml` provides structured Python and Node.js
profiles. Add typed `workflow_call` inputs with safe defaults when extending a
profile. Do not add a generic caller-controlled command input.

`.github/workflows/security-differential.yaml` produces scanner evidence for a
pull request. Preserve these artifact names and formats unless consumers and
the policy adapter are migrated together:

```text
semgrep-report   -> semgrep.json
gitleaks-report  -> gitleaks.json
trivy-report     -> trivy-delta.json
```

`.github/workflows/container-publish.yaml` validates every image definition,
restricts publishing to the caller's default branch, publishes linux/amd64
images to GHCR, and adds OCI source/revision/version labels. Image names are
derived from the caller repository and component name.

`actions/gitleaks-scan/` owns the centrally reviewed Gitleaks configuration.
`gitleaks.ignore` contains exact, reviewed fingerprints. Do not enable
repository-local allowlists or inline suppression comments.

`actions/trivy-diff/` compares normalized vulnerability identity across base
and head reports. Preserve package identity in the comparison; the same CVE in
a different package can be a new finding.

`actions/sgp-policy-gate/` validates scanner JSON, normalizes severities, calls
SGP Manager over HTTPS, validates the returned application/gate/timestamp, and
writes an auditable decision artifact. Unknown scanner severity is `critical`.
Operational errors return a distinct non-zero result and fail closed.

`actions/sgp-policy-from-artifacts/` downloads the three fixed scanner
artifacts and applies the SGP policy independently to `sast`, `secrets`, and
`sca`. The application slug comes from the caller repository name.

`actions/tailscale-ssh-deploy/` validates deployment inputs before using
credentials. It accepts only a Tailscale IPv4 target, restricted Unix user,
command name without arguments, immutable image tag, clean HTTPS origin, safe
readiness path, and an approved expected root status. It must retain strict
host-key checking, public-key-only authentication, ephemeral SSH material,
cleanup with `if: always()`, and public post-deployment verification.

## Differential security semantics

- Semgrep uses the pull request base as `--baseline-commit` and disables
  metrics and inline `nosem` suppression.
- Gitleaks scans the pull-request commit range with the central configuration
  and uploads only redacted JSON.
- Trivy scans base and head with the same vulnerability database, then emits
  only vulnerabilities newly introduced by the head.
- Scanners produce evidence. SGP Manager determines which normalized
  severities block for the exact application and gate.

Do not silently convert differential scanning into a full-repository gate or
vice versa. That is a policy change and must be documented and reviewed.

## Compatibility and release discipline

Consumers pin commit SHAs, so merging here does not automatically update them.
After a reviewed merge, application repositories deliberately adopt the new
merge commit.

Prefer backward-compatible additions:

- new optional inputs with safe defaults;
- stable artifact names and JSON schemas;
- unchanged job/check names used by repository rulesets;
- unchanged image naming and OCI revision labels;
- unchanged exit-code meaning for policy decisions.

A breaking contract requires a new versioned workflow/action path or a phased
consumer migration. Never rewrite or force-push a revision already consumed by
applications.

## Safe change process

1. Start from updated `main` and create a feature branch.
2. Identify every application caller affected by the contract change.
3. Add or update tests before changing security-sensitive parsing or input
   validation.
4. Keep examples free of realistic credential values.
5. Run all local validation commands.
6. Open a pull request and pass `Tooling validation`.
7. Merge without bypassing the ruleset.
8. Record the merge commit SHA and update consumers through their own PRs.
9. For deployment-action changes, prove both an allowed deployment and denial
   of an unrelated SSH command in a controlled application rollout.

## Required local validation

From the repository root:

```bash
python3 -m unittest discover \
  --start-directory tests \
  --pattern 'test_*.py'

actionlint .github/workflows/*.yaml

git diff --check
```

When Gitleaks is installed, also run the repository scan with the central
configuration and a redacted JSON report. Never print finding secrets.

Tests must continue to enforce:

- full-SHA external references;
- absence of `pull_request_target`;
- disabled checkout credential persistence;
- report schema and severity normalization;
- stale or mismatched SGP responses failing closed;
- Trivy package-aware differential behavior;
- strict deployment input validation.

## Documentation and handoff

Update the relevant file in `docs/` whenever a caller contract changes. A
handoff must identify the new immutable platform revision, affected consumers,
compatibility behavior, tests run, and any manual environment or VPS change.
Do not describe work as complete merely because this repository merged; at
least one representative consumer must successfully use security-sensitive new
behavior before rollout is considered proven.

