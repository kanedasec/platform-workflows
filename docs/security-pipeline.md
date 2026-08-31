# Centrally configured security pipeline

## Trust-boundary sequence

```text
Application pull request
  -> caller-owned preflight job bound to security-policy environment
  -> pinned sgp-pipeline-config action
  -> POST https://sgp.kanedasec.com.br/api/v1/policies/resolve-pipeline
  -> validate application, timestamp, gate allowlist, uniqueness and positions
  -> selected predeclared scanner jobs (no secrets)
  -> selected report downloads
  -> SGP enforcement evaluation per selected gate
```

The API credential is available only to preflight and final policy evaluation.
Neither job checks out or executes pull-request source code. The caller workflow
file itself is still pull-request-controlled, so the `security-policy`
environment must require trusted approval before releasing its secret whenever
untrusted developers can open branches. Branch protection and CODEOWNERS stop a
workflow change from merging; they do not by themselves stop that changed
workflow from requesting a secret during the pull request. OIDC-bound workload
identity is the later replacement for this manual approval boundary.

## Supported implementations

The current workflow has an explicit implementation registry:

| Gate slug | Scanner | Artifact |
| --- | --- | --- |
| `sast` | Semgrep | `semgrep-report` |
| `secrets` | Gitleaks | `gitleaks-report` |
| `sca` | Trivy | `trivy-report` |

An administrator can create other SGP gates, but adding an unknown slug to the
global pipe intentionally blocks preflight. Supporting a new executable gate
requires a reviewed platform change first, followed by the SGP configuration
change.

## Fail-closed validation

Pipeline discovery rejects:

- missing, oversized, or invalid credentials;
- non-HTTPS or credential-bearing manager URLs;
- redirects, transport errors, timeouts, invalid JSON, or oversized responses;
- a mismatched application slug;
- timestamps more than five minutes old or more than one minute in the future;
- an empty gate list;
- unknown or duplicate gates;
- boolean, negative, duplicate, gapped, or out-of-order positions.

The ordered selection controls which scanners and policy evaluations execute.
Selected scanners remain parallel because their evidence is independent; order
is retained for audit and presentation rather than used to serialize work.

## Immutable rollout

The resolver and dynamic policy action must be merged before reusable workflows
pin them. A safe rollout is:

1. deploy the backward-compatible SGP endpoint and database migration;
2. merge and validate the resolver/action implementation;
3. record that immutable platform commit;
4. update the reusable workflow and artifact wrapper to pin that commit;
5. merge and record the workflow commit;
6. update one representative application caller and prove end-to-end behavior;
7. migrate remaining consumers deliberately.

Never reference a branch to collapse these phases.

The final caller must keep `Security policy (SGP Manager)` as an `always()` job
that checks both preflight and reusable-scanner results before reading artifacts.
This prevents a failed prerequisite from turning the required policy check into
a successful/skipped result.
