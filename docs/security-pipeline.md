# Centrally configured security pipeline

## Trust-boundary sequence

```text
Application pull request
  -> caller-owned preflight job bound to security-policy environment
  -> pinned sgp-pipeline-config action
  -> POST https://sgp.kanedasec.com.br/api/v1/policies/resolve-pipeline
  -> validate application, timestamp, gate allowlist, uniqueness and positions
     OR, when SGP is unavailable, select every registered gate
  -> every registered scanner job (no secrets)
  -> complete report downloads
  -> SGP enforcement evaluation per executed gate
     OR strict low+medium+high+critical blocking with no bypasses
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

An administrator can create other SGP gates, but adding an unknown slug to an
assigned gate policy intentionally blocks preflight. Supporting a new
executable gate requires a reviewed platform change first, followed by the SGP
configuration change.

## Strict offline fallback

SGP Manager is an availability-independent bypass resolver, not the source of
the guardrails themselves. If pipeline discovery cannot obtain and validate a
fresh response—including outage, timeout, missing credential, authentication
failure, invalid JSON, schema mismatch, or stale data—the resolver emits an
auditable `offline-no-bypass` configuration containing every gate in the local
implementation registry.

After scanning, the policy gate independently attempts to resolve bypasses. If
that call cannot produce a fresh matching policy, it sets the blocking list to
`low`, `medium`, `high`, and `critical`. A clean report passes; any finding
blocks. This lets delivery continue during an SGP outage without honoring any
bypass that cannot be verified.

Malformed or missing scanner evidence remains an operational gate error. The
fallback never manufactures a clean report and never omits a registered tool.
Unknown scanner severities normalize to `critical`.

## Response validation

Online pipeline discovery rejects and replaces with the strict fallback:

- missing, oversized, or invalid credentials;
- non-HTTPS or credential-bearing manager URLs;
- redirects, transport errors, timeouts, invalid JSON, or oversized responses;
- a mismatched application slug;
- timestamps more than five minutes old or more than one minute in the future;
- an empty gate list;
- unknown or duplicate gates;
- boolean, negative, duplicate, gapped, or out-of-order positions.

The validated online order is preserved, then any locally registered gate that
SGP omitted is appended. Every scanner therefore executes before policy
evaluation, closing the race where SGP is available during discovery but not
during enforcement. Scanners remain parallel because their evidence is
independent; order is retained for audit and presentation rather than used to
serialize work.

Each registered scanner evaluates the complete current pull-request snapshot.
Semgrep has no baseline commit, Gitleaks scans the full checked-out working
tree, and Trivy evaluates all dependency manifests and lockfiles once. Existing
findings therefore remain visible and enforceable on every pull request until
they are fixed or covered by an explicit SGP bypass.

## Immutable rollout

The artifact wrapper and policy evaluator are colocated and execute from the
same immutable platform revision, avoiding a stale nested self-pin. A safe
rollout is:

1. implement and locally validate the resolver, evaluator, wrapper, and tests;
2. merge through the protected platform review and record the immutable commit;
3. update one representative application caller to that exact commit and prove
   online and offline behavior end to end;
4. migrate remaining consumers deliberately.

Never reference a branch or mutable tag to collapse these phases.

The final caller must keep `Security policy (SGP Manager)` as an `always()` job
that checks both preflight and reusable-scanner results before reading artifacts.
This prevents a failed scanner or artifact prerequisite from turning the
required policy check into a successful/skipped result. SGP unavailability
itself is handled inside the pinned actions with strict no-bypass enforcement.
