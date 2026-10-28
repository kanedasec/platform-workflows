#!/bin/bash
set -uo pipefail

: "${SGP_MANAGER_URL:?SGP_MANAGER_URL must be set}"
: "${SGP_APPLICATION:?SGP_APPLICATION must be set}"
: "${SEMGREP_REPORT:?SEMGREP_REPORT must be set}"
: "${GITLEAKS_REPORT:?GITLEAKS_REPORT must be set}"
: "${TRIVY_REPORT:?TRIVY_REPORT must be set}"
: "${DECISION_DIRECTORY:?DECISION_DIRECTORY must be set}"
: "${ENABLED_GATES:?ENABLED_GATES must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
status=0

run_gate() {
    local gate="$1"
    local scanner="$2"
    local report="$3"
    local result=0

    python3 "$SCRIPT_DIR/security_gate.py" \
        --manager-url "$SGP_MANAGER_URL" \
        --application "$SGP_APPLICATION" \
        --gate "$gate" \
        --scanner "$scanner" \
        --report "$report" \
        --decision-output "$DECISION_DIRECTORY/$gate.json" || result=$?

    if (( result > status )); then
        status=$result
    fi
}

selection_file="$RUNNER_TEMP/sgp-selected-gates.txt"
if ! python3 "$SCRIPT_DIR/selected_gates.py" \
    --gates "$ENABLED_GATES" \
    --output "$selection_file"; then
    exit 2
fi

while IFS= read -r gate; do
    case "$gate" in
        sast) run_gate sast semgrep "$SEMGREP_REPORT" ;;
        secrets) run_gate secrets gitleaks "$GITLEAKS_REPORT" ;;
        sca) run_gate sca trivy "$TRIVY_REPORT" ;;
        *) echo "Unsupported gate after validation: $gate"; exit 2 ;;
    esac
done < "$selection_file"

exit "$status"
