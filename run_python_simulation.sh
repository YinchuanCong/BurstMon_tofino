#!/usr/bin/env bash
set -Eeuo pipefail

# One-command local Python simulation for Hadoop15 and WebSearch25.
# Defaults reproduce the paper-comparison configuration documented in README.

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
TIMESTEP=${TIMESTEP:-10000}
TIMESTAMP_UNIT=${TIMESTAMP_UNIT:-ns}
DEPTH=${DEPTH:-12}
WIDTH=${WIDTH:-6451}
SCALING_PROFILE=${SCALING_PROFILE:-unscaled}
SCORE_MODE=${SCORE_MODE:-exact}
HADOOP_THRESHOLD=${HADOOP_THRESHOLD:-200}
WEBSEARCH_THRESHOLD=${WEBSEARCH_THRESHOLD:-256}
MAX_PACKETS=${MAX_PACKETS:-}
INCLUDE_RECONSTRUCTION=${INCLUDE_RECONSTRUCTION:-0}
RUN_TAG=${RUN_TAG:-$(date -u +%Y%m%dT%H%M%SZ)}
OUTPUT_DIR=${OUTPUT_DIR:-${PROJECT_DIR}/simulation_results/python_run_${RUN_TAG}}

if [[ ! -f "${PROJECT_DIR}/datasets/hadoop15.csv" ]]; then
  echo "Missing dataset: ${PROJECT_DIR}/datasets/hadoop15.csv" >&2
  exit 1
fi
if [[ ! -f "${PROJECT_DIR}/datasets/websearch25.csv" ]]; then
  echo "Missing dataset: ${PROJECT_DIR}/datasets/websearch25.csv" >&2
  exit 1
fi

"${PYTHON_BIN}" -c "import numpy" >/dev/null 2>&1 || {
  echo "NumPy is required. Install it with: ${PYTHON_BIN} -m pip install numpy" >&2
  exit 1
}

mkdir -p "${OUTPUT_DIR}"

COMMON_ARGS=(
  --timestep "${TIMESTEP}"
  --timestamp-unit "${TIMESTAMP_UNIT}"
  --depth "${DEPTH}"
  --width "${WIDTH}"
  --scaling-profile "${SCALING_PROFILE}"
  --score-mode "${SCORE_MODE}"
)

if [[ -n "${MAX_PACKETS}" ]]; then
  COMMON_ARGS+=(--max-packets "${MAX_PACKETS}")
fi
if [[ "${INCLUDE_RECONSTRUCTION}" == "1" ]]; then
  COMMON_ARGS+=(--include-reconstruction)
fi

run_dataset() {
  local dataset=$1
  local threshold=$2
  local dataset_output="${OUTPUT_DIR}/${dataset}"

  echo "[BurstMon] Running ${dataset} (threshold=${threshold})"
  (
    cd "${PROJECT_DIR}"
    "${PYTHON_BIN}" -m burstmon_simulation \
      --input "datasets/${dataset}.csv" \
      --threshold "${threshold}" \
      --output-dir "${dataset_output}" \
      "${COMMON_ARGS[@]}"
  ) | tee "${OUTPUT_DIR}/${dataset}.log"
}

run_dataset hadoop15 "${HADOOP_THRESHOLD}"
run_dataset websearch25 "${WEBSEARCH_THRESHOLD}"

"${PYTHON_BIN}" - "${OUTPUT_DIR}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output = Path(sys.argv[1])
datasets = {}
for name in ("hadoop15", "websearch25"):
    with (output / name / "summary.json").open(encoding="utf-8") as handle:
        datasets[name] = json.load(handle)

combined = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "datasets": datasets,
}
with (output / "python_simulation_summary.json").open("w", encoding="utf-8") as handle:
    json.dump(combined, handle, indent=2, ensure_ascii=False, allow_nan=False)
PY

echo "[BurstMon] Complete"
echo "[BurstMon] Results: ${OUTPUT_DIR}"
echo "[BurstMon] Combined summary: ${OUTPUT_DIR}/python_simulation_summary.json"
