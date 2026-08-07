#!/usr/bin/env bash
set -Eeuo pipefail

# Self-contained entry point for the Binary16 score-accuracy experiment.
# It owns SSH, upload, compilation, switch lifecycle, sample/LUT programming,
# result collection, and restoration of the original program.

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT_DIR="${PROJECT_DIR}/tofino_score_accuracy"
LOCAL_CODE_DIR="${SCRIPT_DIR}"
P4_PROGRAM=burstmon_score_eval
P4_SOURCE=burstmon_score_eval.p4
RUNTIME_NAME=runtime
LOCAL_RUNTIME_DIR="${LOCAL_CODE_DIR}/${RUNTIME_NAME}"

usage() {
  cat <<'EOF'
Usage: ./run_tofino_score_accuracy.sh

Complete one-command Binary16 anomaly-score accuracy experiment:
  1. Connect once over SSH and upload the evaluator plus its runtime.
  2. Compile and start burstmon_score_eval on Tofino1.
  3. Program deterministic samples and sample-specific LUT entries.
  4. Run the on-chip packet generator and read BF Runtime digests.
  5. Compute MSE/RMSE/MAE/MaxAE and download CSV/JSON results.
  6. Restore LightPacket_forward with bf_kdrv on every exit.

Optional environment variables:
  TOFINO_HOST         Remote address (default: 192.168.30.252)
  TOFINO_PORT         SSH port (default: 22)
  TOFINO_USER         SSH user (default: root)
  REMOTE_SDE          Remote SDE directory (default: /root/bf-sde-9.7.0)
  REMOTE_CODE         Remote evaluator directory
  SAMPLE_COUNT        Deterministic samples, 8..512 (default: 256)
  SEED                Sample generator seed (default: 20260806)
  OUTPUT_DIR          Local result directory
  RESTORE_PROGRAM     Program restored at exit (default: LightPacket_forward)

SSH passwords are never stored; use a key or enter the password once.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

SAMPLE_COUNT=${SAMPLE_COUNT:-256}
SEED=${SEED:-20260806}
TOFINO_HOST=${TOFINO_HOST:-192.168.30.252}
TOFINO_PORT=${TOFINO_PORT:-22}
TOFINO_USER=${TOFINO_USER:-root}
REMOTE_SDE=${REMOTE_SDE:-/root/bf-sde-9.7.0}
REMOTE_CODE=${REMOTE_CODE:-${REMOTE_SDE}/CYC_P4/BurstMon_score_accuracy}
RESTORE_PROGRAM=${RESTORE_PROGRAM:-LightPacket_forward}
RUN_TAG=${RUN_TAG:-$(date -u +%Y%m%dT%H%M%SZ)}
OUTPUT_DIR=${OUTPUT_DIR:-${SCRIPT_DIR}/results/score_accuracy_n${SAMPLE_COUNT}_${RUN_TAG}}

if [[ ! ${TOFINO_PORT} =~ ^[0-9]+$ ]] || (( TOFINO_PORT < 1 || TOFINO_PORT > 65535 )); then
  echo "Invalid TOFINO_PORT: ${TOFINO_PORT}" >&2
  exit 2
fi
if [[ ! ${SAMPLE_COUNT} =~ ^[0-9]+$ ]] ||
   (( SAMPLE_COUNT < 8 || SAMPLE_COUNT > 512 )); then
  echo "SAMPLE_COUNT must be an integer in [8, 512]." >&2; exit 2
fi
if [[ ! ${SEED} =~ ^[0-9]+$ ]]; then
  echo "SEED must be a non-negative integer." >&2; exit 2
fi

for command_name in ssh scp tee mktemp; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
done

required_files=(
  "${LOCAL_CODE_DIR}/${P4_SOURCE}"
  "${LOCAL_RUNTIME_DIR}/test.py"
  "${LOCAL_RUNTIME_DIR}/lut_model.py"
  "${LOCAL_RUNTIME_DIR}/ports.json"
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "Missing required file: ${required_file}" >&2
    exit 1
  fi
done
CONTROL_DIR=$(mktemp -d /tmp/burstmon-ssh-XXXXXX)
CONTROL_SOCKET="${CONTROL_DIR}/control.sock"
SWITCH_TOUCHED=0

mkdir -p "${OUTPUT_DIR}"

MASTER_OPTIONS=(
  -p "${TOFINO_PORT}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ControlMaster=yes
  -o ControlPath="${CONTROL_SOCKET}"
  -o ControlPersist=600
)

echo "[BurstMon] Binary16 anomaly-score accuracy experiment"
echo "[BurstMon] Target: ${TOFINO_USER}@${TOFINO_HOST}:${TOFINO_PORT}"
echo "[BurstMon] SDE: ${REMOTE_SDE}"
echo "[BurstMon] Remote workdir: ${REMOTE_CODE}"
echo "[BurstMon] Samples: ${SAMPLE_COUNT}; seed: ${SEED}"
echo "[BurstMon] Metric: MSE after decoding IEEE-754 Binary16"
echo "[BurstMon] Local results: ${OUTPUT_DIR}"
echo "[1/7] Connecting (one password prompt if no SSH key exists)"
ssh "${MASTER_OPTIONS[@]}" -fnNT "${TOFINO_USER}@${TOFINO_HOST}"
SSH_OPTIONS=(
  -p "${TOFINO_PORT}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ControlPath="${CONTROL_SOCKET}"
)
SCP_OPTIONS=(
  -P "${TOFINO_PORT}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ControlPath="${CONTROL_SOCKET}"
)

remote() {
  ssh "${SSH_OPTIONS[@]}" "${TOFINO_USER}@${TOFINO_HOST}" "$@"
}

wait_for_switch() {
  remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
    for attempt in \$(seq 1 24); do \
      timeout 5 python3 install/lib/python3.5/site-packages/p4testutils/bf_switchd_dev_status.py \
        --host localhost --port 7777 >/tmp/burstmon_status.out 2>&1 && \
        cat /tmp/burstmon_status.out && exit 0; \
      sleep 5; \
    done; cat /tmp/burstmon_status.out; exit 1"
}

stop_switchd() {
  remote "pids=\$(pgrep -x bf_switchd || true); \
    if [ -n \"\${pids}\" ]; then kill -QUIT \${pids}; fi; \
    for attempt in \$(seq 1 15); do pgrep -x bf_switchd >/dev/null || exit 0; sleep 1; done; \
    exit 1"
}

restore_switch() {
  local status=$?
  local restore_status=0
  trap - EXIT INT TERM
  set +e
  if [[ ${SWITCH_TOUCHED} -eq 1 ]]; then
    echo "[restore] Restoring ${RESTORE_PROGRAM} with bf_kdrv"
    if ! stop_switchd >/dev/null 2>&1; then
      echo "[restore] Could not stop the replay bf_switchd cleanly." >&2
      restore_status=1
    fi
    if ! remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
      { install/bin/bf_kpkt_mod_unload >/dev/null 2>&1 || true; } && \
      { lsmod | grep -q '^bf_kdrv' || \
        install/bin/bf_kdrv_mod_load '${REMOTE_SDE}/install'; } && \
      { nohup bf_switchd --install-dir \"\${SDE_INSTALL}\" \
        --conf-file \"\${SDE_INSTALL}/share/p4/targets/tofino/${RESTORE_PROGRAM}.conf\" \
        --init-mode=cold --status-port 7777 \
        > /tmp/burstmon_restore_${RESTORE_PROGRAM}.log 2>&1 < /dev/null & }"; then
      echo "[restore] Failed to launch ${RESTORE_PROGRAM}." >&2
      restore_status=1
    fi
    if ! wait_for_switch >/dev/null 2>&1; then
      echo "[restore] ${RESTORE_PROGRAM} did not become ready on port 7777." >&2
      restore_status=1
    fi
    if ! remote "lsmod | grep '^bf_kdrv' && pgrep -af 'bf_switchd.*${RESTORE_PROGRAM}'"; then
      echo "[restore] Driver/process verification failed." >&2
      restore_status=1
    fi
  fi
  ssh "${SSH_OPTIONS[@]}" -O exit "${TOFINO_USER}@${TOFINO_HOST}" >/dev/null 2>&1
  rmdir "${CONTROL_DIR}" >/dev/null 2>&1
  if [[ ${status} -eq 0 && ${restore_status} -ne 0 ]]; then
    status=1
  fi
  if [[ ${status} -ne 0 ]]; then
    if [[ ${restore_status} -eq 0 ]]; then
      echo "Experiment failed; the original switch program was restored." >&2
    else
      echo "Experiment or restoration failed; inspect the remote restore log." >&2
    fi
  fi
  exit "${status}"
}
trap restore_switch EXIT INT TERM

echo "[2/7] Synchronizing evaluator P4 and accuracy runtime"
remote "mkdir -p '${REMOTE_CODE}/${RUNTIME_NAME}'"
scp "${SCP_OPTIONS[@]}" "${LOCAL_CODE_DIR}/${P4_SOURCE}" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/"
scp "${SCP_OPTIONS[@]}" "${LOCAL_RUNTIME_DIR}/test.py" \
  "${LOCAL_RUNTIME_DIR}/lut_model.py" \
  "${LOCAL_RUNTIME_DIR}/ports.json" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/${RUNTIME_NAME}/"

echo "[3/7] Compiling ${P4_PROGRAM} for Tofino1"
remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
  ./p4_build.sh --with-tofino '${REMOTE_CODE}/${P4_SOURCE}'" \
  | tee "${OUTPUT_DIR}/compile.log"

echo "[4/7] Starting ${P4_PROGRAM} with bf_kdrv"
SWITCH_TOUCHED=1
stop_switchd
remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
  { install/bin/bf_kpkt_mod_unload >/dev/null 2>&1 || true; } && \
  { lsmod | grep -q '^bf_kdrv' || install/bin/bf_kdrv_mod_load '${REMOTE_SDE}/install'; } && \
  { nohup bf_switchd --install-dir \"\${SDE_INSTALL}\" \
    --conf-file \"\${SDE_INSTALL}/share/p4/targets/tofino/${P4_PROGRAM}.conf\" \
    --init-mode=cold --status-port 7777 \
    > /tmp/burstmon_score_accuracy_switchd.log 2>&1 < /dev/null & }"
wait_for_switch

echo "[5/7] Programming samples/LUTs and running the ASIC packet generator"
remote "rm -f '${REMOTE_CODE}/${RUNTIME_NAME}/score_accuracy_results.csv' \
  '${REMOTE_CODE}/${RUNTIME_NAME}/score_accuracy_summary.json'"
remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
  ./run_p4_tests.sh -p '${P4_PROGRAM}' \
    -t '${REMOTE_CODE}/${RUNTIME_NAME}' \
    --no-veth --arch tf1 --target hw \
    --test-params=\"arch='tofino';num_pipes=4;sample_count=${SAMPLE_COUNT};seed=${SEED}\"" \
  | tee "${OUTPUT_DIR}/accuracy.log"

echo "[6/7] Downloading per-sample accuracy results"
scp "${SCP_OPTIONS[@]}" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/${RUNTIME_NAME}/score_accuracy_results.csv" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/${RUNTIME_NAME}/score_accuracy_summary.json" \
  "${OUTPUT_DIR}/"

echo "[7/7] Collecting compiler reports"
mkdir -p "${OUTPUT_DIR}/compiler_reports"
scp "${SCP_OPTIONS[@]}" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_SDE}/build/p4-build/tofino/${P4_PROGRAM}/${P4_PROGRAM}/tofino/pipe/logs/metrics.json" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_SDE}/build/p4-build/tofino/${P4_PROGRAM}/${P4_PROGRAM}/tofino/pipe/logs/table_summary.log" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_SDE}/build/p4-build/tofino/${P4_PROGRAM}/${P4_PROGRAM}/tofino/pipe/logs/resources.json" \
  "${OUTPUT_DIR}/compiler_reports/"

echo "[BurstMon] Results saved to ${OUTPUT_DIR}"
echo "[BurstMon] The EXIT trap will now restore ${RESTORE_PROGRAM}."
