#!/usr/bin/env bash
set -Eeuo pipefail

# Self-contained, repository-root entry point for the complete Tofino1 run.
# It owns SSH, upload, compilation, switch lifecycle, LUT programming, replay,
# result collection, and restoration of the original switch program.

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT_DIR="${PROJECT_DIR}/tofino_optimization"
LOCAL_CODE_DIR="${SCRIPT_DIR}/optimized"
P4_PROGRAM=burstmon_dataset_replay_10us_32bit
P4_SOURCE=burstmon_dataset_replay_10us_32bit.p4
RUNTIME_NAME=replay_runtime_10us_32bit
LOCAL_RUNTIME_DIR="${LOCAL_CODE_DIR}/${RUNTIME_NAME}"

usage() {
  cat <<'EOF'
Usage: ./run_tofino_10us_32bit.sh

Complete one-command workflow:
  1. Connect to the remote Tofino switch over SSH.
  2. Upload P4 sources, runtime files, LUT model, and selected datasets.
  3. Compile and install the 8.192-us/32-bit P4 program under SDE 9.7.0.
  4. Switch from LightPacket_forward/bf_kdrv to replay/bf_kpkt.
  5. Program all log/rotation/score LUTs and replay the datasets.
  6. Download reports, reconstructed curves, metrics, and compiler evidence.
  7. Restore LightPacket_forward/bf_kdrv even when the run fails.

Optional environment variables:
  TOFINO_HOST         Remote switch address (default: 192.168.30.252)
  TOFINO_PORT         SSH port (default: 22)
  TOFINO_USER         SSH user (default: root)
  REMOTE_SDE          Remote SDE directory (default: /root/bf-sde-9.7.0)
  REMOTE_CODE         Remote BurstMon working directory
  DATASETS            Comma-separated list: hadoop15.csv,websearch25.csv
  THRESHOLD           Burst threshold (default: 32)
  OUTPUT_DIR          Local result directory
  RESTORE_PROGRAM     Program restored at exit (default: LightPacket_forward)

Examples:
  ./run_tofino_10us_32bit.sh
  DATASETS=hadoop15.csv ./run_tofino_10us_32bit.sh
  THRESHOLD=64 OUTPUT_DIR=/tmp/burstmon-run ./run_tofino_10us_32bit.sh

The script never stores an SSH password. Configure an SSH key or enter the
password once at the terminal when prompted.
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

THRESHOLD=${THRESHOLD:-32}
DATASETS=${DATASETS:-hadoop15.csv,websearch25.csv}
TOFINO_HOST=${TOFINO_HOST:-192.168.30.252}
TOFINO_PORT=${TOFINO_PORT:-22}
TOFINO_USER=${TOFINO_USER:-root}
REMOTE_SDE=${REMOTE_SDE:-/root/bf-sde-9.7.0}
REMOTE_CODE=${REMOTE_CODE:-${REMOTE_SDE}/CYC_P4/BurstMon_final}
RESTORE_PROGRAM=${RESTORE_PROGRAM:-LightPacket_forward}
RUN_TAG=${RUN_TAG:-$(date -u +%Y%m%dT%H%M%SZ)}
OUTPUT_DIR=${OUTPUT_DIR:-${SCRIPT_DIR}/results/reconstruction_8192ns_32bit_t${THRESHOLD}_${RUN_TAG}}

if [[ ! ${TOFINO_PORT} =~ ^[0-9]+$ ]] || (( TOFINO_PORT < 1 || TOFINO_PORT > 65535 )); then
  echo "Invalid TOFINO_PORT: ${TOFINO_PORT}" >&2
  exit 2
fi
if [[ ! ${THRESHOLD} =~ ^[0-9]+$ ]] || (( THRESHOLD < 1 )); then
  echo "Invalid THRESHOLD: ${THRESHOLD}" >&2
  exit 2
fi

IFS=',' read -r -a DATASET_NAMES <<< "${DATASETS}"
DATASET_FILES=()
NORMALIZED_DATASETS=()
for dataset_name in "${DATASET_NAMES[@]}"; do
  dataset_name=${dataset_name//[[:space:]]/}
  case "${dataset_name}" in
    hadoop15.csv|websearch25.csv)
      DATASET_FILES+=("${PROJECT_DIR}/datasets/${dataset_name}")
      NORMALIZED_DATASETS+=("${dataset_name}")
      ;;
    *)
      echo "Unsupported dataset: ${dataset_name:-<empty>}" >&2
      echo "Allowed values: hadoop15.csv,websearch25.csv" >&2
      exit 2
      ;;
  esac
done
if [[ ${#DATASET_FILES[@]} -eq 0 ]]; then
  echo "DATASETS must contain at least one dataset." >&2
  exit 2
fi
DATASETS=$(IFS=,; echo "${NORMALIZED_DATASETS[*]}")

for command_name in ssh scp tee mktemp; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
done

required_files=(
  "${LOCAL_CODE_DIR}/burstmon_optimized.p4"
  "${LOCAL_CODE_DIR}/${P4_SOURCE}"
  "${LOCAL_CODE_DIR}/runtime/lut_model.py"
  "${LOCAL_CODE_DIR}/replay_runtime/test.py"
  "${LOCAL_CODE_DIR}/replay_runtime/reconstruction.py"
  "${LOCAL_CODE_DIR}/replay_runtime/ports.json"
  "${LOCAL_RUNTIME_DIR}/test.py"
  "${LOCAL_RUNTIME_DIR}/ports.json"
  "${DATASET_FILES[@]}"
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "Missing required file: ${required_file}" >&2
    exit 1
  fi
done
if ! compgen -G "${LOCAL_CODE_DIR}/common/*.p4" >/dev/null; then
  echo "No common P4 include files found in ${LOCAL_CODE_DIR}/common" >&2
  exit 1
fi

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

echo "[BurstMon] Complete remote Tofino1 run"
echo "[BurstMon] Target: ${TOFINO_USER}@${TOFINO_HOST}:${TOFINO_PORT}"
echo "[BurstMon] SDE: ${REMOTE_SDE}"
echo "[BurstMon] Remote workdir: ${REMOTE_CODE}"
echo "[BurstMon] Window: 8.192 us (timestamp[28:13]); raw counters: 32 bit; score input: raw/64"
echo "[BurstMon] Datasets: ${DATASETS}; threshold: ${THRESHOLD}"
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

echo "[2/7] Synchronizing P4, runtime, and datasets"
remote "mkdir -p '${REMOTE_CODE}/common' '${REMOTE_CODE}/runtime' \
  '${REMOTE_CODE}/replay_runtime' '${REMOTE_CODE}/${RUNTIME_NAME}' \
  '${REMOTE_CODE}/datasets'"
scp "${SCP_OPTIONS[@]}" \
  "${LOCAL_CODE_DIR}/burstmon_optimized.p4" \
  "${LOCAL_CODE_DIR}/${P4_SOURCE}" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/"
scp "${SCP_OPTIONS[@]}" "${LOCAL_CODE_DIR}/common/"*.p4 \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/common/"
scp "${SCP_OPTIONS[@]}" "${LOCAL_CODE_DIR}/runtime/lut_model.py" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/runtime/"
scp "${SCP_OPTIONS[@]}" \
  "${LOCAL_CODE_DIR}/replay_runtime/test.py" \
  "${LOCAL_CODE_DIR}/replay_runtime/reconstruction.py" \
  "${LOCAL_CODE_DIR}/replay_runtime/ports.json" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/replay_runtime/"
if [[ ${RUNTIME_NAME} != replay_runtime ]]; then
  scp "${SCP_OPTIONS[@]}" \
    "${LOCAL_RUNTIME_DIR}/test.py" \
    "${LOCAL_RUNTIME_DIR}/ports.json" \
    "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/${RUNTIME_NAME}/"
fi
scp "${SCP_OPTIONS[@]}" \
  "${DATASET_FILES[@]}" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/datasets/"

echo "[3/7] Compiling ${P4_PROGRAM} for Tofino1"
remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
  ./p4_build.sh --with-tofino '${REMOTE_CODE}/${P4_SOURCE}'" \
  | tee "${OUTPUT_DIR}/compile.log"

echo "[4/7] Switching from ${RESTORE_PROGRAM}/bf_kdrv to replay/bf_kpkt"
SWITCH_TOUCHED=1
stop_switchd
remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
  install/bin/bf_kdrv_mod_unload && \
  install/bin/bf_kpkt_mod_load '${REMOTE_SDE}/install' && \
  { nohup bf_switchd --install-dir \"\${SDE_INSTALL}\" \
    --conf-file \"\${SDE_INSTALL}/share/p4/targets/tofino/${P4_PROGRAM}.conf\" \
    --init-mode=cold --status-port 7777 --kernel-pkt \
    > /tmp/burstmon_reconstruction_switchd.log 2>&1 < /dev/null & }"
wait_for_switch
remote "ip link set dev enp7s0 up"

echo "[5/7] Loading complete LUTs and replaying ${DATASETS} through the ASIC"
remote "rm -rf '${REMOTE_CODE}/${RUNTIME_NAME}/reconstruction_results' && \
  mkdir -p '${REMOTE_CODE}/${RUNTIME_NAME}/reconstruction_results' && \
  rm -f '${REMOTE_CODE}/${RUNTIME_NAME}/tofino_dataset_replay_summary.json'"
remote "cd '${REMOTE_SDE}' && source set_sde.bash >/dev/null && \
  ./run_p4_tests.sh -p '${P4_PROGRAM}' \
    -t '${REMOTE_CODE}/${RUNTIME_NAME}' \
    -f '${REMOTE_CODE}/${RUNTIME_NAME}/ports.json' \
    --no-veth --arch tf1 --target hw \
    --test-params=\"arch='tofino';num_pipes=4;datasets='${DATASETS}';dataset_dir='${REMOTE_CODE}/datasets';threshold=${THRESHOLD};mirror_egress_port=64;output='${REMOTE_CODE}/${RUNTIME_NAME}/tofino_dataset_replay_summary.json';reconstruction_output='${REMOTE_CODE}/${RUNTIME_NAME}/reconstruction_results'\"" \
  | tee "${OUTPUT_DIR}/replay.log"

echo "[6/7] Collecting reconstruction curves, metrics, and compiler reports"
scp "${SCP_OPTIONS[@]}" -r \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/${RUNTIME_NAME}/reconstruction_results" \
  "${OUTPUT_DIR}/"
scp "${SCP_OPTIONS[@]}" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_CODE}/${RUNTIME_NAME}/tofino_dataset_replay_summary.json" \
  "${OUTPUT_DIR}/"
mkdir -p "${OUTPUT_DIR}/compiler_reports"
scp "${SCP_OPTIONS[@]}" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_SDE}/build/p4-build/tofino/${P4_PROGRAM}/${P4_PROGRAM}/tofino/pipe/logs/metrics.json" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_SDE}/build/p4-build/tofino/${P4_PROGRAM}/${P4_PROGRAM}/tofino/pipe/logs/table_summary.log" \
  "${TOFINO_USER}@${TOFINO_HOST}:${REMOTE_SDE}/build/p4-build/tofino/${P4_PROGRAM}/${P4_PROGRAM}/tofino/pipe/logs/resources.json" \
  "${OUTPUT_DIR}/compiler_reports/"

echo "[7/7] Results saved to ${OUTPUT_DIR}"
echo "The EXIT trap will now restore ${RESTORE_PROGRAM}."
