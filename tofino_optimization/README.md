# Tofino Replay Reproduction

Run the workflow from the repository root. An authorized Tofino1 host, SDE
9.7.0, SSH access, and a maintenance window are required.

Show all wrapper parameters and start the default reproduction:

```bash
./run_tofino_10us_32bit.sh --help
./run_tofino_10us_32bit.sh
```

Replay Hadoop15 only:

```bash
DATASETS=hadoop15.csv THRESHOLD=32 ./run_tofino_10us_32bit.sh
```

Set the complete connection and output configuration explicitly:

```bash
TOFINO_HOST=192.168.30.252 \
TOFINO_PORT=22 \
TOFINO_USER=root \
REMOTE_SDE=/root/bf-sde-9.7.0 \
REMOTE_CODE=/root/bf-sde-9.7.0/CYC_P4/BurstMon_final \
DATASETS=hadoop15.csv,websearch25.csv \
THRESHOLD=32 \
RESTORE_PROGRAM=LightPacket_forward \
OUTPUT_DIR="$PWD/tofino_optimization/results/custom_run" \
./run_tofino_10us_32bit.sh
```

The script prompts for SSH authentication when a key is unavailable. It
temporarily changes the switch program and attempts restoration on every exit.

Run the host-side checks without switch hardware:

```bash
python3 -m unittest discover \
  -s tofino_optimization/optimized/replay_runtime \
  -p 'test_reconstruction.py' -v

python3 -m unittest discover \
  -s tofino_optimization/optimized/runtime \
  -p 'test_lut_model.py' -v

bash -n run_tofino_10us_32bit.sh
```

