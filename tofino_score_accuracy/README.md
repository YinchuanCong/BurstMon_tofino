# Tofino Score-Accuracy Reproduction

Run from the repository root with an authorized Tofino1 host and SDE 9.7.0:

```bash
./run_tofino_score_accuracy.sh
```

Show all supported parameters:

```bash
./run_tofino_score_accuracy.sh --help
```

Set the remote connection, sample generator, and output path explicitly:

```bash
TOFINO_HOST=192.168.30.252 \
TOFINO_PORT=22 \
TOFINO_USER=root \
REMOTE_SDE=/root/bf-sde-9.7.0 \
REMOTE_CODE=/root/bf-sde-9.7.0/CYC_P4/BurstMon_score_accuracy \
SAMPLE_COUNT=256 \
SEED=20260806 \
RESTORE_PROGRAM=LightPacket_forward \
OUTPUT_DIR="$PWD/tofino_score_accuracy/results/custom_run" \
./run_tofino_score_accuracy.sh
```

Run the host-side arithmetic checks without a switch:

```bash
python3 -m unittest discover \
  -s tofino_score_accuracy/runtime \
  -p 'test_lut_model.py' -v

bash -n run_tofino_score_accuracy.sh
```

