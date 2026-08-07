# 8.192 us / 32-bit Replay Runtime

Start this replay build from the repository root:

```bash
./run_tofino_10us_32bit.sh
```

Replay Hadoop15 and select the local output directory:

```bash
DATASETS=hadoop15.csv \
THRESHOLD=32 \
OUTPUT_DIR="$PWD/tofino_optimization/results/hadoop15_reproduction" \
./run_tofino_10us_32bit.sh
```

Show all available overrides:

```bash
./run_tofino_10us_32bit.sh --help
```
