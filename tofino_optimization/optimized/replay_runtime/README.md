# Dataset Replay Runtime

Start the supported dataset replay from the repository root:

```bash
./run_tofino_10us_32bit.sh
```

Select datasets and threshold explicitly:

```bash
DATASETS=hadoop15.csv,websearch25.csv \
THRESHOLD=32 \
./run_tofino_10us_32bit.sh
```

Show all wrapper options:

```bash
./run_tofino_10us_32bit.sh --help
```
