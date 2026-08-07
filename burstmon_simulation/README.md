# Python Simulation Reproduction

Run from the repository root:

```bash
python3 -m pip install numpy
./run_python_simulation.sh
```

For a shorter smoke run:

```bash
MAX_PACKETS=100000 ./run_python_simulation.sh
```

Override the wrapper parameters with environment variables:

```bash
PYTHON_BIN=python3 \
TIMESTEP=10000 \
TIMESTAMP_UNIT=ns \
DEPTH=12 \
WIDTH=6451 \
SCALING_PROFILE=unscaled \
SCORE_MODE=exact \
HADOOP_THRESHOLD=200 \
WEBSEARCH_THRESHOLD=256 \
INCLUDE_RECONSTRUCTION=1 \
OUTPUT_DIR="$PWD/simulation_results/custom_run" \
./run_python_simulation.sh
```

To reproduce one dataset directly:

```bash
python3 -m burstmon_simulation \
  --input datasets/hadoop15.csv \
  --timestep 10000 \
  --timestamp-unit ns \
  --threshold 200 \
  --depth 12 \
  --width 6451 \
  --scaling-profile unscaled \
  --output-dir simulation_results/hadoop15
```

List all direct-module options:

```bash
python3 -m burstmon_simulation --help
```

