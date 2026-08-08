# Programmable Switch Telemetry at Microsecond Granularity: BurstMon in Action

### Abstract

Modern high-speed networks exhibit highly dynamic traffic behaviors, where
microsecond-scale bursts and rate shifts can significantly impact congestion
control, scheduling, and anomaly response. Most existing telemetry systems
operate at millisecond granularity, missing critical fine-grained events.
Recent work such as µMon pushes monitoring resolution toward microseconds by
compressing rate traces with wavelet transforms, but its multi-timeslot
buffering introduces milliseconds of latency that fundamentally limits
responsiveness.

We make a complementary observation about the structure of microsecond-scale
flow signals: they are sparse in the event domain—most flows exhibit long
stable periods punctuated by a small number of sharp transitions (i.e., rising
and falling edges). This insight motivates BurstMon, a microsecond-resolution
telemetry system that detects change points directly in the data plane and
reconstructs per-flow rate curves via sparse event reporting and control-plane
interpolation.

BurstMon introduces two key advances over prior rotating-sketch systems: (1) a
time-sketch with dual-purpose per-cell timestamps that unify logical lazy
clearing and transition-driven chi-square triggering, eliminating dedicated
cleaning sketches; and (2) a complete event-domain telemetry pipeline—from
in-switch change-point detection via logarithmic-projection-based chi-square
testing, through minimal digest reporting, to control-plane curve
reconstruction. We provide formal guarantees on false-positive rate and
stable-period reconstruction error.

Implemented on an Intel Tofino switch and evaluated on four
production-inspired workloads, BurstMon achieves over 95% cosine similarity at
10–80µs resolution, maintains control-plane bandwidth below 0.07Gbps, and
delivers response latency of ∼410µs—much faster than µMon. We demonstrate its
value through congestion attribution, pulse-wave DDoS detection, elephant flow
steering, and proactive congestion signaling.

## Repository structure

```text
.
├── README.md                              Reproduction entry point
├── paper/
│   └── nsdi_v3_marked.pdf                 Reference paper
├── datasets/
│   ├── hadoop15.csv                       Hadoop trace
│   └── websearch25.csv                    Web-search trace
├── burstmon_simulation/
│   ├── __main__.py                        Python module entry point
│   ├── cli.py                             CLI configuration
│   └── simulator.py                       Simulation and reconstruction
├── tofino_optimization/
│   └── optimized/
│       ├── burstmon_optimized.p4           Shared P4 pipeline
│       ├── burstmon_dataset_replay_10us_32bit.p4
│       ├── common/                         Shared P4 headers
│       ├── runtime/                        LUT loader and tests
│       ├── replay_runtime/                 Replay and reconstruction
│       └── replay_runtime_10us_32bit/      Specialized replay runtime
├── tofino_score_accuracy/
│   ├── burstmon_score_eval.p4             Score-evaluation P4 program
│   └── runtime/                            Accuracy runtime and tests
├── run_python_simulation.sh              Python reproduction wrapper
├── run_tofino_10us_32bit.sh              Tofino replay wrapper
└── run_tofino_score_accuracy.sh           Score-accuracy wrapper
```

Run all commands from the repository root.

## Runtime environment

The repository has two distinct execution environments:

### Local Python simulation (no hardware required)

| Item | Value |
|------|-------|
| OS | Linux (any modern distribution) |
| Python | 3.11.5 (3.9+ expected to work) |
| Dependency | numpy 1.24.3 (pinned in `requirements.txt`) |
| Inputs | Static CSV datasets bundled in `datasets/` |


### Tofino1 hardware runs (replay and score accuracy)

| Item | Value |
|------|-------|
| Switch | Intel Tofino1 (tested on `192.168.30.252`) |
| SDE | 9.7.0 (`/root/bf-sde-9.7.0`) |
| Remote Python | SDE 9.7.0 bundles Python 3.5; replay runtime is standard-library only |
| Access | SSH root (key or interactive password; never stored) |
| Driver swap | `bf_kdrv` (normal) <-> `bf_kpkt` (replay), restored on every exit |


Both `.sh` wrappers run a fixed 7-step workflow (connect -> upload -> compile ->
switch program -> program LUTs -> replay/evaluate -> collect results -> restore).

## Local Python simulation

Install the Python dependency and reproduce both included datasets:

```bash
python3 -m pip install -r requirements.txt
./run_python_simulation.sh
```

Run a shorter smoke reproduction:

```bash
MAX_PACKETS=100000 ./run_python_simulation.sh
```

Override simulation parameters when needed:

```bash
TIMESTEP=10000 \
DEPTH=12 \
WIDTH=6451 \
HADOOP_THRESHOLD=200 \
WEBSEARCH_THRESHOLD=256 \
OUTPUT_DIR="$PWD/simulation_results/custom_run" \
./run_python_simulation.sh
```

## Tofino dataset replay

This command requires an authorized Tofino1 switch with SDE 9.7.0. It changes
the active switch program during the run and restores the configured program
on exit.

```bash
./run_tofino_10us_32bit.sh --help
./run_tofino_10us_32bit.sh
```

Reproduce Hadoop15 with explicit connection and output settings:

```bash
TOFINO_HOST=192.168.30.252 \
TOFINO_PORT=22 \
TOFINO_USER=root \
REMOTE_SDE=/root/bf-sde-9.7.0 \
REMOTE_CODE=/root/bf-sde-9.7.0/CYC_P4/BurstMon_final \
DATASETS=hadoop15.csv \
THRESHOLD=32 \
OUTPUT_DIR="$PWD/tofino_optimization/results/hadoop15_reproduction" \
./run_tofino_10us_32bit.sh
```

Use an SSH key or enter the password interactively. No password is stored by
the script.

## Tofino score-accuracy reproduction

```bash
./run_tofino_score_accuracy.sh --help
./run_tofino_score_accuracy.sh
```

Override the sample count, seed, or output directory:

```bash
SAMPLE_COUNT=2048 \
SEED=20260806 \
OUTPUT_DIR="$PWD/tofino_score_accuracy/results/custom_run" \
./run_tofino_score_accuracy.sh
```
