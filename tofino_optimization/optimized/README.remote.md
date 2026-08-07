# Remote Tofino Reproduction

Run the repository-level wrapper from the repository root:

```bash
TOFINO_HOST=192.168.30.252 \
TOFINO_PORT=22 \
TOFINO_USER=root \
REMOTE_SDE=/root/bf-sde-9.7.0 \
REMOTE_CODE=/root/bf-sde-9.7.0/CYC_P4/BurstMon_final \
./run_tofino_10us_32bit.sh
```

Show all supported overrides:

```bash
./run_tofino_10us_32bit.sh --help
```

Use an SSH key or enter the password interactively. The wrapper restores the
configured switch program on exit.
