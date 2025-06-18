# Programmable Switch Telemetry at Microsecond Granularity: BurstMon in Action

Modern high-speed networks exhibit highly dynamic traffic behaviors, where microsecond-scale bursts and rate shifts can significantly impact congestion control, scheduling, and anomaly response. However, most existing telemetry systems operate at millisecond granularity and rely on periodic sampling or sketch-based aggregation, which miss critical fine-grained events. Achieving microsecond-level visibility at scale remains challenging due to limited compute, memory, and bandwidth in network devices.

We present **{BurstMon}**, a microsecond-resolution telemetry system that performs real-time burst detection in the data plane and reconstructs per-flow traffic curves in the control plane via sparse event reporting. BurstMon is based on the key observation that most traffic is stable, punctuated by short-lived bursts. It identifies statistically significant rate deviations using a lightweight chi-square test and reports only high-signal change points. The control plane interpolates between these sparse points to reconstruct accurate flow trajectories.

To support efficient in-switch execution, BurstMon introduces: (1) a ** time-sketch ** structure with a three-rotation scheme for continuous rate tracking; (2) a hybrid arithmetic approximation method combining lookup tables and logarithmic projection; and (3) a minimal reporting interface for scalable control-plane integration. These techniques effectively address data-plane resource constraints by minimizing per-packet processing overhead and memory usage.

We implement BurstMon on an Intel Tofino switch and evaluate it using production-inspired workloads. At 10~$\mu$s resolution, it achieves over 95\% per-flow traffic reconstruction accuracy while maintaining control-plane bandwidth under 0.07~Gbps 
with negligible impact on the switch's forwarding throughput.
