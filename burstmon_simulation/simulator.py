"""A focused Python simulation of the BurstMon paper.

The implementation follows Sections 4 and 5 of the paper and deliberately
does not modify or depend on the reference implementation, plotting, or
baseline-comparison code. Time is represented
in the same integer unit as the input CSV.  Volumes are stored as bytes and
converted to Gbps only when reconstruction metrics are calculated.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Hashable, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

import numpy as np


FlowId = Hashable
SCORE_SCALING_PROFILES = {
    "paper": (16, "after_delta"),
    "tofino-10us": (6, "before_delta"),
    "unscaled": (0, "after_delta"),
}


@dataclass(frozen=True)
class BurstMonConfig:
    """Simulation parameters.

    ``timestep`` uses the input timestamp unit.  The paper uses three rotating
    time-sketches, so that number is intentionally not configurable.
    """

    depth: int = 3
    width: int = 4096
    timestep: int = 10_000
    threshold: float = 200.0
    timestamp_unit: str = "ns"
    score_mode: str = "exact"
    log_scale: int = 512
    scaling_profile: str = "paper"
    score_downshift: Optional[int] = None
    score_shift_order: Optional[str] = None
    cumulative_counter_bits: int = 16
    report_bytes: int = 24
    metric_min_active_windows: int = 3
    metric_min_packets: int = 1
    metric_min_continuity: float = 0.6
    seed: int = 0

    def __post_init__(self) -> None:
        if self.depth <= 0 or self.width <= 0:
            raise ValueError("depth and width must be positive")
        if self.timestep <= 0:
            raise ValueError("timestep must be positive")
        if self.threshold < 0:
            raise ValueError("threshold must be non-negative")
        if self.timestamp_unit not in {"ns", "us"}:
            raise ValueError("timestamp_unit must be 'ns' or 'us'")
        if self.score_mode not in {"exact", "log"}:
            raise ValueError("score_mode must be 'exact' or 'log'")
        if self.log_scale <= 0:
            raise ValueError("log_scale must be positive")
        if self.scaling_profile not in {*SCORE_SCALING_PROFILES, "custom"}:
            raise ValueError("unknown scaling_profile")
        if self.scaling_profile == "custom":
            if self.score_downshift is None or self.score_shift_order is None:
                raise ValueError(
                    "custom scaling requires score_downshift and score_shift_order"
                )
            resolved_shift = self.score_downshift
            resolved_order = self.score_shift_order
        else:
            preset_shift, preset_order = SCORE_SCALING_PROFILES[self.scaling_profile]
            resolved_shift = (
                preset_shift if self.score_downshift is None else self.score_downshift
            )
            resolved_order = (
                preset_order if self.score_shift_order is None else self.score_shift_order
            )
            if (resolved_shift, resolved_order) != (preset_shift, preset_order):
                object.__setattr__(self, "scaling_profile", "custom")
        object.__setattr__(self, "score_downshift", resolved_shift)
        object.__setattr__(self, "score_shift_order", resolved_order)
        if resolved_shift < 0:
            raise ValueError("score_downshift must be non-negative")
        if resolved_order not in {"after_delta", "before_delta"}:
            raise ValueError("score_shift_order must be 'after_delta' or 'before_delta'")
        if self.cumulative_counter_bits <= 0 or self.cumulative_counter_bits % 8:
            raise ValueError("cumulative_counter_bits must be a positive multiple of 8")
        if self.report_bytes <= 0:
            raise ValueError("report_bytes must be positive")
        if self.metric_min_active_windows <= 0 or self.metric_min_packets <= 0:
            raise ValueError("metric flow filters must be positive")
        if not 0 <= self.metric_min_continuity <= 1:
            raise ValueError("metric_min_continuity must be between 0 and 1")

    @property
    def timestep_seconds(self) -> float:
        scale = 1e-9 if self.timestamp_unit == "ns" else 1e-6
        return self.timestep * scale

    @property
    def timestep_us(self) -> float:
        scale = 1e-3 if self.timestamp_unit == "ns" else 1.0
        return self.timestep * scale

    @property
    def sketch_memory_bytes(self) -> int:
        """Data-plane model: three Time-Sketches plus the cumulative CMS."""

        cells = self.depth * self.width
        time_sketch_bytes = 3 * (4 + 2)  # 32-bit volume + 16-bit timestamp
        cumulative_bytes = self.cumulative_counter_bits // 8
        return cells * (time_sketch_bytes + cumulative_bytes)


@dataclass(frozen=True)
class Packet:
    flow_id: FlowId
    length: int
    timestamp: int


@dataclass(frozen=True)
class BurstEvent:
    flow_id: FlowId
    trigger_timestamp: int
    current_window: int
    completed_window: int
    r_i: int
    r_i_1: int
    delta: int
    cumulative_delta: int
    score_delta: int
    score_cumulative_delta: int
    exact_score: float
    decision_score: float
    reason: str


@dataclass(frozen=True)
class ReconstructionMetrics:
    flow_id: FlowId
    packets: int
    first_window: int
    last_window: int
    active_windows: int
    continuity_ratio: float
    evaluated_windows: int
    reports: int
    cosine_similarity: float
    euclidean_distance_gbps: float
    energy: float
    relative_peak_error: float


@dataclass
class ApproximationMetrics:
    samples: int = 0
    accuracy_sum: float = 0.0

    def add(self, exact: float, approximate: float) -> None:
        if not (math.isfinite(exact) and math.isfinite(approximate)):
            return
        error = exact - approximate
        self.samples += 1
        if exact == 0:
            self.accuracy_sum += 1.0 if approximate == 0 else 0.0
        else:
            self.accuracy_sum += math.exp(-abs(error) / abs(exact))

    @property
    def accuracy(self) -> Optional[float]:
        return self.accuracy_sum / self.samples if self.samples else None


@dataclass
class BurstMonResult:
    config: BurstMonConfig
    packets: int
    first_timestamp: int
    last_timestamp: int
    max_window: int
    transition_checks: int
    events: List[BurstEvent]
    per_flow_metrics: List[ReconstructionMetrics]
    approximation: ApproximationMetrics
    reconstruction: Mapping[FlowId, Tuple[np.ndarray, np.ndarray, np.ndarray]] = field(
        repr=False
    )

    @property
    def duration_seconds(self) -> float:
        # Include the final observed timeslot without rounding the packet span
        # up to a whole number of windows.
        timestamp_scale = 1e-9 if self.config.timestamp_unit == "ns" else 1e-6
        packet_span = (self.last_timestamp - self.first_timestamp) * timestamp_scale
        return packet_span + self.config.timestep_seconds

    @property
    def communication_gbps(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return self.communication_payload_bits / self.duration_seconds / 1e9

    @property
    def communication_payload_bytes(self) -> int:
        """Logical report payload volume, excluding link/protocol overhead."""

        return len(self.events) * self.config.report_bytes

    @property
    def communication_payload_bits(self) -> int:
        return self.communication_payload_bytes * 8

    @property
    def report_ratio(self) -> float:
        return len(self.events) / self.transition_checks if self.transition_checks else 0.0

    def summary(self) -> dict:
        metrics = self.per_flow_metrics

        eligible = [
            item
            for item in metrics
            if item.active_windows >= self.config.metric_min_active_windows
            and item.packets >= self.config.metric_min_packets
            and item.continuity_ratio >= self.config.metric_min_continuity
            and item.reports > 0
            and item.evaluated_windows >= 2
        ]

        def finite_values(
            items: Sequence[ReconstructionMetrics], name: str
        ) -> List[float]:
            values = [float(getattr(item, name)) for item in items]
            return [value for value in values if math.isfinite(value)]

        def finite_mean(items: Sequence[ReconstructionMetrics], name: str) -> Optional[float]:
            values = finite_values(items, name)
            return float(np.mean(values)) if values else None

        def metric_statistics(name: str) -> dict:
            values = finite_values(eligible, name)
            if not values:
                return {"mean": None, "median": None, "p95": None}
            return {
                "mean": float(np.mean(values)),
                "median": float(np.median(values)),
                "p95": float(np.percentile(values, 95)),
            }

        reconstruction_metrics = {
            "eligible_flows": len(eligible),
            "cosine_similarity": metric_statistics("cosine_similarity"),
            "euclidean_distance_gbps": metric_statistics("euclidean_distance_gbps"),
            "energy": metric_statistics("energy"),
            "relative_peak_error": metric_statistics("relative_peak_error"),
        }
        communication_metrics = {
            "events": len(self.events),
            "report_payload_bytes_per_event": self.config.report_bytes,
            "total_payload_bytes": self.communication_payload_bytes,
            "total_payload_bits": self.communication_payload_bits,
            "trace_duration_seconds": self.duration_seconds,
            "average_bandwidth_gbps": self.communication_gbps,
        }

        return {
            "packets": self.packets,
            "flows": len(metrics),
            "metric_eligible_flows": len(eligible),
            "events": len(self.events),
            "transition_checks": self.transition_checks,
            "report_ratio": self.report_ratio,
            "duration_seconds": self.duration_seconds,
            "communication_payload_bytes": self.communication_payload_bytes,
            "communication_payload_bits": self.communication_payload_bits,
            "communication_gbps": self.communication_gbps,
            "sketch_memory_bytes_model": self.config.sketch_memory_bytes,
            "sketch_memory_kib_model": self.config.sketch_memory_bytes / 1024,
            "mean_cosine_similarity": finite_mean(eligible, "cosine_similarity"),
            "mean_euclidean_distance_gbps": finite_mean(
                eligible, "euclidean_distance_gbps"
            ),
            "mean_energy": finite_mean(eligible, "energy"),
            "mean_relative_peak_error": finite_mean(eligible, "relative_peak_error"),
            "all_flow_mean_cosine_similarity": finite_mean(metrics, "cosine_similarity"),
            "all_flow_mean_energy": finite_mean(metrics, "energy"),
            "log_approximation_samples": self.approximation.samples,
            "log_approximation_accuracy": self.approximation.accuracy,
            "reconstruction_metrics": reconstruction_metrics,
            "communication_metrics": communication_metrics,
            "config": asdict(self.config),
        }

    def write(self, output_dir: Path | str, include_reconstruction: bool = False) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)

        with (output / "summary.json").open("w", encoding="utf-8") as handle:
            json.dump(self.summary(), handle, indent=2, ensure_ascii=False, allow_nan=False)

        event_fields = [field.name for field in BurstEvent.__dataclass_fields__.values()]
        with (output / "reports.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=event_fields)
            writer.writeheader()
            writer.writerows(asdict(event) for event in self.events)

        metric_fields = [field.name for field in ReconstructionMetrics.__dataclass_fields__.values()]
        with (output / "per_flow_metrics.csv").open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=metric_fields)
            writer.writeheader()
            writer.writerows(asdict(metric) for metric in self.per_flow_metrics)

        if include_reconstruction:
            with (output / "reconstruction.csv").open(
                "w", newline="", encoding="utf-8"
            ) as handle:
                writer = csv.writer(handle)
                writer.writerow(["flow_id", "window", "ground_truth_gbps", "reconstructed_gbps"])
                for flow_id, (windows, ground_truth, reconstructed) in self.reconstruction.items():
                    for window, truth, rebuilt in zip(windows, ground_truth, reconstructed):
                        writer.writerow([flow_id, int(window), float(truth), float(rebuilt)])


class TimeSketch:
    """CMS cells augmented with timestamps for lazy clearing."""

    def __init__(self, depth: int, width: int) -> None:
        self.depth = depth
        self.width = width
        self.values = np.zeros((depth, width), dtype=np.uint64)
        self.timestamps = np.full((depth, width), -1, dtype=np.int64)

    def is_current(self, indices: Sequence[int], window: int) -> bool:
        return all(self.timestamps[row, index] == window for row, index in enumerate(indices))

    def update(self, indices: Sequence[int], window: int, length: int) -> None:
        for row, index in enumerate(indices):
            if self.timestamps[row, index] != window:
                self.values[row, index] = length
                self.timestamps[row, index] = window
            else:
                self.values[row, index] += length

    def query(self, indices: Sequence[int], expected_window: int) -> int:
        value = self.query_if_current(indices, expected_window)
        return 0 if value is None else value

    def query_if_current(
        self, indices: Sequence[int], expected_window: int
    ) -> Optional[int]:
        """Return a value only when every row belongs to the requested window."""

        estimates = []
        for row, index in enumerate(indices):
            if self.timestamps[row, index] == expected_window:
                estimates.append(int(self.values[row, index]))
            else:
                # A real flow update touches every row. One stale row proves
                # that this flow/window has no valid measurement.
                return None
        return min(estimates)


class CountMinSketch:
    def __init__(self, depth: int, width: int) -> None:
        self.values = np.zeros((depth, width), dtype=np.uint64)

    def update(self, indices: Sequence[int], amount: int) -> None:
        for row, index in enumerate(indices):
            self.values[row, index] += amount

    def query(self, indices: Sequence[int]) -> int:
        return min(int(self.values[row, index]) for row, index in enumerate(indices))


class StableHasher:
    """Deterministic per-row hashes; unlike Python's hash(), stable across runs."""

    _MASK = (1 << 64) - 1

    def __init__(self, depth: int, width: int, seed: int = 0) -> None:
        self.depth = depth
        self.width = width
        self.seed = seed & self._MASK
        self._flow_cache: Dict[FlowId, int] = {}

    @classmethod
    def _mix64(cls, value: int) -> int:
        value = (value + 0x9E3779B97F4A7C15) & cls._MASK
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & cls._MASK
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & cls._MASK
        return value ^ (value >> 31)

    def _flow_value(self, flow_id: FlowId) -> int:
        cached = self._flow_cache.get(flow_id)
        if cached is not None:
            return cached
        if isinstance(flow_id, (int, np.integer)):
            value = int(flow_id) & self._MASK
        else:
            digest = hashlib.blake2b(str(flow_id).encode("utf-8"), digest_size=8).digest()
            value = int.from_bytes(digest, "big")
        self._flow_cache[flow_id] = value
        return value

    def indices(self, flow_id: FlowId) -> List[int]:
        base = self._flow_value(flow_id)
        return [
            self._mix64(base ^ self.seed ^ ((row + 1) * 0xD6E8FEB86659FD93)) % self.width
            for row in range(self.depth)
        ]


def exact_burst_score(delta: int, cumulative_delta: int, observation: int) -> float:
    """Equation (3), with the paper's direct-report cold-start behavior."""

    if cumulative_delta == 0 or observation <= 1:
        return math.inf
    numerator = abs(delta * observation - cumulative_delta)
    denominator = math.sqrt(cumulative_delta * (observation - 1))
    return numerator / denominator


def _quantized_log2(value: float, scale: int) -> float:
    if value <= 0:
        return -math.inf
    return math.floor(scale * math.log2(value)) / scale


def logarithmic_projection_score(
    delta: int, cumulative_delta: int, observation: int, scale: int
) -> float:
    """High-level simulation of Section 4.3's log-projection pipeline.

    The paper does not publish the nine concrete lookup tables, so this models
    their stated floor(k*log2(x)) quantization rather than pretending to be
    bit-for-bit equivalent to the P4 tables.
    """

    if cumulative_delta == 0 or observation <= 1:
        return math.inf
    if delta == 0:
        approximate_at = 0.0
    else:
        approximate_at = 2 ** (
            _quantized_log2(delta, scale) + _quantized_log2(observation, scale)
        )
    numerator = abs(approximate_at - cumulative_delta)
    if numerator == 0:
        return 0.0
    log_numerator = _quantized_log2(numerator, scale)
    log_denominator = 0.5 * (
        _quantized_log2(cumulative_delta, scale)
        + _quantized_log2(observation - 1, scale)
    )
    return 2 ** (log_numerator - log_denominator)


class BurstMonSimulator:
    def __init__(self, config: BurstMonConfig) -> None:
        self.config = config
        self.time_sketches = [TimeSketch(config.depth, config.width) for _ in range(3)]
        # The raw sketch is retained for report diagnostics. The score sketch
        # mirrors the Tofino path that accumulates already-scaled differences.
        self.delta_sketch = CountMinSketch(config.depth, config.width)
        self.score_delta_sketch = CountMinSketch(config.depth, config.width)
        self.hasher = StableHasher(config.depth, config.width, config.seed)
        self.base_timestamp: Optional[int] = None
        self.last_timestamp: Optional[int] = None
        self.max_window = 0
        self.packets = 0
        self.transition_checks = 0
        self.events: List[BurstEvent] = []
        self.ground_truth: Dict[FlowId, Dict[int, int]] = {}
        self.flow_packet_counts: Dict[FlowId, int] = {}
        self.approximation = ApproximationMetrics()

    def process(self, packet: Packet) -> None:
        if packet.length < 0:
            raise ValueError("packet length must be non-negative")
        if self.base_timestamp is None:
            self.base_timestamp = packet.timestamp
        if self.last_timestamp is not None and packet.timestamp < self.last_timestamp:
            raise ValueError("input packets must be sorted by timestamp")
        self.last_timestamp = packet.timestamp

        window = (packet.timestamp - self.base_timestamp) // self.config.timestep
        self.max_window = max(self.max_window, window)
        self.packets += 1
        truth = self.ground_truth.setdefault(packet.flow_id, {})
        truth[window] = truth.get(window, 0) + packet.length
        self.flow_packet_counts[packet.flow_id] = self.flow_packet_counts.get(packet.flow_id, 0) + 1

        indices = self.hasher.indices(packet.flow_id)
        current_sketch = self.time_sketches[window % 3]
        first_for_flow_window = not current_sketch.is_current(indices, window)

        if first_for_flow_window and window > 0:
            self._detect(packet, indices, window)

        current_sketch.update(indices, window, packet.length)

    def _detect(self, packet: Packet, indices: Sequence[int], current_window: int) -> None:
        self.transition_checks += 1
        completed = current_window - 1
        previous = completed - 1
        r_i = self.time_sketches[completed % 3].query_if_current(indices, completed)
        if r_i is None:
            # The flow did not occur in the just-completed window. Reporting
            # (0, 0) here would create a false anchor after an inactive gap.
            return
        previous_value = (
            self.time_sketches[previous % 3].query_if_current(indices, previous)
            if previous >= 0
            else None
        )
        r_i_1 = 0 if previous_value is None else previous_value
        delta = abs(r_i - r_i_1)
        self.delta_sketch.update(indices, delta)
        cumulative = self.delta_sketch.query(indices)

        # Mathematical timeslots start at one. For zero-based window indices,
        # current_window is therefore the observation count i in Equation (3).
        observation = current_window
        shift = self.config.score_downshift
        if self.config.score_shift_order == "before_delta":
            # Latest 10-us Tofino path: shrink each 32-bit window counter to
            # 16 bits first, then take and accumulate the scaled difference.
            score_delta = abs((r_i >> shift) - (r_i_1 >> shift))
            self.score_delta_sketch.update(indices, score_delta)
            score_cumulative = self.score_delta_sketch.query(indices)
        else:
            # Paper path: calculate a_i and s_i in the original units, then
            # apply the stated right shift before Equation (3).
            score_delta = delta >> shift
            score_cumulative = cumulative >> shift
        exact = exact_burst_score(score_delta, score_cumulative, observation)
        approximate = logarithmic_projection_score(
            score_delta, score_cumulative, observation, self.config.log_scale
        )
        self.approximation.add(exact, approximate)
        decision = approximate if self.config.score_mode == "log" else exact

        if not math.isfinite(decision):
            reason = "cold_start"
        elif decision > self.config.threshold:
            reason = "threshold"
        else:
            return

        self.events.append(
            BurstEvent(
                flow_id=packet.flow_id,
                trigger_timestamp=packet.timestamp,
                current_window=current_window,
                completed_window=completed,
                r_i=r_i,
                r_i_1=r_i_1,
                delta=delta,
                cumulative_delta=cumulative,
                score_delta=score_delta,
                score_cumulative_delta=score_cumulative,
                exact_score=exact,
                decision_score=decision,
                reason=reason,
            )
        )

    def finish(self) -> BurstMonResult:
        if not self.packets or self.base_timestamp is None or self.last_timestamp is None:
            raise ValueError("cannot finish an empty simulation")
        reconstruction, metrics = reconstruct_and_measure(
            self.ground_truth, self.flow_packet_counts, self.events, self.config
        )
        return BurstMonResult(
            config=self.config,
            packets=self.packets,
            first_timestamp=self.base_timestamp,
            last_timestamp=self.last_timestamp,
            max_window=self.max_window,
            transition_checks=self.transition_checks,
            events=list(self.events),
            per_flow_metrics=metrics,
            approximation=self.approximation,
            reconstruction=reconstruction,
        )


def paper_metrics(ground_truth: np.ndarray, reconstructed: np.ndarray) -> Tuple[float, float, float, float]:
    """Equation (7): COS, ED, symmetric Energy, and paper-defined RPE."""

    truth = np.asarray(ground_truth, dtype=np.float64)
    rebuilt = np.asarray(reconstructed, dtype=np.float64)
    if truth.shape != rebuilt.shape:
        raise ValueError("metric vectors must have the same shape")
    truth_energy = float(np.dot(truth, truth))
    rebuilt_energy = float(np.dot(rebuilt, rebuilt))
    if truth_energy == 0 and rebuilt_energy == 0:
        cosine = energy = 1.0
    elif truth_energy == 0 or rebuilt_energy == 0:
        cosine = energy = 0.0
    else:
        cosine = float(np.dot(truth, rebuilt) / math.sqrt(truth_energy * rebuilt_energy))
        energy = min(truth_energy / rebuilt_energy, rebuilt_energy / truth_energy)
    distance = float(np.linalg.norm(truth - rebuilt))
    true_peak = float(np.max(truth)) if len(truth) else 0.0
    rebuilt_peak = float(np.max(rebuilt)) if len(rebuilt) else 0.0
    if rebuilt_peak == 0:
        rpe = 0.0 if true_peak == 0 else math.inf
    else:
        # This intentionally follows Equation (7), whose denominator is max(f_hat).
        rpe = abs(true_peak - rebuilt_peak) / rebuilt_peak
    return cosine, distance, energy, rpe


def reconstruct_and_measure(
    ground_truth: Mapping[FlowId, Mapping[int, int]],
    flow_packet_counts: Mapping[FlowId, int],
    events: Sequence[BurstEvent],
    config: BurstMonConfig,
) -> Tuple[
    Dict[FlowId, Tuple[np.ndarray, np.ndarray, np.ndarray]],
    List[ReconstructionMetrics],
]:
    events_by_flow: Dict[FlowId, List[BurstEvent]] = {}
    for event in events:
        events_by_flow.setdefault(event.flow_id, []).append(event)

    reconstruction: Dict[FlowId, Tuple[np.ndarray, np.ndarray, np.ndarray]] = {}
    metrics: List[ReconstructionMetrics] = []
    volume_to_gbps = 8 / (config.timestep_seconds * 1e9)

    for flow_id, sparse_truth in ground_truth.items():
        first_window = min(sparse_truth)
        last_window = max(sparse_truth)
        active_window_numbers = sorted(sparse_truth)
        if len(active_window_numbers) < 2:
            continuity_ratio = 0.0
        else:
            consecutive = sum(
                right == left + 1
                for left, right in zip(active_window_numbers, active_window_numbers[1:])
            )
            continuity_ratio = consecutive / (len(active_window_numbers) - 1)

        anchors: Dict[int, float] = {}
        flow_events = events_by_flow.get(flow_id, [])
        for event in flow_events:
            anchors[event.completed_window] = float(event.r_i)
            if event.completed_window > 0:
                anchors[event.completed_window - 1] = float(event.r_i_1)

        # Only evaluate the interval supported by reported anchors. Constantly
        # extrapolating the first/last report over an unseen flow head or tail
        # biases every reconstruction metric.
        if anchors:
            evaluated_first = max(first_window, min(anchors))
            evaluated_last = min(last_window, max(anchors))
        else:
            evaluated_first, evaluated_last = 1, 0

        if evaluated_first <= evaluated_last:
            windows = np.arange(evaluated_first, evaluated_last + 1, dtype=np.int64)
            truth_volumes = np.array(
                [sparse_truth.get(int(window), 0) for window in windows], dtype=np.float64
            )
            anchor_windows = np.array(sorted(anchors), dtype=np.float64)
            anchor_values = np.array([anchors[int(window)] for window in anchor_windows])
            rebuilt_volumes = np.interp(windows, anchor_windows, anchor_values)
            truth_gbps = truth_volumes * volume_to_gbps
            rebuilt_gbps = rebuilt_volumes * volume_to_gbps
            cosine, distance, energy, rpe = paper_metrics(truth_gbps, rebuilt_gbps)
        else:
            windows = np.array([], dtype=np.int64)
            truth_gbps = np.array([], dtype=np.float64)
            rebuilt_gbps = np.array([], dtype=np.float64)
            cosine = distance = energy = rpe = math.nan
        reconstruction[flow_id] = (windows, truth_gbps, rebuilt_gbps)
        metrics.append(
            ReconstructionMetrics(
                flow_id=flow_id,
                packets=flow_packet_counts.get(flow_id, 0),
                first_window=first_window,
                last_window=last_window,
                active_windows=len(sparse_truth),
                continuity_ratio=continuity_ratio,
                evaluated_windows=len(windows),
                reports=len(flow_events),
                cosine_similarity=cosine,
                euclidean_distance_gbps=distance,
                energy=energy,
                relative_peak_error=rpe,
            )
        )

    metrics.sort(key=lambda item: str(item.flow_id))
    return reconstruction, metrics


_HEADER_ALIASES = {
    "id": "flow_id",
    "flowid": "flow_id",
    "length": "length",
    "len": "length",
    "packetsize": "length",
    "timestamp": "timestamp",
    "time": "timestamp",
    "t": "timestamp",
}


def _normalized_header(value: str) -> str:
    return "".join(character for character in value.strip().lower() if character.isalnum())


def _parse_flow_id(value: str) -> FlowId:
    stripped = value.strip()
    try:
        return int(stripped)
    except ValueError:
        return stripped


def read_packets(path: Path | str, max_packets: Optional[int] = None) -> Iterator[Packet]:
    """Read the headered and headerless CSV layouts included in this repository."""

    with Path(path).open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            first = next(reader)
        except StopIteration:
            return

        normalized = [_normalized_header(value) for value in first]
        mapped = [_HEADER_ALIASES.get(value) for value in normalized]
        has_header = all(required in mapped for required in ("flow_id", "length", "timestamp"))
        if has_header:
            positions = {name: mapped.index(name) for name in ("flow_id", "length", "timestamp")}
            rows: Iterable[Sequence[str]] = reader
        else:
            if len(first) < 3:
                raise ValueError("CSV rows must contain flow ID, packet length, and timestamp")
            positions = {"flow_id": 0, "length": 1, "timestamp": 2}
            rows = _prepend(first, reader)

        packet_count = 0
        for row_number, row in enumerate(rows, start=1):
            if not row or all(not value.strip() for value in row):
                continue
            if max_packets is not None and packet_count >= max_packets:
                break
            try:
                packet = Packet(
                    flow_id=_parse_flow_id(row[positions["flow_id"]]),
                    length=int(float(row[positions["length"]])),
                    timestamp=int(float(row[positions["timestamp"]])),
                )
            except (IndexError, ValueError) as error:
                raise ValueError(f"invalid CSV row {row_number}: {row}") from error
            yield packet
            packet_count += 1


def _prepend(first: Sequence[str], rows: Iterable[Sequence[str]]) -> Iterator[Sequence[str]]:
    yield first
    yield from rows


def run_csv(
    input_path: Path | str,
    config: BurstMonConfig,
    max_packets: Optional[int] = None,
) -> BurstMonResult:
    simulator = BurstMonSimulator(config)
    for packet in read_packets(input_path, max_packets=max_packets):
        simulator.process(packet)
    return simulator.finish()
