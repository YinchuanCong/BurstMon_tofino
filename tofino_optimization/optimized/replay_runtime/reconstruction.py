"""Paper-compatible traffic-curve reconstruction for Tofino reports.

This module intentionally uses only the Python standard library so it runs in
the SDE 9.7 Python 3.5 environment.  Volumes remain bytes until the final
metric conversion to Gbit/s.
"""

from __future__ import division, print_function

import bisect
import csv
import json
import math
import os


def build_timestamp_window_ranges(first_timestamp, last_timestamp,
                                  timestep_ns, window_offset=2):
    """Build 48-bit timestamp ranges with a 16-bit range-key component.

    Each logical window is split at a 2^16 boundary when necessary so the P4
    table can match the upper 32 timestamp bits exactly and range-match only
    the lower 16 bits.
    """

    if not 0 <= first_timestamp < (1 << 48):
        raise ValueError("first timestamp must fit in 48 bits")
    if not first_timestamp <= last_timestamp < (1 << 48):
        raise ValueError("last timestamp must be sorted and fit in 48 bits")
    if timestep_ns <= 0:
        raise ValueError("timestep must be positive")

    max_window = (last_timestamp - first_timestamp) // timestep_ns
    ranges = []
    for zero_based_window in range(max_window + 1):
        low = first_timestamp + zero_based_window * timestep_ns
        high = min(low + timestep_ns - 1, (1 << 48) - 1)
        cursor = low
        while cursor <= high:
            timestamp_high = cursor >> 16
            segment_high = min(high, (timestamp_high << 16) | 0xFFFF)
            ranges.append((timestamp_high, cursor & 0xFFFF,
                           segment_high & 0xFFFF,
                           zero_based_window + window_offset))
            cursor = segment_high + 1
    return ranges


def load_ground_truth(path, timestep_ns, timestamp_shift=None):
    """Return per-flow, zero-based window volumes and packet counts."""

    ground_truth = {}
    packet_counts = {}
    first_timestamp = None
    last_timestamp = None
    packets = 0
    with open(path, "r") as handle:
        for row in csv.reader(handle):
            if not row:
                continue
            try:
                flow_id = int(row[0])
                packet_length = int(row[1])
                timestamp = int(row[2])
            except ValueError:
                # Accept the repository's optional CSV header.
                continue
            if first_timestamp is None:
                first_timestamp = timestamp
            if last_timestamp is not None and timestamp < last_timestamp:
                raise ValueError("dataset timestamps are not sorted")
            last_timestamp = timestamp
            if timestamp_shift is None:
                window = (timestamp - first_timestamp) // timestep_ns
            else:
                window = ((timestamp >> timestamp_shift) -
                          (first_timestamp >> timestamp_shift))
            curve = ground_truth.setdefault(flow_id, {})
            curve[window] = curve.get(window, 0) + packet_length
            packet_counts[flow_id] = packet_counts.get(flow_id, 0) + 1
            packets += 1
    if first_timestamp is None:
        raise ValueError("empty dataset: %s" % path)
    return ground_truth, packet_counts, {
        "packets": packets,
        "first_timestamp_ns": first_timestamp,
        "last_timestamp_ns": last_timestamp,
    }


def _interpolate(windows, anchors):
    """Linear interpolation with constant extrapolation, as in the paper."""

    if not anchors:
        return [0.0 for _ in windows]
    anchor_windows = sorted(anchors)
    result = []
    for window in windows:
        position = bisect.bisect_left(anchor_windows, window)
        if position == 0:
            result.append(float(anchors[anchor_windows[0]]))
        elif position == len(anchor_windows):
            result.append(float(anchors[anchor_windows[-1]]))
        elif anchor_windows[position] == window:
            result.append(float(anchors[window]))
        else:
            left = anchor_windows[position - 1]
            right = anchor_windows[position]
            ratio = (window - left) / float(right - left)
            result.append(anchors[left] + ratio * (anchors[right] - anchors[left]))
    return result


def paper_metrics(ground_truth, reconstructed):
    """Equation (7): COS, ED, symmetric Energy, and paper-defined RPE."""

    if len(ground_truth) != len(reconstructed):
        raise ValueError("metric vectors must have the same length")
    truth_energy = sum(value * value for value in ground_truth)
    rebuilt_energy = sum(value * value for value in reconstructed)
    if truth_energy == 0 and rebuilt_energy == 0:
        cosine = 1.0
        energy = 1.0
    elif truth_energy == 0 or rebuilt_energy == 0:
        cosine = 0.0
        energy = 0.0
    else:
        dot = sum(left * right for left, right in zip(ground_truth, reconstructed))
        cosine = dot / math.sqrt(truth_energy * rebuilt_energy)
        energy = min(truth_energy / rebuilt_energy, rebuilt_energy / truth_energy)
    distance = math.sqrt(sum(
        (left - right) * (left - right)
        for left, right in zip(ground_truth, reconstructed)
    ))
    true_peak = max(ground_truth) if ground_truth else 0.0
    rebuilt_peak = max(reconstructed) if reconstructed else 0.0
    if rebuilt_peak == 0:
        rpe = 0.0 if true_peak == 0 else float("inf")
    else:
        # Equation (7) uses the reconstructed peak as the denominator.
        rpe = abs(true_peak - rebuilt_peak) / rebuilt_peak
    return cosine, distance, energy, rpe


def _percentile(values, percent):
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percent / 100.0
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return ordered[lower]
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _statistics(metrics, field):
    values = [row[field] for row in metrics if math.isfinite(row[field])]
    if not values:
        return {"mean": None, "median": None, "p95": None}
    return {
        "mean": sum(values) / len(values),
        "median": _percentile(values, 50),
        "p95": _percentile(values, 95),
    }


def reconstruct_curves(ground_truth, packet_counts, reports, timestep_ns,
                       min_active_windows=2, min_packets=1,
                       min_continuity=0.6):
    """Reconstruct and evaluate between the first and last reported anchors."""

    reports_by_flow = {}
    for report in reports:
        reports_by_flow.setdefault(report["flow_id"], []).append(report)

    rate_factor = 8.0 / ((timestep_ns / 1e9) * 1e9)
    # Equivalent simplified form is 8/timestep_ns, retained explicitly above
    # to document the bytes -> Gbit/s unit conversion.
    curves = []
    per_flow = []
    for flow_id in sorted(ground_truth):
        sparse_truth = ground_truth[flow_id]
        flow_first_window = min(sparse_truth)
        flow_last_window = max(sparse_truth)
        anchors = {}
        flow_reports = reports_by_flow.get(flow_id, [])
        for report in flow_reports:
            completed = report["completed_window"]
            if flow_first_window <= completed <= flow_last_window:
                anchors[completed] = max(
                    anchors.get(completed, 0.0), float(report["r_i_bytes"]))
            previous = completed - 1
            if flow_first_window <= previous <= flow_last_window:
                anchors[previous] = max(
                    anchors.get(previous, 0.0), float(report["r_i_1_bytes"]))

        # The paper/reference implementation aligns ground truth only to the
        # interval covered by reports; it does not score extrapolated tails.
        if anchors:
            evaluation_first_window = min(anchors)
            evaluation_last_window = max(anchors)
        else:
            evaluation_first_window = flow_first_window
            evaluation_last_window = flow_last_window
        windows = list(range(evaluation_first_window,
                             evaluation_last_window + 1))
        truth_bytes = [float(sparse_truth.get(window, 0)) for window in windows]
        active = [window for window in windows if sparse_truth.get(window, 0) > 0]
        if len(active) < 2:
            continuity = 0.0
        else:
            consecutive = sum(
                right == left + 1 for left, right in zip(active, active[1:]))
            continuity = consecutive / float(len(active) - 1)
        rebuilt_bytes = _interpolate(windows, anchors)
        truth_gbps = [value * rate_factor for value in truth_bytes]
        rebuilt_gbps = [value * rate_factor for value in rebuilt_bytes]
        cosine, distance, energy, rpe = paper_metrics(truth_gbps, rebuilt_gbps)
        eligible = (
            len(active) >= min_active_windows
            and packet_counts.get(flow_id, 0) >= min_packets
            and continuity >= min_continuity
            and bool(flow_reports)
        )
        per_flow.append({
            "flow_id": flow_id,
            "packets": packet_counts.get(flow_id, 0),
            "first_window": flow_first_window,
            "last_window": flow_last_window,
            "evaluation_first_window": evaluation_first_window,
            "evaluation_last_window": evaluation_last_window,
            "active_windows": len(active),
            "continuity_ratio": continuity,
            "evaluated_windows": len(windows),
            "reports": len(flow_reports),
            "eligible": int(eligible),
            "cosine_similarity": cosine,
            "euclidean_distance_gbps": distance,
            "energy": energy,
            "relative_peak_error": rpe,
        })
        if flow_reports:
            for window, truth, rebuilt in zip(windows, truth_gbps, rebuilt_gbps):
                curves.append({
                    "flow_id": flow_id,
                    "window": window,
                    "ground_truth_gbps": truth,
                    "reconstructed_gbps": rebuilt,
                })

    eligible_metrics = [row for row in per_flow if row["eligible"]]
    summary = {
        "flows": len(per_flow),
        "reported_flows": len(reports_by_flow),
        "eligible_flows": len(eligible_metrics),
        "data_plane_reports": len(reports),
        "timestep_ns": timestep_ns,
        "filters": {
            "min_active_windows": min_active_windows,
            "min_packets": min_packets,
            "min_continuity": min_continuity,
            "requires_report": True,
        },
        "metrics": {
            "cosine_similarity": _statistics(eligible_metrics, "cosine_similarity"),
            "euclidean_distance_gbps": _statistics(
                eligible_metrics, "euclidean_distance_gbps"),
            "energy": _statistics(eligible_metrics, "energy"),
            "relative_peak_error": _statistics(
                eligible_metrics, "relative_peak_error"),
        },
    }
    return summary, per_flow, curves


def _write_csv(path, fieldnames, rows):
    with open(path, "w") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_dataset_outputs(output_dir, dataset_name, dataset_path, reports,
                          timestep_ns, report_capacity=1024,
                          total_reports=None, timestamp_shift=None):
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    ground_truth, packet_counts, trace = load_ground_truth(
        dataset_path, timestep_ns, timestamp_shift=timestamp_shift)
    summary, per_flow, curves = reconstruct_curves(
        ground_truth, packet_counts, reports, timestep_ns)
    summary.update(trace)
    summary.update({
        "dataset": dataset_name,
        "report_capacity": report_capacity,
        "reports_dropped_from_ring": max(
            0, (len(reports) if total_reports is None else total_reports)
            - report_capacity),
    })
    stem = os.path.splitext(os.path.basename(dataset_name))[0]
    _write_csv(
        os.path.join(output_dir, stem + "_data_plane_reports.csv"),
        ["report_index", "flow_id", "completed_window", "r_i_bytes",
         "r_i_1_bytes", "score_log", "score"],
        reports,
    )
    _write_csv(
        os.path.join(output_dir, stem + "_per_flow_metrics.csv"),
        ["flow_id", "packets", "first_window", "last_window",
         "evaluation_first_window", "evaluation_last_window",
         "active_windows", "continuity_ratio", "evaluated_windows",
         "reports", "eligible", "cosine_similarity",
         "euclidean_distance_gbps", "energy", "relative_peak_error"],
        per_flow,
    )
    _write_csv(
        os.path.join(output_dir, stem + "_reconstruction.csv"),
        ["flow_id", "window", "ground_truth_gbps", "reconstructed_gbps"],
        curves,
    )
    with open(os.path.join(output_dir, stem + "_summary.json"), "w") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    return summary
