from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from .simulator import SCORE_SCALING_PROFILES, BurstMonConfig, run_csv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the paper-faithful BurstMon main-pipeline simulation."
    )
    parser.add_argument("--input", required=True, type=Path, help="Input packet CSV")
    parser.add_argument("--output-dir", type=Path, help="Write CSV/JSON results here")
    parser.add_argument("--timestep", required=True, type=int, help="Timeslot in timestamp units")
    parser.add_argument("--threshold", required=True, type=float, help="Burst score threshold T")
    parser.add_argument("--depth", type=int, default=3, help="Sketch hash rows (default: 3)")
    parser.add_argument("--width", type=int, default=4096, help="Sketch width (default: 4096)")
    parser.add_argument(
        "--timestamp-unit", choices=("ns", "us"), default="ns", help="Input timestamp unit"
    )
    parser.add_argument(
        "--score-mode",
        choices=("exact", "log"),
        default="exact",
        help="Use Equation (3) or the high-level log-projection model for decisions",
    )
    parser.add_argument("--log-scale", type=int, default=512, help="Log projection k")
    parser.add_argument(
        "--scaling-profile",
        choices=tuple(SCORE_SCALING_PROFILES),
        default="paper",
        help=(
            "Score scaling preset: paper=shift a/s by 16, "
            "tofino-10us=shift 32-bit window counters by 6 before delta, "
            "unscaled=no shift (default: paper)"
        ),
    )
    parser.add_argument(
        "--score-downshift",
        type=int,
        help="Override the selected profile's right-shift amount",
    )
    parser.add_argument(
        "--score-shift-order",
        choices=("after_delta", "before_delta"),
        help="Override whether scaling occurs before or after delta calculation",
    )
    parser.add_argument(
        "--cumulative-counter-bits",
        type=int,
        default=16,
        help="Cumulative variation CMS width used by memory accounting (default: 16)",
    )
    parser.add_argument(
        "--report-bytes",
        type=int,
        default=24,
        help="Logical report payload bytes; P4 mirror_h is 24 bytes",
    )
    parser.add_argument(
        "--metric-min-active-windows",
        type=int,
        default=3,
        help="Minimum active windows for inclusion in aggregate metrics",
    )
    parser.add_argument(
        "--metric-min-packets",
        type=int,
        default=1,
        help="Minimum packets for inclusion in aggregate metrics",
    )
    parser.add_argument(
        "--metric-min-continuity",
        type=float,
        default=0.6,
        help="Minimum consecutive-active-window ratio for aggregate metrics",
    )
    parser.add_argument("--max-packets", type=int, help="Read only the first N packets")
    parser.add_argument(
        "--include-reconstruction",
        action="store_true",
        help="Write per-window reconstructed curves (can be large)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = BurstMonConfig(
        depth=args.depth,
        width=args.width,
        timestep=args.timestep,
        threshold=args.threshold,
        timestamp_unit=args.timestamp_unit,
        score_mode=args.score_mode,
        log_scale=args.log_scale,
        scaling_profile=args.scaling_profile,
        score_downshift=args.score_downshift,
        score_shift_order=args.score_shift_order,
        cumulative_counter_bits=args.cumulative_counter_bits,
        report_bytes=args.report_bytes,
        metric_min_active_windows=args.metric_min_active_windows,
        metric_min_packets=args.metric_min_packets,
        metric_min_continuity=args.metric_min_continuity,
    )
    result = run_csv(args.input, config, max_packets=args.max_packets)
    if args.output_dir:
        result.write(args.output_dir, include_reconstruction=args.include_reconstruction)
    print(json.dumps(result.summary(), indent=2, ensure_ascii=False, allow_nan=False))
    return 0
