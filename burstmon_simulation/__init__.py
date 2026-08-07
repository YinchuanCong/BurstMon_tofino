"""Paper-faithful BurstMon simulator kept outside the reference repositories.

This package intentionally contains only the main BurstMon pipeline described
in the paper: time-sketch measurement, chi-square change detection, sparse
reporting, control-plane reconstruction, and evaluation metrics.
"""

from .simulator import (
    BurstEvent,
    BurstMonConfig,
    BurstMonResult,
    BurstMonSimulator,
    ReconstructionMetrics,
    run_csv,
)

__all__ = [
    "BurstEvent",
    "BurstMonConfig",
    "BurstMonResult",
    "BurstMonSimulator",
    "ReconstructionMetrics",
    "run_csv",
]
