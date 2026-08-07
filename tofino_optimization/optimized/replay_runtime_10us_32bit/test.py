"""8.192 us BurstMon replay with raw 32-bit volume counters.

The P4 data plane retains and reports the original byte counts. It divides the
two score inputs by 64 before converting them to 16 bits.
"""

from __future__ import print_function

import imp
import os
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
BASE_RUNTIME = os.path.abspath(os.path.join(HERE, "..", "replay_runtime"))
if BASE_RUNTIME not in sys.path:
    sys.path.insert(0, BASE_RUNTIME)
BASE_TEST = os.path.join(BASE_RUNTIME, "test.py")
base = imp.load_source("burstmon_replay_10us_32bit_base", BASE_TEST)

base.P4_NAME = "burstmon_dataset_replay_10us_32bit"
base.TIMESTEP_NS = 8192
base.MIRROR_PACKET_BYTES = 32
base.REPORT_CAPACITY = 4096
base.LOAD_DELTA_ABS_TABLE = True
base.COUNTER_BITS = 32
base.SCORE_INPUT_SHIFT = 6
base.SKETCH_WIDTH = 8192
base.RAW_TIMESTAMP_REPLAY = True
base.RAW_TIMESTAMP_SHIFT_BITS = 13
base.REPORT_WINDOW_OFFSET = 0


class BurstMonDatasetReplay10us32bit(base.BurstMonDatasetReplay):
    """PTF entry point for the 8.192 us/32-bit timestamp-slice build."""

    pass
