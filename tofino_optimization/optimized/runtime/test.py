"""Program every BurstMon rotation/arithmetic table through BF Runtime.

Typical SDE invocation (after burstmon_optimized is running):

  ./run_p4_tests.sh -p burstmon_optimized \
      -t CYC_P4/BurstMon_final/runtime \
      --test-params="arch='tofino';num_pipes=4;threshold=12;mirror_port=184"
"""

from __future__ import print_function

import logging
import math

import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest
from ptf.testutils import test_param_get

from lut_model import (
    INT16_MAX,
    SCALING_FACTOR,
    UINT16_MAX,
    binary16_to_float,
    fixed_log2,
    inverse_sqrt_binary16,
    positive_finite_binary16_values,
    rotation_slot,
    saturated_exp2,
    threshold_log_low,
    u16,
)


LOGGER = logging.getLogger("BurstMonRuntime")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

P4_NAME = "burstmon_optimized"
MIRROR_PACKET_TYPE = 2


def _param(name, default, convert):
    value = test_param_get(name)
    if value in (None, ""):
        return default
    return convert(value)


class BurstMonRuntime(BfRuntimeTest):
    """Idempotently replace all control-plane-generated BurstMon entries."""

    def setUp(self):
        BfRuntimeTest.setUp(self, 0, P4_NAME)
        self.bfrt_info = self.interface.bfrt_info_get(P4_NAME)
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.batch_size = _param("batch_size", 512, int)
        self.threshold = _param("threshold", 12.0, float)
        self.mirror_port = _param("mirror_port", 184, int)
        self.mirror_sid = _param("mirror_sid", 2, int)

    def _replace_exact(self, table_name, key_name, action_name, data_name, entries):
        table = self.bfrt_info.table_get(table_name)
        table.entry_del(self.target)
        keys = []
        values = []
        count = 0
        for key_value, data_value in entries:
            keys.append(table.make_key([gc.KeyTuple(key_name, key_value)]))
            values.append(
                table.make_data([gc.DataTuple(data_name, data_value)], action_name)
            )
            if len(keys) == self.batch_size:
                table.entry_add(self.target, keys, values)
                count += len(keys)
                keys, values = [], []
        if keys:
            table.entry_add(self.target, keys, values)
            count += len(keys)
        LOGGER.info("loaded %-48s %d entries", table_name, count)

    @staticmethod
    def _integer_logs():
        for value in range(1, UINT16_MAX + 1):
            yield value, u16(fixed_log2(value))

    @staticmethod
    def _integer_logs_plus_one():
        for value in range(UINT16_MAX + 1):
            yield value, u16(fixed_log2(min(UINT16_MAX, value + 1)))

    @staticmethod
    def _absolute_deltas():
        for bits in range(UINT16_MAX + 1):
            signed = bits if bits <= INT16_MAX else bits - (1 << 16)
            yield bits, abs(signed)

    @staticmethod
    def _exp_values():
        for encoded_log in range(0, 32 * SCALING_FACTOR + 1):
            yield encoded_log, saturated_exp2(encoded_log)

    @staticmethod
    def _inverse_sqrt_values():
        for encoded_log in range(0, 32 * SCALING_FACTOR + 1):
            yield encoded_log, inverse_sqrt_binary16(encoded_log)

    @staticmethod
    def _binary16_logs():
        for bits in positive_finite_binary16_values():
            yield bits, u16(fixed_log2(binary16_to_float(bits)))

    def _program_rotation(self):
        self._replace_exact(
            "SwitchIngress.set_time_conv_table",
            "ig_md.time",
            "SwitchIngress.set_time_conv_action",
            "conv",
            ((window, rotation_slot(window)) for window in range(UINT16_MAX + 1)),
        )
        self._replace_exact(
            "SwitchIngress.delta_abs_table",
            "ig_md.signed_delta",
            "SwitchIngress.set_abs_delta",
            "abs_delta",
            self._absolute_deltas(),
        )

    def _program_logs(self):
        integer_log_tables = (
            ("SwitchEgress.get_log_int_m1_table", "eg_md.ac_md.int_m1", "SwitchEgress.get_log_int_m1_action"),
            ("SwitchEgress.get_log_int_m2_table", "eg_md.ac_md.int_m2", "SwitchEgress.get_log_int_m2_action"),
            ("SwitchEgress.get_log_int_m2_table2", "eg_md.ac_md.int_m2", "SwitchEgress.get_log_int_m2_action"),
            ("SwitchEgress.get_log_int_m1_table3", "eg_md.ac_md.int_m1", "SwitchEgress.get_log_int_m1_action"),
        )
        for table_name, key_name, action_name in integer_log_tables:
            self._replace_exact(
                table_name, key_name, action_name, "log_int", self._integer_logs()
            )

        self._replace_exact(
            "SwitchEgress.get_log_int_m1_table2",
            "eg_md.ac_md.int_m1",
            "SwitchEgress.get_log_int_m1_action",
            "log_int",
            self._integer_logs_plus_one(),
        )

        self._replace_exact(
            "SwitchEgress.get_exp_at_table",
            "eg_md.ac_md.n",
            "SwitchEgress.get_exp_at_action",
            "value",
            self._exp_values(),
        )
        self._replace_exact(
            "SwitchEgress.get_inv_sqrt_table",
            "eg_md.ac_md.n",
            "SwitchEgress.get_inv_sqrt_action",
            "value",
            self._inverse_sqrt_values(),
        )
        self._replace_exact(
            "SwitchEgress.get_log_int_m2_table3",
            "eg_md.ac_md.int_m2",
            "SwitchEgress.get_log_int_m2_action",
            "log_int",
            self._binary16_logs(),
        )

    def _program_mirror(self):
        mirror = self.bfrt_info.table_get("$mirror.cfg")
        key = mirror.make_key([gc.KeyTuple("$sid", self.mirror_sid)])
        data = mirror.make_data(
            [
                gc.DataTuple("$direction", str_val="EGRESS"),
                gc.DataTuple("$ucast_egress_port", self.mirror_port),
                gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
                gc.DataTuple("$session_enable", bool_val=True),
                gc.DataTuple("$max_pkt_len", 128),
            ],
            "$normal",
        )
        try:
            mirror.entry_mod(self.target, [key], [data])
        except Exception:
            mirror.entry_add(self.target, [key], [data])

        report = self.bfrt_info.table_get("SwitchEgress.report_threshold_table")
        report.entry_del(self.target)
        low = threshold_log_low(self.threshold)
        key = report.make_key(
            [
                gc.KeyTuple("eg_md.ac_md.n", low=low, high=INT16_MAX),
                gc.KeyTuple("$MATCH_PRIORITY", 1),
            ]
        )
        data = report.make_data(
            [
                gc.DataTuple("pkt_type", MIRROR_PACKET_TYPE),
                gc.DataTuple("eg_mir_ses", self.mirror_sid),
            ],
            "SwitchEgress.get_mirror_cfg",
        )
        report.entry_add(self.target, [key], [data])
        LOGGER.info(
            "report score > %.6g (log2 fixed-point range %d..%d), mirror sid=%d port=%d",
            self.threshold,
            low,
            INT16_MAX,
            self.mirror_sid,
            self.mirror_port,
        )

    def runTest(self):
        LOGGER.info("loading complete BurstMon tables (scale=%d)", SCALING_FACTOR)
        self._program_rotation()
        self._program_logs()
        self._program_mirror()
        LOGGER.info("BurstMon table programming complete")
