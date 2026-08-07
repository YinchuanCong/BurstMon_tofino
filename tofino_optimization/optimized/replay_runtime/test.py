"""Replay the complete Hadoop15 and WebSearch25 traces through Tofino1.

The base build converts each CSV timestamp to a logical window in the host.
Specialized builds can instead carry the original 48-bit CSV timestamp and
divide it with exact data-plane lookup tables. In both modes, control-plane
replay speed does not alter BurstMon's rotation or anomaly calculation.
"""

from __future__ import print_function

import csv
import json
import logging
import math
import os
import struct
import sys
import time

import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest
from ptf.testutils import test_param_get


MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "runtime"))
if MODEL_DIR not in sys.path:
    sys.path.insert(0, MODEL_DIR)

from lut_model import (  # noqa: E402
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
from reconstruction import write_dataset_outputs  # noqa: E402


LOGGER = logging.getLogger("BurstMonDatasetReplay")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

P4_NAME = "burstmon_dataset_replay"
# PTF and the Tofino1 mirror block both expose the PCI CPU path as dev-port 64,
# even though register diagnostics show injected packets in the second active
# hardware-pipe value returned by BFRT.
PTF_INJECT_PORT = 64
DEFAULT_MIRROR_EGRESS_PORT = 64
TIMESTEP_NS = 2000
MIRROR_SID = 7
MIRROR_PACKET_BYTES = 28
REPORT_CAPACITY = 4096
LOAD_DELTA_ABS_TABLE = True
COUNTER_BITS = 16
SCORE_INPUT_SHIFT = 0
SKETCH_WIDTH = 1024
RAW_TIMESTAMP_REPLAY = False
RAW_TIMESTAMP_SHIFT_BITS = None
REPORT_WINDOW_OFFSET = 2

ETHERNET = bytes.fromhex("0000000000020000000000010800")
IPV4 = struct.pack("!BBHHHBBHII", 0x45, 0, 36, 0, 0, 64, 17, 0,
                   0x0A000001, 0x0A000002)
UDP = struct.pack("!HHHH", 1234, 4321, 16, 0)
PAD = bytes(10)
PACKET_PREFIX = ETHERNET + IPV4 + UDP

RAW_TIMESTAMP_IPV4 = struct.pack(
    "!BBHHHBBHII", 0x45, 0, 38, 0, 0, 64, 17, 0,
    0x0A000001, 0x0A000002)
RAW_TIMESTAMP_UDP = struct.pack("!HHHH", 1234, 4321, 18, 0)
RAW_TIMESTAMP_PAD = bytes(8)
RAW_TIMESTAMP_PACKET_PREFIX = ETHERNET + RAW_TIMESTAMP_IPV4 + RAW_TIMESTAMP_UDP


def _param(name, default, convert):
    value = test_param_get(name)
    if value in (None, ""):
        return default
    return convert(value)


class BurstMonDatasetReplay(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, P4_NAME)
        self.bfrt_info = self.interface.bfrt_info_get(P4_NAME)
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.batch_size = _param("batch_size", 512, int)
        self.threshold = _param("threshold", 32.0, float)
        self.mirror_egress_port = _param(
            "mirror_egress_port", DEFAULT_MIRROR_EGRESS_PORT, int)
        self.dataset_dir = _param(
            "dataset_dir", "/root/bf-sde-9.7.0/CYC_P4/BurstMon_final/datasets", str
        )
        self.output_path = _param(
            "output",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "tofino_dataset_replay_summary.json"),
            str,
        )
        self.reconstruction_output = _param(
            "reconstruction_output",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "reconstruction_results"),
            str,
        )
        self.report_window_origin = 0
        self.diagnose_only = _param("diagnose_only", False,
                                    lambda value: str(value).lower() == "true")
        self.skip_luts = _param("skip_luts", False,
                                lambda value: str(value).lower() == "true")
        self.max_packets = _param("max_packets", 0, int)
        self.dataset_names = _param(
            "datasets", "hadoop15.csv,websearch25.csv", str
        ).split(",")

    def _replace_exact(self, table_name, key_name, action_name, data_name, entries):
        table = self.bfrt_info.table_get(table_name)
        table.entry_del(self.target)
        keys = []
        values = []
        count = 0
        for key_value, data_value in entries:
            keys.append(table.make_key([gc.KeyTuple(key_name, key_value)]))
            values.append(table.make_data(
                [gc.DataTuple(data_name, data_value)], action_name))
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

    def _program_all_luts(self):
        if RAW_TIMESTAMP_REPLAY:
            self._program_shift_window_table()
        else:
            self._replace_exact(
                "SwitchIngress.set_time_conv_table", "ig_md.time",
                "SwitchIngress.set_time_conv_action", "conv",
                ((window, rotation_slot(window))
                 for window in range(UINT16_MAX + 1)),
            )
        if LOAD_DELTA_ABS_TABLE:
            self._replace_exact(
                "SwitchIngress.delta_abs_table", "ig_md.signed_delta",
                "SwitchIngress.set_abs_delta", "abs_delta", self._absolute_deltas(),
            )

        integer_tables = (
            ("SwitchEgress.get_log_int_m1_table", "eg_md.ac_md.int_m1"),
            ("SwitchEgress.get_log_int_m2_table", "eg_md.ac_md.int_m2"),
            ("SwitchEgress.get_log_int_m2_table2", "eg_md.ac_md.int_m2"),
            ("SwitchEgress.get_log_int_m1_table3", "eg_md.ac_md.int_m1"),
        )
        for table_name, key_name in integer_tables:
            self._replace_exact(
                table_name, key_name, "SwitchEgress.get_log_int_m1_action"
                if "m1" in table_name else "SwitchEgress.get_log_int_m2_action",
                "log_int", self._integer_logs(),
            )

        self._replace_exact(
            "SwitchEgress.get_log_int_m1_table2", "eg_md.ac_md.int_m1",
            "SwitchEgress.get_log_int_m1_action", "log_int",
            self._integer_logs_plus_one(),
        )
        self._replace_exact(
            "SwitchEgress.get_exp_at_table", "eg_md.ac_md.n",
            "SwitchEgress.get_exp_at_action", "value", self._exp_values(),
        )
        self._replace_exact(
            "SwitchEgress.get_inv_sqrt_table", "eg_md.ac_md.n",
            "SwitchEgress.get_inv_sqrt_action", "value",
            self._inverse_sqrt_values(),
        )
        self._replace_exact(
            "SwitchEgress.get_log_int_m2_table3", "eg_md.ac_md.int_m2",
            "SwitchEgress.get_log_int_m2_action", "log_int",
            self._binary16_logs(),
        )

        report = self.bfrt_info.table_get("SwitchEgress.report_threshold_table")
        report.entry_del(self.target)
        low = threshold_log_low(self.threshold)
        key = report.make_key([
            gc.KeyTuple("eg_md.ac_md.n", low=low, high=INT16_MAX),
            gc.KeyTuple("$MATCH_PRIORITY", 1),
        ])
        data = report.make_data([
            gc.DataTuple("pkt_type", 2),
            gc.DataTuple("eg_mir_ses", MIRROR_SID),
        ], "SwitchEgress.get_mirror_cfg")
        report.entry_add(self.target, [key], [data])
        LOGGER.info("configured anomaly threshold score > %.6g", self.threshold)

    def _program_shift_window_table(self):
        """Program rotation metadata for every 16-bit sliced window number."""

        table_name = "SwitchIngress.replay_timestamp_to_window_table"
        table = self.bfrt_info.table_get(table_name)
        table.entry_del(self.target)
        keys = []
        values = []
        count = 0
        for window in range(UINT16_MAX + 1):
            conv = rotation_slot(window)
            keys.append(table.make_key([
                gc.KeyTuple("ig_md.replay_window_key", window),
            ]))
            values.append(table.make_data([
                gc.DataTuple("window", window),
                gc.DataTuple("previous_window", (window - 1) & UINT16_MAX),
                gc.DataTuple("previous2_window", (window - 2) & UINT16_MAX),
                gc.DataTuple("conv", conv),
                gc.DataTuple("active_slots", 1 << conv),
            ], "SwitchIngress.set_replay_window_action"))
            if len(keys) == self.batch_size:
                table.entry_add(self.target, keys, values)
                count += len(keys)
                keys, values = [], []
        if keys:
            table.entry_add(self.target, keys, values)
            count += len(keys)
        LOGGER.info("loaded %-48s %d entries", table_name, count)

    def _program_mirror(self):
        mirror = self.bfrt_info.table_get("$mirror.cfg")
        key = mirror.make_key([gc.KeyTuple("$sid", MIRROR_SID)])
        data = mirror.make_data([
            gc.DataTuple("$direction", str_val="EGRESS"),
            gc.DataTuple("$ucast_egress_port", self.mirror_egress_port),
            gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
            gc.DataTuple("$session_enable", bool_val=True),
            # Tofino1's normal mirror-session API rejects an otherwise valid
            # session when the truncation length is omitted.
            gc.DataTuple("$max_pkt_len", 128),
        ], "$normal")
        # SDE 9.7 reports DELETE of a missing mirror SID as INVALID_ARGUMENT.
        # Treat that case as an empty initial state so cold and repeated runs
        # both converge on the same enabled session.
        try:
            mirror.entry_del(self.target, [key])
        except Exception as exc:
            LOGGER.debug("mirror SID %d was not present: %s", MIRROR_SID, exc)
        mirror.entry_add(self.target, [key], [data])

    def _clear_register(self, name):
        table = self.bfrt_info.table_get(name)
        table.entry_del(self.target)

    def _reset_state(self):
        names = []
        names += ["SwitchIngress.T_REGISTER_%d" % i for i in range(6)]
        names += ["SwitchIngress.RET_PKTCOUNT_%d" % i for i in range(6)]
        names += ["SwitchIngress.S_0", "SwitchIngress.S_1"]
        names += ["SwitchEgress.replay_evaluation_count",
                  "SwitchEgress.replay_anomaly_count",
                  "SwitchEgress.replay_report_flow",
                  "SwitchEgress.replay_report_window",
                  "SwitchEgress.replay_report_r_i",
                  "SwitchEgress.replay_report_r_i_1",
                  "SwitchEgress.replay_report_score"]
        for name in names:
            self._clear_register(name)
        self.dataplane.flush()

    def _read_counter(self, name):
        table = self.bfrt_info.table_get(name)
        table.operations_execute(self.target, "Sync")
        key = table.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
        response = table.entry_get(self.target, [key], {"from_hw": False})
        values = next(response)[0].to_dict()[name + ".f1"]
        # A register read on an all-pipes target returns one value per active
        # pipe.  PCI packet injection is platform-dependent and is not
        # guaranteed to use pipe 0, so the dataset total is their sum.
        return sum(values)

    def _register_diagnostic(self, name):
        table = self.bfrt_info.table_get(name)
        table.operations_execute(self.target, "Sync")
        field = name + ".f1"
        nonzero = 0
        maximum = 0
        examples = []
        pipe_nonzero = None
        pipe_sums = None
        for data, key in table.entry_get(self.target, flags={"from_hw": False}):
            values = data.to_dict()[field]
            if pipe_nonzero is None:
                pipe_nonzero = [0] * len(values)
                pipe_sums = [0] * len(values)
            for pipe, value in enumerate(values):
                pipe_sums[pipe] += value
                if value:
                    pipe_nonzero[pipe] += 1
            value = max(values)
            if value:
                nonzero += 1
                maximum = max(maximum, value)
                if len(examples) < 8:
                    examples.append({
                        "index": key.to_dict()["$REGISTER_INDEX"]["value"],
                        "pipe_values": values,
                    })
        return {"nonzero_cells": nonzero, "maximum": maximum,
                "pipe_nonzero_cells": pipe_nonzero or [],
                "pipe_sums": pipe_sums or [], "examples": examples}

    def _read_report_register(self, name, count):
        table = self.bfrt_info.table_get(name)
        table.operations_execute(self.target, "Sync")
        keys = [table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])
                for index in range(count)]
        field = name + ".f1"
        values_by_index = {}
        for data, key in table.entry_get(
                self.target, keys, {"from_hw": False}):
            index = key.to_dict()["$REGISTER_INDEX"]["value"]
            values_by_index[index] = data.to_dict()[field]
        return values_by_index

    def _read_data_plane_reports(self, total_reports):
        count = min(total_reports, REPORT_CAPACITY)
        flows = self._read_report_register(
            "SwitchEgress.replay_report_flow", count)
        windows = self._read_report_register(
            "SwitchEgress.replay_report_window", count)
        r_i_values = self._read_report_register(
            "SwitchEgress.replay_report_r_i", count)
        r_i_1_values = self._read_report_register(
            "SwitchEgress.replay_report_r_i_1", count)
        scores = self._read_report_register(
            "SwitchEgress.replay_report_score", count)
        reports = []
        for index in range(count):
            pipe_windows = windows.get(index, [])
            pipe_scores = scores.get(index, [])
            active_pipe = 0
            for pipe, value in enumerate(pipe_windows):
                if value:
                    active_pipe = pipe
                    break
            def pipe_value(register_values):
                values = register_values.get(index, [])
                return values[active_pipe] if active_pipe < len(values) else 0

            p4_window = pipe_value(windows)
            score_bits = (pipe_scores[active_pipe]
                          if active_pipe < len(pipe_scores) else 0)
            score_log = score_bits if score_bits <= INT16_MAX else score_bits - (1 << 16)
            reports.append({
                "report_index": index,
                "flow_id": pipe_value(flows),
                "completed_window": (p4_window - REPORT_WINDOW_OFFSET -
                                     self.report_window_origin),
                "r_i_bytes": pipe_value(r_i_values),
                "r_i_1_bytes": pipe_value(r_i_1_values),
                "score_log": score_log,
                "score": math.pow(2.0, score_log / float(SCALING_FACTOR)),
            })
        return reports

    def _program_timestamp_windows(self, path):
        """Validate raw timestamps and establish the sliced-window origin."""

        first_timestamp = None
        last_timestamp = None
        with open(path, "r") as handle:
            for row in csv.reader(handle):
                if not row:
                    continue
                timestamp = int(row[2])
                if not 0 <= timestamp < (1 << 48):
                    raise ValueError(
                        "timestamp does not fit the 48-bit replay header: %r" % row)
                if first_timestamp is None:
                    first_timestamp = timestamp
                if last_timestamp is not None and timestamp < last_timestamp:
                    raise ValueError("dataset timestamps are not sorted")
                last_timestamp = timestamp
        if first_timestamp is None:
            raise ValueError("empty dataset: %s" % path)
        if RAW_TIMESTAMP_SHIFT_BITS is None:
            raise ValueError("raw timestamp shift is not configured")
        first_window = first_timestamp >> RAW_TIMESTAMP_SHIFT_BITS
        last_window = last_timestamp >> RAW_TIMESTAMP_SHIFT_BITS
        if last_window - first_window > UINT16_MAX:
            raise ValueError("logical window span does not fit the 16-bit P4 time field")
        self.report_window_origin = first_window
        max_window = last_window - first_window
        return first_timestamp, last_timestamp, max_window

    def _diagnose_state(self):
        names = ["SwitchIngress.T_REGISTER_0",
                 "SwitchIngress.T_REGISTER_2",
                 "SwitchIngress.T_REGISTER_4",
                 "SwitchIngress.RET_PKTCOUNT_0",
                 "SwitchIngress.RET_PKTCOUNT_2",
                 "SwitchIngress.RET_PKTCOUNT_4",
                 "SwitchIngress.S_0",
                 "SwitchEgress.replay_evaluation_count",
                 "SwitchEgress.replay_anomaly_count"]
        diagnostic = {name: self._register_diagnostic(name) for name in names}
        LOGGER.info("STATE_DIAGNOSTIC=%s", json.dumps(diagnostic, sort_keys=True))
        return diagnostic

    @staticmethod
    def _packet(flow_id, packet_length, packet_time):
        if RAW_TIMESTAMP_REPLAY:
            timestamp_high = packet_time >> 32
            timestamp_low = packet_time & 0xFFFFFFFF
            calc = struct.pack(
                "!hhHI", flow_id, packet_length,
                timestamp_high, timestamp_low)
            return (RAW_TIMESTAMP_PACKET_PREFIX + calc +
                    RAW_TIMESTAMP_PAD)
        return PACKET_PREFIX + struct.pack(
            "!hhhh", flow_id, packet_length, packet_time, 0) + PAD

    def _replay_one(self, dataset_name):
        path = os.path.join(self.dataset_dir, dataset_name)
        self._reset_state()
        if RAW_TIMESTAMP_REPLAY:
            self._program_timestamp_windows(path)
        packets = 0
        flows = set()
        first_timestamp = None
        last_timestamp = None
        max_window = 0
        started = time.time()

        with open(path, "r") as handle:
            reader = csv.reader(handle)
            for row in reader:
                if not row:
                    continue
                flow_id = int(row[0])
                packet_length = int(row[1])
                timestamp = int(row[2])
                if first_timestamp is None:
                    first_timestamp = timestamp
                if RAW_TIMESTAMP_SHIFT_BITS is None:
                    window = ((timestamp - first_timestamp) // TIMESTEP_NS) + 2
                else:
                    window = ((timestamp >> RAW_TIMESTAMP_SHIFT_BITS) -
                              (first_timestamp >> RAW_TIMESTAMP_SHIFT_BITS))
                if not (0 <= flow_id <= INT16_MAX and
                        0 < packet_length <= INT16_MAX and
                        0 <= window <= UINT16_MAX and
                        0 <= timestamp < (1 << 48)):
                    raise ValueError("row does not fit replay header: %r" % row)
                packet_time = timestamp if RAW_TIMESTAMP_REPLAY else window
                self.dataplane.send(
                    0, PTF_INJECT_PORT,
                    self._packet(flow_id, packet_length, packet_time))
                packets += 1
                flows.add(flow_id)
                last_timestamp = timestamp
                max_window = max(max_window, window)
                if packets % 100000 == 0:
                    elapsed = time.time() - started
                    LOGGER.info("%-20s replayed %d packets (%.0f pkt/s)",
                                dataset_name, packets, packets / elapsed)
                if self.max_packets and packets >= self.max_packets:
                    break

        # Allow the final CPU-injected packets to drain through the ASIC.
        time.sleep(1.0)
        elapsed = time.time() - started
        evaluations = self._read_counter("SwitchEgress.replay_evaluation_count")
        anomalies = self._read_counter("SwitchEgress.replay_anomaly_count")
        if anomalies > REPORT_CAPACITY:
            raise RuntimeError(
                "data-plane reports %d exceed ring capacity %d" %
                (anomalies, REPORT_CAPACITY))
        reports = self._read_data_plane_reports(anomalies)
        reconstruction = write_dataset_outputs(
            self.reconstruction_output, dataset_name, path, reports,
            TIMESTEP_NS, REPORT_CAPACITY, anomalies,
            timestamp_shift=RAW_TIMESTAMP_SHIFT_BITS)
        duration_seconds = ((last_timestamp - first_timestamp) + TIMESTEP_NS) / 1e9
        result = {
            "dataset": dataset_name,
            "packets": packets,
            "flows": len(flows),
            "first_timestamp_ns": first_timestamp,
            "last_timestamp_ns": last_timestamp,
            "trace_duration_seconds": duration_seconds,
            "timestep_ns": TIMESTEP_NS,
            "timestamp_source": (
                "raw_48bit_p4_slice" if RAW_TIMESTAMP_REPLAY
                else "host_precomputed_window"),
            "logical_windows": max_window - REPORT_WINDOW_OFFSET + 1,
            "threshold": self.threshold,
            "evaluations": evaluations,
            "anomalies": anomalies,
            "data_plane_reports_read": len(reports),
            "reconstruction": reconstruction,
            "report_ratio": anomalies / float(evaluations) if evaluations else 0.0,
            "report_bytes": anomalies * MIRROR_PACKET_BYTES,
            "communication_gbps": (anomalies * MIRROR_PACKET_BYTES * 8 /
                                   duration_seconds / 1e9),
            "replay_wall_seconds": elapsed,
            "replay_packets_per_second": packets / elapsed,
        }
        LOGGER.info("completed %s: packets=%d evaluations=%d anomalies=%d",
                    dataset_name, packets, evaluations, anomalies)
        return result

    def runTest(self):
        if self.diagnose_only:
            self._diagnose_state()
            return
        if not self.skip_luts:
            LOGGER.info("loading complete BurstMon LUTs (scale=%d)", SCALING_FACTOR)
            self._program_all_luts()
        self._program_mirror()
        results = [self._replay_one(name.strip())
                   for name in self.dataset_names if name.strip()]
        summary = {
            "p4_program": P4_NAME,
            "platform": "Tofino1",
            "counter_bits": COUNTER_BITS,
            "score_input_shift": SCORE_INPUT_SHIFT,
            "score_input_divisor": 1 << SCORE_INPUT_SHIFT,
            "score_log_scale": SCALING_FACTOR,
            "threshold": self.threshold,
            "sketch_hash_rows": 2,
            "sketch_width": SKETCH_WIDTH,
            "datasets": results,
        }
        with open(self.output_path, "w") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)
            handle.write("\n")
        reconstruction_summary_path = os.path.join(
            self.reconstruction_output, "tofino_reconstruction_summary.json")
        if not os.path.isdir(self.reconstruction_output):
            os.makedirs(self.reconstruction_output)
        with open(reconstruction_summary_path, "w") as handle:
            json.dump({
                "p4_program": P4_NAME,
                "platform": "Tofino1",
                "counter_bits": COUNTER_BITS,
                "score_input_shift": SCORE_INPUT_SHIFT,
                "score_input_divisor": 1 << SCORE_INPUT_SHIFT,
                "threshold": self.threshold,
                "timestep_ns": TIMESTEP_NS,
                "datasets": [item["reconstruction"] for item in results],
            }, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
        LOGGER.info("wrote %s", self.output_path)
        LOGGER.info("wrote %s", reconstruction_summary_path)
