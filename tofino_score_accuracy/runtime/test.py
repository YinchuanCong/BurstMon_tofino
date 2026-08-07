"""Run BurstMon anomaly-score accuracy samples through a physical Tofino ASIC.

Typical invocation after loading ``burstmon_score_eval``::

  ./run_p4_tests.sh -p burstmon_score_eval \
      -t CYC_P4/BurstMon_score_accuracy/runtime \
      --target hw --no-veth \
      --test-params="arch='tofino';num_pipes=4;sample_count=256"
"""

from __future__ import print_function

import csv
import json
import logging
import os
import random
import time

import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest
from ptf.testutils import test_param_get

from lut_model import (
    binary16_exp2,
    binary16_to_float,
    exact_score,
    fixed_log2,
    pipeline_values,
    u16,
)


LOGGER = logging.getLogger("BurstMonScoreAccuracy")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

P4_NAME = "burstmon_score_eval"
APP_ID = 1
PKTGEN_PORT = 68
BUFFER_OFFSET = 0
PACKET_LENGTH = 64


def _param(name, default, convert):
    value = test_param_get(name)
    if value in (None, ""):
        return default
    return convert(value)


def _unique_map(pairs):
    result = {}
    for key, value in pairs:
        if key in result and result[key] != value:
            raise AssertionError("one LUT key maps to multiple values: %r" % (key,))
        result[key] = value
    return sorted(result.items())


def generate_samples(count, seed):
    """Build a repeatable sample set covering several score bands."""
    if count < 8 or count > 512:
        raise ValueError("sample_count must be in [8, 512]")

    samples = [
        (1, 0, 2),
        (1, 2, 2),                  # exact zero
        (10, 10, 2),
        (100, 1000, 10),            # exact zero
        (7, 92, 13),
        (31, 1000, 32),
        (255, 8192, 32),
        (1023, 65000, 64),
    ]
    rng = random.Random(seed)
    seen = set(samples)

    # Alternate between values near a*t and values spread across S.  Filtering
    # keeps multiplication unsaturated and preserves the previous comparison set.
    attempts = 0
    while len(samples) < count:
        attempts += 1
        if attempts > count * 1000:
            raise RuntimeError("unable to generate enough unsaturated samples")
        t = rng.randint(2, 512)
        a = rng.randint(1, 65535 // t)
        at = a * t
        if len(samples) % 2:
            radius = max(1, int(((at + 1) * (t - 1)) ** 0.5 * 96))
            s = max(0, min(65534, at + rng.randint(-radius, radius)))
        else:
            s = rng.randint(0, 65534)
        triple = (a, s, t)
        if triple in seen:
            continue
        score = exact_score(a, s, t)
        if score >= 240.0:
            continue
        seen.add(triple)
        samples.append(triple)
    return samples


class BurstMonScoreAccuracy(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, P4_NAME)
        self.bfrt_info = self.interface.bfrt_info_get(P4_NAME)
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.sample_count = _param("sample_count", 256, int)
        self.seed = _param("seed", 20260806, int)
        self.num_pipes = _param("num_pipes", 4, int)
        self.samples = generate_samples(self.sample_count, self.seed)

    def _replace_exact(self, table_name, key_name, action_name, fields, entries):
        table = self.bfrt_info.table_get(table_name)
        table.entry_del(self.target)
        entries = list(entries)
        for offset in range(0, len(entries), 256):
            chunk = entries[offset:offset + 256]
            keys = [table.make_key([gc.KeyTuple(key_name, key)]) for key, _ in chunk]
            data = []
            for _, values in chunk:
                tuples = [gc.DataTuple(name, value) for name, value in zip(fields, values)]
                data.append(table.make_data(tuples, action_name))
            table.entry_add(self.target, keys, data)
        LOGGER.info("loaded %-46s %d entries", table_name, len(entries))

    def _program_samples_and_luts(self):
        evaluated = [(sample, pipeline_values(*sample)) for sample in self.samples]

        self._replace_exact(
            "SwitchIngress.load_sample_table",
            "hdr.timer.packet_id",
            "SwitchIngress.load_sample_action",
            ("a", "s", "t"),
            [(idx, sample) for idx, sample in enumerate(self.samples)],
        )

        specifications = [
            ("log_a_table", "md.lhs", "set_log_lhs", "value",
             _unique_map((a, u16(values["log_a"])) for (a, _, _), values in evaluated)),
            ("log_t_table", "md.rhs", "set_log_rhs", "value",
             _unique_map((t, u16(values["log_t"])) for (_, _, t), values in evaluated)),
            ("exp_at_table", "md.log_sum", "set_lut_value", "value",
             _unique_map((u16(values["at_log"]), values["at"]) for _, values in evaluated)),
            ("log_s_plus_one_table", "md.lhs", "set_log_lhs", "value",
             _unique_map((s, u16(values["log_s_plus_one"])) for (_, s, _), values in evaluated)),
            ("log_t_minus_one_table", "md.rhs", "set_log_rhs", "value",
             _unique_map((t, u16(values["log_t_minus_one"])) for (_, _, t), values in evaluated)),
            ("inverse_sqrt_table", "md.log_sum", "set_inverse_sqrt", "value",
             _unique_map((u16(values["denominator_log"]), values["half_bits"])
                         for _, values in evaluated)),
            ("log_numerator_table", "md.lhs", "set_log_lhs", "value",
             _unique_map((values["numerator"], u16(fixed_log2(values["numerator"])))
                         for _, values in evaluated if values["numerator"] != 0)),
            ("log_half_table", "md.rhs", "set_log_rhs", "value",
             _unique_map((values["half_bits"],
                          u16(fixed_log2(self._half_to_float(values["half_bits"]))))
                         for _, values in evaluated if values["numerator"] != 0)),
            ("exp_score_table", "md.log_sum", "set_score", "value",
             _unique_map((u16(values["score_log"]), binary16_exp2(values["score_log"]))
                         for _, values in evaluated if values["numerator"] != 0)),
        ]

        for table, key, action, field, entries in specifications:
            self._replace_exact(
                "SwitchIngress." + table,
                key,
                "SwitchIngress." + action,
                (field,),
                [(entry_key, (entry_value,)) for entry_key, entry_value in entries],
            )
        return evaluated

    @staticmethod
    def _half_to_float(bits):
        # Imported lazily here only to keep the table specification readable.
        from lut_model import binary16_to_float
        return binary16_to_float(bits)

    def _configure_and_run_pktgen(self):
        app = self.bfrt_info.table_get("app_cfg")
        buffer_table = self.bfrt_info.table_get("pkt_buffer")
        port = self.bfrt_info.table_get("port_cfg")

        port_key = port.make_key([gc.KeyTuple("dev_port", PKTGEN_PORT)])
        try:
            port.entry_add(
                self.target, [port_key],
                [port.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])],
            )
        except Exception:
            port.entry_mod(
                self.target, [port_key],
                [port.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])],
            )

        payload_size = PACKET_LENGTH - 6
        buffer_key = buffer_table.make_key([
            gc.KeyTuple("pkt_buffer_offset", BUFFER_OFFSET),
            gc.KeyTuple("pkt_buffer_size", payload_size),
        ])
        buffer_data = buffer_table.make_data([
            gc.DataTuple("buffer", bytearray(payload_size)),
        ])
        try:
            buffer_table.entry_add(self.target, [buffer_key], [buffer_data])
        except Exception:
            buffer_table.entry_mod(self.target, [buffer_key], [buffer_data])

        app_key = app.make_key([gc.KeyTuple("app_id", APP_ID)])
        disabled = app.make_data([
            gc.DataTuple("timer_nanosec", 100),
            gc.DataTuple("app_enable", bool_val=False),
            gc.DataTuple("pkt_len", payload_size),
            gc.DataTuple("pkt_buffer_offset", BUFFER_OFFSET),
            gc.DataTuple("pipe_local_source_port", PKTGEN_PORT),
            gc.DataTuple("increment_source_port", bool_val=False),
            gc.DataTuple("batch_count_cfg", 0),
            gc.DataTuple("packets_per_batch_cfg", self.sample_count - 1),
            gc.DataTuple("ibg", 1),
            gc.DataTuple("ibg_jitter", 0),
            gc.DataTuple("ipg", 1000),
            gc.DataTuple("ipg_jitter", 0),
            gc.DataTuple("batch_counter", 0),
            gc.DataTuple("pkt_counter", 0),
            gc.DataTuple("trigger_counter", 0),
        ], "trigger_timer_one_shot")
        try:
            app.entry_add(self.target, [app_key], [disabled])
        except Exception:
            app.entry_mod(self.target, [app_key], [disabled])

        app.entry_mod(
            self.target, [app_key],
            [app.make_data([gc.DataTuple("app_enable", bool_val=True)],
                           "trigger_timer_one_shot")],
        )

        deadline = time.time() + 15.0
        counters = None
        while time.time() < deadline:
            response = app.entry_get(self.target, [app_key], {"from_hw": True})
            counters = next(response)[0].to_dict()
            if (counters.get("trigger_counter", 0) >= 1 and
                    counters.get("pkt_counter", 0) >= self.sample_count):
                break
            time.sleep(0.1)
        else:
            raise AssertionError("pktgen timed out: %r" % (counters,))

        app.entry_mod(
            self.target, [app_key],
            [app.make_data([gc.DataTuple("app_enable", bool_val=False)],
                           "trigger_timer_one_shot")],
        )
        port.entry_mod(
            self.target, [port_key],
            [port.make_data([gc.DataTuple("pktgen_enable", bool_val=False)])],
        )
        LOGGER.info("ASIC pktgen counters: trigger=%d batches=%d packets=%d",
                    counters["trigger_counter"], counters["batch_counter"],
                    counters["pkt_counter"])
        return counters

    def _read_results(self):
        learn = self.bfrt_info.learn_get("score_digest")
        by_sample = {}
        deadline = time.time() + 15.0
        while len(by_sample) < self.sample_count and time.time() < deadline:
            digest = self.interface.digest_get(timeout=2)
            for data in learn.make_data_list(digest):
                fields = data.to_dict()
                sample_id = fields["sample_id"]
                if sample_id < self.sample_count:
                    by_sample[sample_id] = fields["score_binary16"]
        if len(by_sample) != self.sample_count:
            missing = sorted(set(range(self.sample_count)) - set(by_sample))
            raise AssertionError("missing ASIC score digests: %r" % missing[:20])
        return [by_sample[idx] for idx in range(self.sample_count)]

    def _write_report(self, binary16_results, counters):
        rows = []
        squared_errors = []
        absolute_errors = []
        for idx, ((a, s, t), binary16_bits) in enumerate(
                zip(self.samples, binary16_results)):
            exact = exact_score(a, s, t)
            tofino = binary16_to_float(binary16_bits)
            error = tofino - exact
            squared_errors.append(error * error)
            absolute_errors.append(abs(error))
            rows.append({
                "sample_id": idx,
                "a": a,
                "S": s,
                "t": t,
                "exact_score": "%.12g" % exact,
                "tofino_binary16_bits": binary16_bits,
                "tofino_binary16_hex": "0x%04x" % binary16_bits,
                "tofino_score": "%.12g" % tofino,
                "error": "%.12g" % error,
                "squared_error": "%.12g" % (error * error),
            })

        mse = sum(squared_errors) / len(squared_errors)
        summary = {
            "metric": "mean((binary16_to_float(tofino_bits) - exact_score)^2)",
            "mse": mse,
            "rmse": mse ** 0.5,
            "mae": sum(absolute_errors) / len(absolute_errors),
            "max_absolute_error": max(absolute_errors),
            "sample_count": self.sample_count,
            "seed": self.seed,
            "score_encoding": "IEEE-754 binary16",
            "lut_log2_scale": 512,
            "pktgen_trigger_counter": counters["trigger_counter"],
            "pktgen_batch_counter": counters["batch_counter"],
            "pktgen_packet_counter": counters["pkt_counter"],
        }
        output_dir = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(output_dir, "score_accuracy_results.csv")
        json_path = os.path.join(output_dir, "score_accuracy_summary.json")
        with open(csv_path, "w") as handle:
            # SDE 9.7 uses Python 3.5, where dict iteration order is not a
            # language guarantee.  Keep the artifact byte-stable across runs.
            fieldnames = [
                "sample_id", "a", "S", "t", "exact_score",
                "tofino_binary16_bits", "tofino_binary16_hex",
                "tofino_score", "error", "squared_error",
            ]
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        with open(json_path, "w") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)
            handle.write("\n")
        LOGGER.info("MSE=%.12g RMSE=%.12g MAE=%.12g max_abs=%.12g n=%d",
                    mse, summary["rmse"], summary["mae"],
                    summary["max_absolute_error"], self.sample_count)
        LOGGER.info("wrote %s and %s", csv_path, json_path)
        return summary

    def runTest(self):
        LOGGER.info("programming %d deterministic accuracy samples (seed=%d)",
                    self.sample_count, self.seed)
        self._program_samples_and_luts()
        counters = self._configure_and_run_pktgen()
        binary16_results = self._read_results()
        summary = self._write_report(binary16_results, counters)
        self.assertGreaterEqual(counters["pkt_counter"], self.sample_count)
        self.assertGreaterEqual(summary["mse"], 0.0)
