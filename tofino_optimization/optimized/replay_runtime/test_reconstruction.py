import math
import os
import sys
import tempfile
import unittest


HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from reconstruction import (
    build_timestamp_window_ranges,
    load_ground_truth,
    paper_metrics,
    reconstruct_curves,
)


class ReconstructionMetricTest(unittest.TestCase):
    def test_ground_truth_uses_same_8192ns_slice_as_p4(self):
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
        try:
            handle.write("1,100,100000000,0\n")
            handle.write("1,200,100007000,0\n")
            handle.write("1,300,100008192,0\n")
            handle.close()
            ground_truth, _, _ = load_ground_truth(
                handle.name, 8192, timestamp_shift=13)
            self.assertEqual(ground_truth, {1: {0: 300, 1: 300}})
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                pass

    def test_raw_timestamp_ranges_split_at_16_bit_boundary(self):
        ranges = build_timestamp_window_ranges(65530, 85529, 10000)
        self.assertEqual(ranges, [
            (0, 65530, 65535, 2),
            (1, 0, 9993, 2),
            (1, 9994, 19993, 3),
        ])

    def test_identical_curves_match_equation_7(self):
        curve = [1.0, 2.0, 3.0]
        cosine, distance, energy, rpe = paper_metrics(curve, curve)
        self.assertAlmostEqual(cosine, 1.0)
        self.assertAlmostEqual(distance, 0.0)
        self.assertAlmostEqual(energy, 1.0)
        self.assertAlmostEqual(rpe, 0.0)

    def test_rpe_uses_reconstructed_peak_denominator(self):
        _, distance, energy, rpe = paper_metrics([4.0], [2.0])
        self.assertAlmostEqual(distance, 2.0)
        self.assertAlmostEqual(energy, 0.25)
        self.assertAlmostEqual(rpe, 1.0)

    def test_sparse_reports_create_linear_curve(self):
        ground_truth = {7: {0: 10, 1: 20, 2: 30}}
        packet_counts = {7: 3}
        reports = [{
            "flow_id": 7,
            "completed_window": 2,
            "r_i_bytes": 30,
            "r_i_1_bytes": 20,
            "score_log": 0,
            "score": 1.0,
            "report_index": 0,
        }]
        summary, metrics, curves = reconstruct_curves(
            ground_truth, packet_counts, reports, 2000,
            min_continuity=0.0)
        self.assertEqual(summary["eligible_flows"], 1)
        self.assertEqual([row["reconstructed_gbps"] for row in curves],
                         [20 * 8.0 / 2000, 30 * 8.0 / 2000])
        self.assertEqual(metrics[0]["evaluation_first_window"], 1)
        self.assertEqual(metrics[0]["evaluation_last_window"], 2)
        self.assertTrue(math.isfinite(metrics[0]["euclidean_distance_gbps"]))


if __name__ == "__main__":
    unittest.main()
