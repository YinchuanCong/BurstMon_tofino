import math
import unittest

from lut_model import (
    SCALING_FACTOR,
    approximate_score,
    binary16_to_float,
    fixed_log2,
    float_to_binary16,
    inverse_sqrt_binary16,
    rotation_slot,
    saturated_exp2,
    threshold_log_low,
    u16,
)


class LookupModelTest(unittest.TestCase):
    def test_complete_rotation_mapping(self):
        slots = [rotation_slot(i) for i in range(1 << 16)]
        self.assertEqual(slots.count(0), 21846)
        self.assertEqual(slots.count(1), 21845)
        self.assertEqual(slots.count(2), 21845)

    def test_log_exp_round_trip_is_bounded(self):
        for value in (1, 2, 3, 127, 1024, 8191, 65535):
            recovered = saturated_exp2(fixed_log2(value))
            self.assertLessEqual(recovered, value)
            self.assertLess((value - recovered) / value, 0.002)

    def test_inverse_sqrt_binary16(self):
        for product in (1, 3, 100, 65535):
            encoded = inverse_sqrt_binary16(fixed_log2(product))
            actual = binary16_to_float(encoded)
            expected = 1.0 / math.sqrt(product)
            self.assertLess(abs(actual - expected) / expected, 0.002)

    def test_binary16_and_signed_encoding(self):
        self.assertEqual(float_to_binary16(1.0), 0x3C00)
        self.assertEqual(binary16_to_float(0x3C00), 1.0)
        self.assertEqual(u16(-1), 0xFFFF)

    def test_strict_threshold(self):
        threshold = 12.0
        low = threshold_log_low(threshold)
        self.assertGreater(2 ** (low / SCALING_FACTOR), threshold)

    def test_complete_score_pipeline(self):
        for delta, cumulative, time_index in (
            (100, 300, 3),
            (500, 1200, 5),
            (1024, 5000, 8),
        ):
            expected = abs(delta * time_index - cumulative) / math.sqrt(
                (cumulative + 1) * (time_index - 1)
            )
            actual = approximate_score(delta, cumulative, time_index)
            if expected == 0:
                self.assertEqual(actual, 0)
            else:
                self.assertLess(abs(actual - expected) / expected, 0.01)


if __name__ == "__main__":
    unittest.main()
