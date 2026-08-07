from __future__ import print_function

import math
import unittest

from lut_model import binary16_to_float, exact_score, float_to_binary16, pipeline_values


class LookupModelTest(unittest.TestCase):
    def test_binary16_round_trip(self):
        for value in (0.0, 2.0 ** -12, 0.125, 1.0, 3.5):
            recovered = binary16_to_float(float_to_binary16(value))
            self.assertAlmostEqual(recovered, value, delta=max(2.0 ** -20, value / 1000.0))

    def test_exact_score(self):
        self.assertEqual(exact_score(10, 20, 2), 0.0)
        self.assertAlmostEqual(exact_score(10, 10, 2), 10.0 / math.sqrt(11.0))

    def test_pipeline_is_binary16(self):
        result = pipeline_values(10, 10, 2)
        self.assertEqual(
            result["score"], binary16_to_float(result["score_binary16"])
        )
        self.assertLess(abs(result["score"] - exact_score(10, 10, 2)), 0.1)


if __name__ == "__main__":
    unittest.main()
