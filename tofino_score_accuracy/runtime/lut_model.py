"""BurstMon score lookup model shared by the evaluator and local tests."""

from __future__ import print_function

import math


SCALE = 512
UINT16_MAX = 65535


def u16(value):
    return int(value) & UINT16_MAX


def fixed_log2(value):
    if value <= 0:
        raise ValueError("log input must be positive")
    return int(math.floor(math.log(value, 2) * SCALE))


def saturated_exp2(log_value):
    value = int(round(2.0 ** (float(log_value) / SCALE)))
    return max(0, min(UINT16_MAX, value))


def float_to_binary16(value):
    if math.isnan(value):
        return 0x7E00
    sign = 0x8000 if value < 0 else 0
    value = abs(value)
    if math.isinf(value):
        return sign | 0x7C00
    if value == 0:
        return sign
    if value < 2.0 ** -14:
        return sign | min(int(round(value / (2.0 ** -24))), 0x3FF)
    mantissa, exponent = math.frexp(value)
    half_exponent = exponent + 14
    half_mantissa = int(round((mantissa * 2.0 - 1.0) * 1024.0))
    if half_mantissa == 1024:
        half_mantissa = 0
        half_exponent += 1
    if half_exponent >= 31:
        return sign | 0x7C00
    return sign | (half_exponent << 10) | half_mantissa


def binary16_to_float(bits):
    sign = -1.0 if bits & 0x8000 else 1.0
    exponent = (bits >> 10) & 0x1F
    mantissa = bits & 0x3FF
    if exponent == 0:
        return sign * (mantissa / 1024.0) * (2.0 ** -14)
    if exponent == 0x1F:
        return sign * float("inf") if mantissa == 0 else float("nan")
    return sign * (1.0 + mantissa / 1024.0) * (2.0 ** (exponent - 15))


def inverse_sqrt_binary16(product_log):
    return float_to_binary16(2.0 ** (-float(product_log) / (2.0 * SCALE)))


def binary16_exp2(log_value):
    """Encode the final exp2 lookup result as IEEE-754 binary16 bits."""
    return float_to_binary16(2.0 ** (float(log_value) / SCALE))


def exact_score(a, s, t):
    if t <= 1:
        raise ValueError("t must be greater than one")
    return abs(a * t - s) / math.sqrt(float(s + 1) * (t - 1))


def pipeline_values(a, s, t):
    """Return every value used to program one sample's ASIC lookup path."""
    log_a = fixed_log2(a)
    log_t = fixed_log2(t)
    at_log = log_a + log_t
    at = saturated_exp2(at_log)
    numerator = abs(at - s)
    result = {
        "log_a": log_a,
        "log_t": log_t,
        "at_log": at_log,
        "at": at,
        "numerator": numerator,
        "log_s_plus_one": fixed_log2(min(UINT16_MAX, s + 1)),
        "log_t_minus_one": fixed_log2(t - 1),
    }
    denominator_log = result["log_s_plus_one"] + result["log_t_minus_one"]
    result["denominator_log"] = denominator_log
    half_bits = inverse_sqrt_binary16(denominator_log)
    result["half_bits"] = half_bits
    if numerator == 0:
        result["score_log"] = None
        result["score_binary16"] = 0
        result["score"] = 0.0
    else:
        score_log = fixed_log2(numerator) + fixed_log2(binary16_to_float(half_bits))
        result["score_log"] = score_log
        result["score_binary16"] = binary16_exp2(score_log)
        result["score"] = binary16_to_float(result["score_binary16"])
    return result
