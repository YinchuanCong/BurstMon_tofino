"""Pure-Python definitions for BurstMon's Tofino lookup tables.

This module deliberately has no SDE/PTF dependency, so table contents can be
unit-tested on the development host before they are programmed into the ASIC.
"""

import math


SCALING_FACTOR = 512
UINT16_MAX = (1 << 16) - 1
INT16_MAX = (1 << 15) - 1


def u16(value: int) -> int:
    """Return the two's-complement bit pattern used by a 16-bit BFRT field."""
    return value & UINT16_MAX


def rotation_slot(window: int) -> int:
    """Select one of the three time sketches."""
    if not 0 <= window <= UINT16_MAX:
        raise ValueError("window must fit in 16 bits")
    return window % 3


def fixed_log2(value: float, scale: int = SCALING_FACTOR) -> int:
    """Encode log2(value) as a signed fixed-point integer."""
    if value <= 0 or not math.isfinite(value):
        raise ValueError("log2 lookup input must be positive and finite")
    result = math.floor(math.log2(value) * scale)
    if not -(1 << 15) <= result <= INT16_MAX:
        raise OverflowError("scaled logarithm does not fit in int<16>")
    return result


def saturated_exp2(log_value: int, scale: int = SCALING_FACTOR) -> int:
    """Decode a fixed-point logarithm to the P4 path's unsigned 16-bit domain."""
    value = round(2.0 ** (log_value / scale))
    return max(0, min(UINT16_MAX, value))


def float_to_binary16(value: float) -> int:
    """Encode a Python float as IEEE-754 binary16 bits."""
    if math.isnan(value):
        return 0x7E00
    sign = 0x8000 if value < 0 else 0
    value = abs(value)
    if math.isinf(value):
        return sign | 0x7C00
    if value == 0:
        return sign
    if value < 2.0 ** -14:
        mantissa = int(round(value / (2.0 ** -24)))
        return sign | min(mantissa, 0x3FF)
    mantissa, exponent = math.frexp(value)
    half_exponent = exponent + 14
    half_mantissa = int(round((mantissa * 2.0 - 1.0) * 1024.0))
    if half_mantissa == 1024:
        half_mantissa = 0
        half_exponent += 1
    if half_exponent >= 31:
        return sign | 0x7C00
    return sign | (half_exponent << 10) | half_mantissa


def binary16_to_float(bits: int) -> float:
    """Decode IEEE-754 binary16 bits to a Python float."""
    if not 0 <= bits <= UINT16_MAX:
        raise ValueError("binary16 value must fit in 16 bits")
    sign = -1.0 if bits & 0x8000 else 1.0
    exponent = (bits >> 10) & 0x1F
    mantissa = bits & 0x3FF
    if exponent == 0:
        return sign * (mantissa / 1024.0) * (2.0 ** -14)
    if exponent == 0x1F:
        return sign * float("inf") if mantissa == 0 else float("nan")
    return sign * (1.0 + mantissa / 1024.0) * (2.0 ** (exponent - 15))


def inverse_sqrt_binary16(product_log: int, scale: int = SCALING_FACTOR) -> int:
    """Return binary16 bits for 1/sqrt(2**(product_log/scale))."""
    value = 2.0 ** (-product_log / (2.0 * scale))
    return float_to_binary16(value)


def threshold_log_low(threshold: float, scale: int = SCALING_FACTOR) -> int:
    """First fixed-point score strictly greater than the user threshold."""
    if threshold <= 0 or not math.isfinite(threshold):
        raise ValueError("threshold must be positive and finite")
    return math.floor(math.log2(threshold) * scale) + 1


def approximate_score(delta: int, cumulative_delta: int, time_index: int) -> float:
    """Evaluate the same lookup pipeline as the P4 data plane for validation."""
    if delta <= 0 or cumulative_delta < 0 or time_index <= 1:
        return 0.0
    at = saturated_exp2(fixed_log2(delta) + fixed_log2(time_index))
    numerator = abs(at - cumulative_delta)
    if numerator == 0:
        return 0.0
    denominator_log = fixed_log2(min(UINT16_MAX, cumulative_delta + 1))
    denominator_log += fixed_log2(time_index - 1)
    inv_sqrt = binary16_to_float(inverse_sqrt_binary16(denominator_log))
    score_log = fixed_log2(numerator) + fixed_log2(inv_sqrt)
    return 2.0 ** (score_log / SCALING_FACTOR)


def positive_finite_binary16_values():
    """Yield every positive, finite, non-zero binary16 bit pattern."""
    yield from range(1, 0x7C00)
