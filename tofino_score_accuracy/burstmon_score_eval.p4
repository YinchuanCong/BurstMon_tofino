#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

/*
 * Stand-alone ASIC accuracy harness for BurstMon's anomaly score:
 *
 *              |a*t - S|
 *   score = -----------------
 *            sqrt((S+1)(t-1))
 *
 * The control plane loads deterministic samples and only the LUT keys needed
 * by those samples.  Tofino's on-chip packet generator supplies packet_id;
 * one IEEE-754 binary16 score per sample is returned as a BF Runtime digest.
 */

const bit<3> EVAL_APP_ID = 1;

header result_h {
    bit<16> sample_id;
    bit<16> score_binary16;
}

struct headers_t {
    pktgen_timer_header_t timer;
    result_h result;
}

struct score_digest_t {
    bit<16> sample_id;
    bit<16> score_binary16;
}

struct ingress_metadata_t {
    bit<16> a;
    bit<16> s;
    bit<16> t;
    bit<16> lhs;
    bit<16> rhs;
    int<16> log_lhs;
    int<16> log_rhs;
    int<16> log_sum;
    bit<16> at;
    bit<16> maximum;
    bit<16> minimum;
    bit<16> numerator;
    bit<16> inverse_sqrt_half;
}

struct empty_headers_t {}
struct empty_metadata_t {}

parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out ingress_metadata_t md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        hdr.result.setInvalid();
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_timer;
    }

    state parse_timer {
        pkt.extract(hdr.timer);
        transition select(hdr.timer.app_id) {
            EVAL_APP_ID: accept;
            default: reject;
        }
    }
}

control SwitchIngress(
        inout headers_t hdr,
        inout ingress_metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action load_sample_action(bit<16> a, bit<16> s, bit<16> t) {
        md.a = a;
        md.s = s;
        md.t = t;
        hdr.result.sample_id = hdr.timer.packet_id;
        hdr.result.score_binary16 = 0;
    }

    table load_sample_table {
        key = { hdr.timer.packet_id: exact; }
        actions = { load_sample_action; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 512;
    }

    action set_log_lhs(int<16> value) { md.log_lhs = value; }
    action set_log_rhs(int<16> value) { md.log_rhs = value; }
    action set_lut_value(bit<16> value) { md.at = value; }
    action set_inverse_sqrt(bit<16> value) { md.inverse_sqrt_half = value; }
    action set_score(bit<16> value) {
        hdr.result.score_binary16 = value;
    }

    table log_a_table {
        key = { md.lhs: exact; }
        actions = { set_log_lhs; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 512;
    }

    table log_t_table {
        key = { md.rhs: exact; }
        actions = { set_log_rhs; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 512;
    }

    table exp_at_table {
        key = { md.log_sum: exact; }
        actions = { set_lut_value; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 1024;
    }

    table log_s_plus_one_table {
        key = { md.lhs: exact; }
        actions = { set_log_lhs; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 512;
    }

    table log_t_minus_one_table {
        key = { md.rhs: exact; }
        actions = { set_log_rhs; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 512;
    }

    table inverse_sqrt_table {
        key = { md.log_sum: exact; }
        actions = { set_inverse_sqrt; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 1024;
    }

    table log_numerator_table {
        key = { md.lhs: exact; }
        actions = { set_log_lhs; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 512;
    }

    table log_half_table {
        key = { md.rhs: exact; }
        actions = { set_log_rhs; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 512;
    }

    table exp_score_table {
        key = { md.log_sum: exact; }
        actions = { set_score; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 1024;
    }

    action calculate_extrema() {
        md.maximum = max(md.at, md.s);
        md.minimum = min(md.at, md.s);
    }

    action calculate_numerator() {
        md.numerator = md.maximum - md.minimum;
    }

    apply {
        hdr.result.setValid();
        load_sample_table.apply();

        /* Approximate a*t through fixed-point log2 and exp2. */
        md.lhs = md.a;
        md.rhs = md.t;
        log_a_table.apply();
        log_t_table.apply();
        md.log_sum = md.log_lhs + md.log_rhs;
        exp_at_table.apply();

        calculate_extrema();
        calculate_numerator();

        if (md.numerator != 0) {
            /* Approximate 1/sqrt((S+1)*(t-1)); S+1 is saturated by software. */
            md.lhs = md.s;
            md.rhs = md.t;
            log_s_plus_one_table.apply();
            log_t_minus_one_table.apply();
            md.log_sum = md.log_lhs + md.log_rhs;
            inverse_sqrt_table.apply();

            /* Multiply numerator by inverse sqrt and encode as IEEE binary16. */
            md.lhs = md.numerator;
            md.rhs = md.inverse_sqrt_half;
            log_numerator_table.apply();
            log_half_table.apply();
            md.log_sum = md.log_lhs + md.log_rhs;
            exp_score_table.apply();
        }

        ig_dprsr_md.digest_type = 1;
        ig_dprsr_md.drop_ctl = 1;
        ig_tm_md.bypass_egress = 1w1;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in ingress_metadata_t md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Digest<score_digest_t>() score_digest;
    apply {
        if (ig_dprsr_md.digest_type == 1) {
            score_digest.pack({hdr.result.sample_id, hdr.result.score_binary16});
        }
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out empty_headers_t hdr,
        out empty_metadata_t md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgress(
        inout empty_headers_t hdr,
        inout empty_metadata_t md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {}
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout empty_headers_t hdr,
        in empty_metadata_t md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {}
}

Pipeline(
    SwitchIngressParser(), SwitchIngress(), SwitchIngressDeparser(),
    SwitchEgressParser(), SwitchEgress(), SwitchEgressDeparser()) pipe;
Switch(pipe) main;
