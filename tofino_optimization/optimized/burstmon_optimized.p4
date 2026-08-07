#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers_new.p4"
#include "common/util.p4"

// #define w


typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

#ifdef WIDE_COUNTERS
/*
 * Preserve the unscaled byte volume in the sketches and reports.  Only the
 * anomaly-score path converts it to 16 bits (see calculate_delta below).
 */
typedef bit<32> volume_t;
typedef bit<12> report_index_t;
#define REPORT_RING_SIZE 4096
#else
typedef bit<16> volume_t;
typedef bit<12> report_index_t;
#define REPORT_RING_SIZE 4096
#endif


// struct digest_1 {

// }

enum bit<8> internal_header_t {
    NONE = 0x0,
    BRIDGE_HDR = 0x1
}

header internal_h {
    internal_header_t header_type;
}

@flexible
header bridge_h {
    bit<16> delta;
    bit<16> S;
    bit<16> S_alt;
    bit<16> time;
    volume_t len_i;
    volume_t len_i_1;
}

// struct pair_t {
//     bit<16>     value;
//     bit<32>     time;
// }
// Compile-time width selection. With 32-bit volume_t, all Time-Sketch
// volumes, timestamp tags, and cumulative sketches occupy 40 bytes per cell.
#ifdef SKETCH_WIDTH_8192
typedef bit<13> index_t;
#define SKETCH_WIDTH 8192
#elif defined(SKETCH_WIDTH_4096)
typedef bit<12> index_t;
#define SKETCH_WIDTH 4096
#elif defined(SKETCH_WIDTH_2048)
typedef bit<11> index_t;
#define SKETCH_WIDTH 2048
#else
typedef bit<10> index_t;
#define SKETCH_WIDTH 1024
#endif

// struct pair32_t {
//     bit<32>     value;
//     bit<32>     time;
// }

struct ingress_metadata_t {
    internal_h internal_hdr;

    bit<1> monitor_valid;
#ifdef RAW_TIMESTAMP_REPLAY
    bit<16> replay_window_key;
    bit<2> update_mode_0;
    bit<2> update_mode_1;
    bit<2> update_mode_2;
    bit<2> update_mode_3;
    bit<2> update_mode_4;
    bit<2> update_mode_5;
#else
    bit<8> update_mode_0;
    bit<8> update_mode_1;
    bit<8> update_mode_2;
    bit<8> update_mode_3;
    bit<8> update_mode_4;
    bit<8> update_mode_5;
#endif
    bit<16> time;
    bit<16> previous_time;
    bit<16> previous2_time;
    bit<2> time_conv;
    bit<1> new_window;
    bit<1> previous_row0_valid;
    bit<1> previous2_row0_valid;
    bit<6> stale;
    volume_t ret5;
    volume_t ret4;
    volume_t ret3;
    volume_t ret2;
    volume_t ret1;
    volume_t ret0;

    bit<16> t5;
    bit<16> t4;
    bit<16> t3;
    bit<16> t2;
    bit<16> t1;
    bit<16> t0;
    bit<16> selected_previous_t0;
    bit<16> selected_previous2_t0;

    bit<16> delta;
    int<16> signed_delta;
    index_t index_0;
    index_t index_1;

    bridge_h bridge_hdr;

    // example_bridge_h example_bridge_hdr;
    // MirrorId_t egr_mir_ses;   // Egress mirror session ID
}

header mirror_h {
    bit<48> timestamp;
    volume_t len_i;
    volume_t len_i_1;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> protocol;
    pkt_type_t  pkt_type;
#ifdef DATASET_REPLAY
    int<16> dataset_flow_id;
    int<16> score_log;
#endif
}

struct egress_metadata_t {
    internal_h internal_hdr;
    approximate_calculation_metadata_t ac_md;
    bridge_h bridge_hdr;
    bit<48> timestamp;
    MirrorId_t eg_mir_ses;
    pkt_type_t pkt_type;
#ifdef DATASET_REPLAY
    bit<1> replay_anomaly;
    bit<32> replay_evaluation_result;
    bit<32> replay_anomaly_result;
    report_index_t replay_report_slot;
    bit<1> replay_report_write_result;
#endif
};

//////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////  sketches ///////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////
         

#define SET_HASH(num, seed) \
    CRCPolynomial<bit<32>>(seed,                                            \
                           true,                                            \
                           false,                                           \
                           false,                                           \
                           32w0xFFFFFFFF,                                   \
                           32w0xFFFFFFFF                                    \
                           ) poly##num;                                     \
    Hash<index_t>(HashAlgorithm_t.CUSTOM, poly##num) hash_##num    

#define TIMESTAMP_REGISTER(num, slot) \
    Register<bit<16>, index_t>(SKETCH_WIDTH) T_REGISTER_##num;   \
    RegisterAction<bit<16>, index_t, bit<16>> (T_REGISTER_##num) T_Access_##num = { \
        void apply(inout bit<16> t,out bit<16> read_t){\
            read_t = t;\
            if (ig_md.time_conv == slot) { t = ig_md.time; }\
        }\
    }

#ifdef RAW_TIMESTAMP_REPLAY
#define RET_PKTCOUNT_REGISTER(num, slot) \
    Register<volume_t, index_t>(SKETCH_WIDTH) RET_PKTCOUNT_##num;   \
    RegisterAction<volume_t, index_t, volume_t> (RET_PKTCOUNT_##num) RET_PKTCOUNT_access_##num = { \
        void apply(inout volume_t pair, out volume_t read_pair) { \
            if (ig_md.update_mode_##num == 3) { \
                pair = (volume_t)MONITORED_PACKET_LENGTH; \
            } else if (ig_md.update_mode_##num == 1) { \
                pair = pair + (volume_t)MONITORED_PACKET_LENGTH; \
            } \
            read_pair = pair;\
        }\
    }
#else
#define RET_PKTCOUNT_REGISTER(num, slot) \
    Register<volume_t, index_t>(SKETCH_WIDTH) RET_PKTCOUNT_##num;   \
    RegisterAction<volume_t, index_t, volume_t> (RET_PKTCOUNT_##num) RET_PKTCOUNT_access_##num = { \
        void apply(inout volume_t pair, out volume_t read_pair) { \
            if (ig_md.update_mode_##num == 2) { \
                pair = (volume_t)MONITORED_PACKET_LENGTH; \
            } else if (ig_md.update_mode_##num == 1) { \
                pair = pair + (volume_t)MONITORED_PACKET_LENGTH; \
            } \
            read_pair = pair;\
        }\
    }
#endif

#define S_REGISTER(num) \
    Register<bit<16>, index_t>(SKETCH_WIDTH) S_##num;   \
    RegisterAction<bit<16>, index_t, bit<16>> (S_##num) S_updateClean_##num = { \
        void apply(inout bit<16> pair, out bit<16> read_pair) { \
            pair = pair + ig_md.delta; \
            read_pair = pair; \
        }\
    }

#ifdef DATASET_REPLAY
#define MONITORED_PACKET_LENGTH (bit<16>)hdr.calc.s
#define APPLY_HASH(num)                   \
    ig_md.index_##num = hash_##num.get({hdr.calc.a})
#else
#define MONITORED_PACKET_LENGTH (bit<16>)hdr.ipv4.total_len
#define APPLY_HASH(num)                   \
    ig_md.index_##num = hash_##num.get({          \
      hdr.ipv4.src_addr,                  \
      hdr.ipv4.dst_addr,                 \
      hdr.udp.src_port,  \
      hdr.udp.dst_port,\
      hdr.ipv4.protocol \
    })
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////  End sketches ///////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    
    state start {
        ig_md.internal_hdr.setValid();
        ig_md.internal_hdr.header_type = internal_header_t.NONE;
        ig_md.bridge_hdr.setInvalid();
        ig_md.monitor_valid = 0;
        // ig_md.internal_hdr.header_type = internal_header_t.NONE;
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
       
        // transition parse_calc;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_calc;
        // transition accept;
    }
    state parse_calc {
        pkt.extract(hdr.calc);
#ifdef RAW_TIMESTAMP_REPLAY
        /* 8,192 ns is 2^13 ns: retain the 16 window bits immediately above
         * the discarded low 13 timestamp bits. */
        ig_md.monitor_valid = 0;
        ig_md.replay_window_key = (bit<16>)hdr.calc.timestamp[28:13];
#else
        ig_md.monitor_valid = 1;
#endif
#ifdef DATASET_REPLAY
#ifndef RAW_TIMESTAMP_REPLAY
        /* Parser-side assignment avoids consuming a MAU stage during replay. */
        ig_md.time = (bit<16>)hdr.calc.t;
#endif
#endif
        transition accept;
    }   
    
}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
        ) {

    apply {
        // hdr.ipv4.hdr_checksum = ipv4_checksum.update({
        //     hdr.ipv4.version,
        //     hdr.ipv4.ihl,
        //     hdr.ipv4.diffserv,
        //     hdr.ipv4.total_len,
        //     hdr.ipv4.identification,
        //     hdr.ipv4.flags,
        //     hdr.ipv4.frag_offset,
        //     hdr.ipv4.ttl,
        //     hdr.ipv4.protocol,
        //     hdr.ipv4.src_addr,
        //     hdr.ipv4.dst_addr});
        // pkt.emit(ig_md.internal_hdr);
        // pkt.emit(ig_md.example_bridge_hdr);
        pkt.emit(ig_md.internal_hdr);
        pkt.emit(ig_md.bridge_hdr);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.calc);
    } 
}



control SwitchIngress(
        inout header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    SET_HASH(0, 32w0x04C11DB7);
    SET_HASH(1, 32w0x34FD110C);

    TIMESTAMP_REGISTER(0, 0);
    TIMESTAMP_REGISTER(1, 0);
    TIMESTAMP_REGISTER(2, 1);
    TIMESTAMP_REGISTER(3, 1);
    TIMESTAMP_REGISTER(4, 2);
    TIMESTAMP_REGISTER(5, 2);

    RET_PKTCOUNT_REGISTER(0, 0);
    RET_PKTCOUNT_REGISTER(1, 0);
    RET_PKTCOUNT_REGISTER(2, 1);
    RET_PKTCOUNT_REGISTER(3, 1);
    RET_PKTCOUNT_REGISTER(4, 2);
    RET_PKTCOUNT_REGISTER(5, 2);

    S_REGISTER(0);
    S_REGISTER(1);

    action set_time_conv_action(bit<2> conv){
        ig_md.time_conv = conv;
    }

    action set_window_times() {
        ig_md.previous_time = ig_md.time - 1;
        ig_md.previous2_time = ig_md.time - 2;
    }

#ifdef RAW_TIMESTAMP_REPLAY
    action set_replay_window_action(bit<16> window,
                                    bit<16> previous_window,
                                    bit<16> previous2_window,
                                    bit<2> conv,
                                    bit<3> active_slots) {
        ig_md.time = window;
        ig_md.previous_time = previous_window;
        ig_md.previous2_time = previous2_window;
        ig_md.time_conv = conv;
        ig_md.update_mode_0 = (bit<2>)active_slots[0:0];
        ig_md.update_mode_1 = (bit<2>)active_slots[0:0];
        ig_md.update_mode_2 = (bit<2>)active_slots[1:1];
        ig_md.update_mode_3 = (bit<2>)active_slots[1:1];
        ig_md.update_mode_4 = (bit<2>)active_slots[2:2];
        ig_md.update_mode_5 = (bit<2>)active_slots[2:2];
        ig_md.monitor_valid = 1;
    }

    table replay_timestamp_to_window_table {
        key = {
            ig_md.replay_window_key : exact;
        }
        actions = {
            set_replay_window_action;
            NoAction;
        }
        size = 65536;
        const default_action = NoAction();
    }
#endif

#ifndef RAW_TIMESTAMP_REPLAY
    action select_update_mode_0() {
        ig_md.update_mode_0 = 1 + ig_md.stale[0:0];
        ig_md.update_mode_1 = 1 + ig_md.stale[1:1];
        ig_md.update_mode_2 = 0; ig_md.update_mode_3 = 0;
        ig_md.update_mode_4 = 0; ig_md.update_mode_5 = 0;
    }
    action select_update_mode_1() {
        ig_md.update_mode_0 = 0; ig_md.update_mode_1 = 0;
        ig_md.update_mode_2 = 1 + ig_md.stale[2:2];
        ig_md.update_mode_3 = 1 + ig_md.stale[3:3];
        ig_md.update_mode_4 = 0; ig_md.update_mode_5 = 0;
    }
    action select_update_mode_2() {
        ig_md.update_mode_0 = 0; ig_md.update_mode_1 = 0;
        ig_md.update_mode_2 = 0; ig_md.update_mode_3 = 0;
        ig_md.update_mode_4 = 1 + ig_md.stale[4:4];
        ig_md.update_mode_5 = 1 + ig_md.stale[5:5];
    }
    table select_update_mode_table {
        key = { ig_md.time_conv : exact; }
        actions = { select_update_mode_0; select_update_mode_1; select_update_mode_2; }
        const entries = {
            0 : select_update_mode_0();
            1 : select_update_mode_1();
            2 : select_update_mode_2();
        }
        const default_action = select_update_mode_2;
        size = 3;
    }
#endif

    action select_windows_0() {
        ig_md.new_window = ig_md.stale[0:0] | ig_md.stale[1:1];
        ig_md.selected_previous_t0 = ig_md.t4;
        ig_md.selected_previous2_t0 = ig_md.t2;
        ig_md.bridge_hdr.len_i = min(ig_md.ret4, ig_md.ret5);
        ig_md.bridge_hdr.len_i_1 = min(ig_md.ret2, ig_md.ret3);
    }

    action select_windows_1() {
        ig_md.new_window = ig_md.stale[2:2] | ig_md.stale[3:3];
        ig_md.selected_previous_t0 = ig_md.t0;
        ig_md.selected_previous2_t0 = ig_md.t4;
        ig_md.bridge_hdr.len_i = min(ig_md.ret0, ig_md.ret1);
        ig_md.bridge_hdr.len_i_1 = min(ig_md.ret4, ig_md.ret5);
    }
    action select_windows_2() {
        ig_md.new_window = ig_md.stale[4:4] | ig_md.stale[5:5];
        ig_md.selected_previous_t0 = ig_md.t2;
        ig_md.selected_previous2_t0 = ig_md.t0;
        ig_md.bridge_hdr.len_i = min(ig_md.ret2, ig_md.ret3);
        ig_md.bridge_hdr.len_i_1 = min(ig_md.ret0, ig_md.ret1);
    }
    table select_windows_table {
        key = { ig_md.time_conv : exact; }
        actions = { select_windows_0; select_windows_1; select_windows_2; }
        const entries = {
            0 : select_windows_0();
            1 : select_windows_1();
            2 : select_windows_2();
        }
        const default_action = select_windows_2;
        size = 3;
    }

    action calculate_delta() {
#ifdef WIDE_COUNTERS
        ig_md.signed_delta = (int<16>)ig_md.bridge_hdr.len_i[21:6] -
                             (int<16>)ig_md.bridge_hdr.len_i_1[21:6];
#else
        ig_md.signed_delta = (int<16>)ig_md.bridge_hdr.len_i -
                             (int<16>)ig_md.bridge_hdr.len_i_1;
#endif
    }

    action set_abs_delta(bit<16> abs_delta) {
        ig_md.delta = abs_delta;
        ig_md.bridge_hdr.delta = abs_delta;
    }

    table delta_abs_table {
        key = {
            ig_md.signed_delta : exact;
        }
        actions = {
            set_abs_delta;
        }
        size = 65536;
    }
    table set_time_conv_table {
        key = {
            ig_md.time : exact;
        }
        actions = {
            set_time_conv_action;
        }
        size = 65536;
    }

    apply {
#ifdef RAW_TIMESTAMP_REPLAY
    if (hdr.calc.isValid()) {
        replay_timestamp_to_window_table.apply();
    }
#endif
    if (ig_md.monitor_valid == 1) {
    /* The normal program uses 2^16 ns = 65.536 us per measurement window. */
#ifdef DATASET_REPLAY
    /* Replay time is supplied either by calc.t or by the raw-timestamp table. */
#else
    ig_md.time = ig_prsr_md.global_tstamp[31:16];
#endif
#ifndef RAW_TIMESTAMP_REPLAY
    set_window_times();

    set_time_conv_table.apply();
#endif
    APPLY_HASH(0);
    APPLY_HASH(1);

    /* Every register is read, but its stateful action writes only its active slot. */
    ig_md.t0 = T_Access_0.execute(ig_md.index_0);
    ig_md.t1 = T_Access_1.execute(ig_md.index_1);
    ig_md.t2 = T_Access_2.execute(ig_md.index_0);
    ig_md.t3 = T_Access_3.execute(ig_md.index_1);
    ig_md.t4 = T_Access_4.execute(ig_md.index_0);
    ig_md.t5 = T_Access_5.execute(ig_md.index_1);
    ig_md.stale = 0;
    if (ig_md.t0 != ig_md.time) {
        ig_md.stale[0:0] = 1;
#ifdef RAW_TIMESTAMP_REPLAY
        ig_md.update_mode_0[1:1] = ig_md.update_mode_0[0:0];
#endif
    }
    if (ig_md.t1 != ig_md.time) {
        ig_md.stale[1:1] = 1;
#ifdef RAW_TIMESTAMP_REPLAY
        ig_md.update_mode_1[1:1] = ig_md.update_mode_1[0:0];
#endif
    }
    if (ig_md.t2 != ig_md.time) {
        ig_md.stale[2:2] = 1;
#ifdef RAW_TIMESTAMP_REPLAY
        ig_md.update_mode_2[1:1] = ig_md.update_mode_2[0:0];
#endif
    }
    if (ig_md.t3 != ig_md.time) {
        ig_md.stale[3:3] = 1;
#ifdef RAW_TIMESTAMP_REPLAY
        ig_md.update_mode_3[1:1] = ig_md.update_mode_3[0:0];
#endif
    }
    if (ig_md.t4 != ig_md.time) {
        ig_md.stale[4:4] = 1;
#ifdef RAW_TIMESTAMP_REPLAY
        ig_md.update_mode_4[1:1] = ig_md.update_mode_4[0:0];
#endif
    }
    if (ig_md.t5 != ig_md.time) {
        ig_md.stale[5:5] = 1;
#ifdef RAW_TIMESTAMP_REPLAY
        ig_md.update_mode_5[1:1] = ig_md.update_mode_5[0:0];
#endif
    }
#ifndef RAW_TIMESTAMP_REPLAY
    select_update_mode_table.apply();
#endif
    ig_md.ret0 = RET_PKTCOUNT_access_0.execute(ig_md.index_0);
    ig_md.ret1 = RET_PKTCOUNT_access_1.execute(ig_md.index_1);
    ig_md.ret2 = RET_PKTCOUNT_access_2.execute(ig_md.index_0);
    ig_md.ret3 = RET_PKTCOUNT_access_3.execute(ig_md.index_1);
    ig_md.ret4 = RET_PKTCOUNT_access_4.execute(ig_md.index_0);
    ig_md.ret5 = RET_PKTCOUNT_access_5.execute(ig_md.index_1);
    select_windows_table.apply();

    ig_md.previous_row0_valid = 0;
    ig_md.previous2_row0_valid = 0;
    if (ig_md.selected_previous_t0 == ig_md.previous_time) { ig_md.previous_row0_valid = 1; }
    if (ig_md.selected_previous2_t0 == ig_md.previous2_time) { ig_md.previous2_row0_valid = 1; }
    calculate_delta();
    delta_abs_table.apply();

    /* Evaluate once per flow/window, on the first packet of the new window. */
    if ((ig_md.new_window == 1) &&
        (ig_md.previous_row0_valid == 1) &&
        (ig_md.previous2_row0_valid == 1) &&
        (ig_md.delta != 0)
#ifndef RAW_TIMESTAMP_REPLAY
        && (ig_md.previous_time > 1)
#endif
        ) {
        ig_md.bridge_hdr.S = S_updateClean_0.execute(ig_md.index_0);
        ig_md.bridge_hdr.S_alt = S_updateClean_1.execute(ig_md.index_1);
        ig_md.bridge_hdr.time = ig_md.previous_time;
        ig_md.bridge_hdr.setValid();
        ig_md.internal_hdr.header_type = internal_header_t.BRIDGE_HDR;
    }
    }

#ifdef DATASET_REPLAY
    /*
     * Traverse egress for score evaluation on the same PCI CPU pipe that
     * injected the packet.  Real Tofino boards may expose PCI on a CPU port
     * other than dev-port 64; hard-coding 64 can silently send the packet to
     * an inactive pipe and skip the complete egress score path.
     */
    ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
#else
    if(ig_intr_md.ingress_port==176) {
        ig_tm_md.ucast_egress_port=184;
    } else {
        ig_tm_md.ucast_egress_port=176;
    }
#endif
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_internal_hdr;
    }

    state parse_internal_hdr {
        pkt.extract(eg_md.internal_hdr);
        eg_md.bridge_hdr.setInvalid();
        transition select(eg_md.internal_hdr.header_type) {
            internal_header_t.NONE: parse_ethernet;
            internal_header_t.BRIDGE_HDR: parse_brige_hdr;
            default: accept;
        }
    }

    state parse_brige_hdr {
        pkt.extract(eg_md.bridge_hdr);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_calc;
    }

    state parse_calc {
        pkt.extract(hdr.calc);
        transition accept;
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

#ifdef DATASET_REPLAY
    Register<bit<32>, bit<1>>(1) replay_evaluation_count;
    RegisterAction<bit<32>, bit<1>, bit<32>>(replay_evaluation_count) replay_count_evaluation = {
        void apply(inout bit<32> stored, out bit<32> result) {
            stored = stored + 1;
            result = stored;
        }
    };
    Register<bit<32>, bit<1>>(1) replay_anomaly_count;
    RegisterAction<bit<32>, bit<1>, bit<32>>(replay_anomaly_count) replay_count_anomaly = {
        void apply(inout bit<32> stored, out bit<32> result) {
            /* Return the zero-based report slot, then advance the total. */
            result = stored;
            stored = stored + 1;
        }
    };
    /* Parallel arrays preserve the raw volume width selected by volume_t. */
    Register<bit<16>, report_index_t>(REPORT_RING_SIZE) replay_report_flow;
    RegisterAction<bit<16>, report_index_t, bit<1>>(replay_report_flow) replay_write_flow = {
        void apply(inout bit<16> stored, out bit<1> result) {
            stored = (bit<16>)hdr.calc.a; result = 1;
        }
    };
    Register<bit<16>, report_index_t>(REPORT_RING_SIZE) replay_report_window;
    RegisterAction<bit<16>, report_index_t, bit<1>>(replay_report_window) replay_write_window = {
        void apply(inout bit<16> stored, out bit<1> result) {
            stored = eg_md.bridge_hdr.time; result = 1;
        }
    };
    Register<volume_t, report_index_t>(REPORT_RING_SIZE) replay_report_r_i;
    RegisterAction<volume_t, report_index_t, bit<1>>(replay_report_r_i) replay_write_r_i = {
        void apply(inout volume_t stored, out bit<1> result) {
            stored = eg_md.bridge_hdr.len_i; result = 1;
        }
    };
    Register<volume_t, report_index_t>(REPORT_RING_SIZE) replay_report_r_i_1;
    RegisterAction<volume_t, report_index_t, bit<1>>(replay_report_r_i_1) replay_write_r_i_1 = {
        void apply(inout volume_t stored, out bit<1> result) {
            stored = eg_md.bridge_hdr.len_i_1; result = 1;
        }
    };
    Register<bit<16>, report_index_t>(REPORT_RING_SIZE) replay_report_score;
    RegisterAction<bit<16>, report_index_t, bit<1>>(replay_report_score) replay_write_score = {
        void apply(inout bit<16> stored, out bit<1> result) {
            stored = (bit<16>)eg_md.ac_md.n;
            result = 1;
        }
    };
#endif

    action get_log_int_m1_action(int<16> log_int) {
        eg_md.ac_md.log_int_m1 = log_int;
    }

    /* Keep 16-bit LUT values in the match entry itself.  Without this pragma,
     * the compiler creates a 64K direct ADT whose stash indices can exceed
     * the Tofino1 16-bit ADT index and the last entries fail at runtime. */
    @force_immediate(1)
    table get_log_int_m1_table {
        key = {
            eg_md.ac_md.int_m1 : exact;
        }
        actions = {
            get_log_int_m1_action;
        }

        size = 65536; 
    }

    action get_log_int_m2_action(int<16> log_int) {
        eg_md.ac_md.log_int_m2 = log_int;
    }
    @force_immediate(1)
    table get_log_int_m2_table {
        key = {
            eg_md.ac_md.int_m2 : exact;
        }
        actions = {
            get_log_int_m2_action;
        }

        size = 65536; 
    }

    action get_exp_at_action(bit<16> value) {
        eg_md.ac_md.z = value;
    }
    @force_immediate(1)
    table get_exp_at_table {
        key = {
           eg_md.ac_md.n : exact;
        }
        actions = {
            get_exp_at_action;
        }
        size = 65536;
    }

    @force_immediate(1)
    table get_log_int_m1_table2 {
        key = {
            eg_md.ac_md.int_m1 : exact;
        }
        actions = {
            get_log_int_m1_action;
        }
        size = 65536;
    }

    @force_immediate(1)
    table get_log_int_m2_table2 {
        key = {
            eg_md.ac_md.int_m2 : exact;
        }
        actions = {
            get_log_int_m2_action;
        }
        size = 65536;
    }

    action get_inv_sqrt_action(bit<16> value) {
        eg_md.ac_md.z = value;
    }
    @force_immediate(1)
    table get_inv_sqrt_table {
        key = {
           eg_md.ac_md.n : exact;
        }
        actions = {
            get_inv_sqrt_action;
        }
        size = 65536;
    }

    @force_immediate(1)
    table get_log_int_m1_table3 {
        key = {
            eg_md.ac_md.int_m1 : exact;
        }
        actions = {
            get_log_int_m1_action;
        }
        size = 65536;
    }

    @force_immediate(1)
    table get_log_int_m2_table3 {
        key = {
            eg_md.ac_md.int_m2 : exact;
        }
        actions = {
            get_log_int_m2_action;
        }
        size = 65536;
    }

    action get_mirror_cfg(pkt_type_t pkt_type, MirrorId_t eg_mir_ses) {
        eg_md.eg_mir_ses = eg_mir_ses;
        eg_md.pkt_type = pkt_type;
        eg_intr_md_for_dprsr.mirror_type = MIRROR_TYPE_E2E;
        eg_md.timestamp = eg_intr_from_prsr.global_tstamp;
#ifdef DATASET_REPLAY
        eg_md.replay_anomaly = 1;
#ifndef RAW_TIMESTAMP_REPLAY
        hdr.calc.score = eg_md.ac_md.n;
#endif
#endif
    }

    action set_score_extrema() {
        eg_md.ac_md.max_value = max(eg_md.ac_md.at, eg_md.bridge_hdr.S);
        eg_md.ac_md.min_value = min(eg_md.ac_md.at, eg_md.bridge_hdr.S);
    }

    action select_min_s() {
        eg_md.bridge_hdr.S = min(eg_md.bridge_hdr.S, eg_md.bridge_hdr.S_alt);
    }

    action subtract_score_numerator() {
        eg_md.ac_md.at_s = eg_md.ac_md.max_value - eg_md.ac_md.min_value;
    }

    table report_threshold_table {
        key = {
           eg_md.ac_md.n : range;
        }
        actions = {
            get_mirror_cfg;
            NoAction;
        }
        size = 2;
    }

    apply {
#ifdef DATASET_REPLAY
    eg_md.replay_anomaly = 0;
#endif
    if (eg_md.bridge_hdr.isValid()) {
#ifdef DATASET_REPLAY
        eg_md.replay_evaluation_result = replay_count_evaluation.execute(0);
#endif
        select_min_s();
        /* a*t, evaluated by log/exp lookup tables. */
            eg_md.ac_md.int_m1 = eg_md.bridge_hdr.delta;
            get_log_int_m1_table.apply();
            eg_md.ac_md.int_m2 = eg_md.bridge_hdr.time;
            get_log_int_m2_table.apply();
            eg_md.ac_md.n = eg_md.ac_md.log_int_m1 + eg_md.ac_md.log_int_m2;
            get_exp_at_table.apply();
            eg_md.ac_md.at = eg_md.ac_md.z;

            set_score_extrema();
            subtract_score_numerator();

            /* Paper score denominator: sqrt((S+1)*(t-1)). */
            /* This table is populated with log2(S+1), including S=0xffff. */
            eg_md.ac_md.int_m1 = eg_md.bridge_hdr.S;
            eg_md.ac_md.int_m2 = eg_md.bridge_hdr.time - 1;
            get_log_int_m1_table2.apply();
            get_log_int_m2_table2.apply();
            eg_md.ac_md.n = eg_md.ac_md.log_int_m1 + eg_md.ac_md.log_int_m2;
            get_inv_sqrt_table.apply();
            eg_md.ac_md.f_sqrt_s_t_1 = eg_md.ac_md.z;

            if (eg_md.ac_md.at_s != 0) {
                eg_md.ac_md.int_m1 = eg_md.ac_md.at_s;
                get_log_int_m1_table3.apply();
                eg_md.ac_md.int_m2 = eg_md.ac_md.f_sqrt_s_t_1;
                get_log_int_m2_table3.apply();
                eg_md.ac_md.n = eg_md.ac_md.log_int_m1 + eg_md.ac_md.log_int_m2;
                eg_md.ac_md.score_valid = 1;
                report_threshold_table.apply();
#ifdef DATASET_REPLAY
                if (eg_md.replay_anomaly == 1) {
                    eg_md.replay_anomaly_result = replay_count_anomaly.execute(0);
                    eg_md.replay_report_slot =
                        (report_index_t)eg_md.replay_anomaly_result;
                    eg_md.replay_report_write_result =
                        replay_write_flow.execute(eg_md.replay_report_slot);
                    eg_md.replay_report_write_result =
                        replay_write_window.execute(eg_md.replay_report_slot);
                    eg_md.replay_report_write_result =
                        replay_write_r_i.execute(eg_md.replay_report_slot);
                    eg_md.replay_report_write_result =
                        replay_write_r_i_1.execute(eg_md.replay_report_slot);
                    eg_md.replay_report_write_result =
                        replay_write_score.execute(eg_md.replay_report_slot);
                }
#endif
            }
    }
#ifdef DATASET_REPLAY
    /* Mirror reports are retained; suppress the replayed source packet. */
    eg_intr_md_for_dprsr.drop_ctl = 1;
#endif
    }
}

/*
 * The old implementation carried three partially populated arithmetic groups
 * and used the last exponential table as a mirror table.  The complete path
 * above gives every table one operation and detects against the score in the
 * scaled log2 domain, avoiding a lossy final float-to-integer conversion.
 */

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    
    Mirror() mirror;
    apply {
        if(eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
#ifdef DATASET_REPLAY
            mirror.emit<mirror_h>(  eg_md.eg_mir_ses,
                                    {eg_md.timestamp,
                                    eg_md.bridge_hdr.len_i,
                                    eg_md.bridge_hdr.len_i_1,
                                    hdr.ipv4.src_addr,
                                    hdr.ipv4.dst_addr,
                                    hdr.udp.src_port,
                                    hdr.udp.dst_port,
                                    hdr.ipv4.protocol,
                                    eg_md.pkt_type,
                                    hdr.calc.a,
                                    eg_md.ac_md.n});
#else
            mirror.emit<mirror_h>(  eg_md.eg_mir_ses,
                                    {eg_md.timestamp, 
                                    eg_md.bridge_hdr.len_i, 
                                    eg_md.bridge_hdr.len_i_1, 
                                    hdr.ipv4.src_addr, 
                                    hdr.ipv4.dst_addr,
                                    hdr.udp.src_port,
                                    hdr.udp.dst_port,
                                    hdr.ipv4.protocol,
                                    eg_md.pkt_type});
#endif
        }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.calc);
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
