#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
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


// struct digest_1 {

// }

enum bit<8> internal_header_t {
    NONE = 0x0,
    BRIDGE_HDR = 0x1
}

header internal_h {
    internal_header_t header_type;
}

// struct pair_t {
//     bit<16>     value;
//     bit<32>     time;
// }
typedef bit<10> index_t;

// struct pair32_t {
//     bit<32>     value;
//     bit<32>     time;
// }

struct metadata_t {
    internal_h internal_hdr;
    approximate_calculation_metadata_t ac_md;
    bit<16> A_W_T;
    // bit<16> A_W;
    bit<16> time;
    // bit<16> time0;
    // bit<16> time1;

    bit<4> windownum;
    bit<4> windownum_tmp;
    bit<2> time_conv;

    bit<1> equal_sign;
    bit<1> delta_sign;


    bit<16> ret5;
    bit<16> ret4;
    bit<16> ret3;
    bit<16> ret2;
    bit<16> ret1;
    bit<16> ret0;
    // bit<16> ret;

    // bit<16> A_pre1;
    // bit<16> A_pre2;
    // bit<16> A_pre;    

    bit<16> S1;
    bit<16> S2;
    bit<16> S;


    bit<16> t5;
    bit<16> t4;
    bit<16> t3;
    bit<16> t2;
    bit<16> t1;
    bit<16> t0;

    bit<16> v_i;
    bit<16> v_i_1;

    bit<16> len_i;
    bit<16> len_i_1;

    bit<16> delta;
    bit<32> t;
    bit<10> index_0;
    bit<10> index_1;
    // bit<10> index_2;
    // bit<16> tmp1;
    // bit<16> tmp2;


    // example_bridge_h example_bridge_hdr;
    // MirrorId_t egr_mir_ses;   // Egress mirror session ID
}



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

#define TIMESTAMP_REGISTER(num) \
    Register<bit<16>, index_t>(1024) T_REGISTER_##num;   \
    RegisterAction<bit<16>, index_t, bit<16>> (T_REGISTER_##num) T_update_##num = { \
        void apply(inout bit<16> t,out bit<16> reat_t){\
            t =  ig_md.time;\
            reat_t = 0;\
        }\
    };\
    RegisterAction<bit<16>, index_t, bit<16>> (T_REGISTER_##num) T_clean_##num = { \
        void apply(inout bit<16> t,out bit<16> reat_t){\
            t = 0; \
            reat_t = 0;\
        }\
    }; \
    RegisterAction<bit<16>, index_t, bit<16>> (T_REGISTER_##num) T_Query_##num = { \
        void apply(inout bit<16> t,out bit<16> reat_t){\
            reat_t = t;\
            t =  ig_md.time;\
        }\
    }

#define RET_PKTCOUNT_REGISTER(num) \
    Register<bit<16>, index_t>(1024) RET_PKTCOUNT_##num;   \
    RegisterAction<bit<16>, index_t, bit<16>> (RET_PKTCOUNT_##num)     RET_PKTCOUNT_updateClean_##num = { \
        void apply(inout bit<16> pair, out bit<16> read_pair) { \
            if(ig_md.equal_sign == 0){ \
                pair = 0; \
            } else { \
                pair = pair + (bit<16>)hdr.ipv4.total_len ;\
            }\
            \
            read_pair = pair;\
        }\
    }; \
    RegisterAction<bit<16>, index_t, bit<16>> (RET_PKTCOUNT_##num)     RET_PKTCOUNT_query_##num = { \
        void apply(inout bit<16> pair, out bit<16> read_pair) { \
            read_pair = pair;\
        }\
    }  

#define S_REGISTER(num) \
    Register<bit<16>, index_t>(1024) S_##num;   \
    RegisterAction<bit<16>, index_t, bit<16>> (S_##num) S_updateClean_##num = { \
        void apply(inout bit<16> pair, out bit<16> read_pair) { \
            pair = pair + ig_md.delta; \
            read_pair = pair; \
        }\
    }

#define APPLY_HASH(num)                   \
    ig_md.index_##num = hash_##num.get({          \
      hdr.ipv4.src_addr,                  \
      hdr.ipv4.dst_addr,                 \
      hdr.udp.src_port,  \
      hdr.udp.dst_port,\
      hdr.ipv4.protocol \
    })  


//////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////  End sketches ///////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    


    state start {
        ig_md.internal_hdr.setValid();
        // ig_md.example_bridge_hdr.setInvalid();
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
    }
    state parse_calc {
        pkt.extract(hdr.calc);
        transition accept;
    }   
    
}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
        ) {

    Checksum() ipv4_checksum;

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
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.calc);
    }
}



control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    SET_HASH(0, 32w0x04C11DB7);
    SET_HASH(1, 32w0x34FD110C);

    TIMESTAMP_REGISTER(0);
    TIMESTAMP_REGISTER(1);

    TIMESTAMP_REGISTER(2);
    TIMESTAMP_REGISTER(3);

    TIMESTAMP_REGISTER(4);
    TIMESTAMP_REGISTER(5);

    RET_PKTCOUNT_REGISTER(0);
    RET_PKTCOUNT_REGISTER(1);

    RET_PKTCOUNT_REGISTER(2);
    RET_PKTCOUNT_REGISTER(3);

    RET_PKTCOUNT_REGISTER(4);
    RET_PKTCOUNT_REGISTER(5);

    S_REGISTER(0);
    S_REGISTER(1);

    action set_equal_sign(bit<1> sign) {
        ig_md.equal_sign = sign;
    }
    table time_equal_table {
        key = {
            ig_md.A_W_T[7:0] : exact;
            ig_md.time[7:0]:exact;
        }
        actions = {
            set_equal_sign;
        }
        size = 65536;
    }
    
    action set_abs_delta(bit<16> abs_delta){
        ig_md.delta = abs_delta; 
    }
    table delta_abs_table {
        key = {
            ig_md.delta: exact;
        }
        actions = {
            set_abs_delta;
        }
        size = 65535;
    }


    action get_log_int_m1_action(int<16> log_int) {
        ig_md.ac_md.log_int_m1 = log_int;
    }

    table get_log_int_m1_table {
        key = {
            ig_md.ac_md.int_m1 : exact;
        }
        actions = {
            get_log_int_m1_action;
        }

        size = 65536; 
    }

    action get_log_int_m2_action(int<16> log_int) {
        ig_md.ac_md.log_int_m2 = log_int;
    }
    table get_log_int_m2_table {
        key = {
            ig_md.ac_md.int_m2 : exact;
        }
        actions = {
            get_log_int_m2_action;
        }

        size = 65536; 
    }

    

    action get_abs_z_action(int<16> abs_z) {
        ig_md.ac_md.z = abs_z;
    }

    @force_immediate(1)
    table get_abs_z_table {
        key = {
           ig_md.ac_md.n : exact;
        }
        actions = {
            get_abs_z_action;
        }

        size = 65536; 
    }

    table get_log_int_m1_table2 {
        key = {
            ig_md.ac_md.int_m1 : exact;
        }
        actions = {
            get_log_int_m1_action;
        }

        size = 65536; 
    }

    table get_log_int_m2_table2 {
        key = {
            ig_md.ac_md.int_m2 : exact;
        }
        actions = {
            get_log_int_m2_action;
        }

        size = 65536; 
    }

     @force_immediate(1)
    table get_abs_z_table2 {
        key = {
           ig_md.ac_md.n : exact;
        }
        actions = {
            get_abs_z_action;
        }

        size = 65536; 
    } 

    table get_log_int_m1_table3 {
        key = {
            ig_md.ac_md.int_m1 : exact;
        }
        actions = {
            get_log_int_m1_action;
        }

        size = 65536; 
    }

    table get_log_int_m2_table3 {
        key = {
            ig_md.ac_md.int_m2 : exact;
        }
        actions = {
            get_log_int_m2_action;
        }

        size = 65536; 
    }

    @force_immediate(1)
    table get_abs_z_table3 {
        key = {
           ig_md.ac_md.n : exact;
        }
        actions = {
            get_abs_z_action;
        }

        size = 65536; 
    }


    apply{
    ig_md.time = ig_prsr_md.global_tstamp[31:16];
    ig_md.windownum = (bit<4>)(ig_md.time >> 12);

    ig_md.time_conv = (bit<2>)(ig_md.windownum_tmp & 0b11);
    if(ig_md.windownum_tmp == 3){
        ig_md.windownum = 0;
    }
    else{
        ig_md.windownum = ig_md.windownum_tmp;
    }
    APPLY_HASH(0);
    APPLY_HASH(1);
    // APPLY_HASH(2);
    // APPLY_HASH(3);
    ig_md.t0 = T_Query_0.execute(ig_md.index_0);
    ig_md.t1 = T_Query_1.execute(ig_md.index_1);

    ig_md.t2 = T_Query_2.execute(ig_md.index_0);
    ig_md.t3 = T_Query_3.execute(ig_md.index_1);

    ig_md.t4 = T_Query_4.execute(ig_md.index_0);
    ig_md.t5 = T_Query_5.execute(ig_md.index_1);
    if(ig_md.time_conv == 0){
        ig_md.A_W_T = min(ig_md.t0, ig_md.t1);
    }
    if(ig_md.time_conv == 1){
        ig_md.A_W_T = min(ig_md.t2, ig_md.t3);
    }
    if(ig_md.time_conv == 2){
        ig_md.A_W_T = min(ig_md.t4, ig_md.t5);
    }
    
    time_equal_table.apply();
    
    ig_md.ret0 = RET_PKTCOUNT_updateClean_0.execute(ig_md.index_0);
    ig_md.ret1 = RET_PKTCOUNT_updateClean_1.execute(ig_md.index_1);
    ig_md.ret2 = RET_PKTCOUNT_updateClean_2.execute(ig_md.index_0);
    ig_md.ret3 = RET_PKTCOUNT_updateClean_3.execute(ig_md.index_1);
    ig_md.ret4 = RET_PKTCOUNT_updateClean_4.execute(ig_md.index_0);
    ig_md.ret5 = RET_PKTCOUNT_updateClean_5.execute(ig_md.index_1);

    if(ig_md.equal_sign == 0){
        if(ig_md.time_conv == 0){
            ig_md.v_i_1 = min(ig_md.t2, ig_md.t3);
            ig_md.len_i_1 = min(ig_md.ret2, ig_md.ret3);

            ig_md.v_i = min(ig_md.t4, ig_md.t5);
            ig_md.len_i = min(ig_md.ret4, ig_md.ret5);
        }
        if(ig_md.time_conv == 1){
            ig_md.v_i_1 = min(ig_md.t4, ig_md.t5);
            ig_md.len_i_1 = min(ig_md.ret2, ig_md.ret3);

            ig_md.v_i = min(ig_md.t0, ig_md.t1);
            ig_md.len_i = min(ig_md.ret4, ig_md.ret5);
        }
        if(ig_md.time_conv == 2){
            
            ig_md.v_i_1 = min(ig_md.t2, ig_md.t3);
            ig_md.len_i_1 = min(ig_md.ret2, ig_md.ret3);

            ig_md.v_i = min(ig_md.t2, ig_md.t3);
            ig_md.len_i = min(ig_md.ret4, ig_md.ret5);
        }
    }

    
    ig_md.delta = ig_md.len_i - ig_md.len_i_1;
    delta_abs_table.apply();

    ig_md.S1 = S_updateClean_0.execute(ig_md.index_0);
    ig_md.S2 = S_updateClean_1.execute(ig_md.index_1);
    ig_md.S = min(ig_md.S1, ig_md.S2);



    ig_md.ac_md.a_avg = ig_md.delta;
    ig_md.ac_md.s_avg = ig_md.S;
    ig_md.ac_md.t = ig_md.time;
    
    ig_md.ac_md.int_m1 = ig_md.ac_md.a_avg;
    get_log_int_m1_table.apply();

    ig_md.ac_md.int_m2 = ig_md.ac_md.t;
    get_log_int_m2_table.apply();

    ig_md.ac_md.sign_z = 0x0000;
    ig_md.ac_md.n = ig_md.ac_md.log_int_m1 + ig_md.ac_md.log_int_m2;
    get_abs_z_table.apply();
    ig_md.ac_md.z = ig_md.ac_md.z | ig_md.ac_md.sign_z;
    ig_md.ac_md.at = ig_md.ac_md.z;  // a*t  is INT16
    // checked

    
    



    ig_md.ac_md.z = ig_md.ac_md.at - ig_md.ac_md.s_avg;
    if (ig_md.ac_md.z[15:15]==0) {
        ig_md.ac_md.at_s = ig_md.ac_md.s_avg - ig_md.ac_md.at;
    } else {
        // ig_md.ac_md.s0 = 0xFFFF^ig_md.ac_md.z;
        ig_md.ac_md.at_s =  ig_md.ac_md.at - ig_md.ac_md.s_avg ;
    }
    // checked

    
   

    ig_md.ac_md.int_m1 = ig_md.ac_md.s_avg;
    get_log_int_m1_table2.apply();
    ig_md.ac_md.int_m2 = ig_md.ac_md.t - 1;
    get_log_int_m2_table2.apply();
    ig_md.ac_md.sign_z = 0x0000;
    ig_md.ac_md.n = ig_md.ac_md.log_int_m1 + ig_md.ac_md.log_int_m2; // checked
    // ig_md.ac_md.n = hdr.calc.a; // for debug 4449-> 56792?
    get_abs_z_table2.apply();
    ig_md.ac_md.f_sqrt_s_t_1 = ig_md.ac_md.z ; // 1/sqrt(s*(t-1))  float16
    //


    // for debug
    
    

    ig_md.ac_md.int_m1 = ig_md.ac_md.at_s;
    get_log_int_m1_table3.apply();
    ig_md.ac_md.log_int_m2 = ig_md.ac_md.f_sqrt_s_t_1; // is a bit16 float >1
    get_log_int_m2_table3.apply();
    // ig_md.ac_md.sign_z = 0x0000;

    ig_md.ac_md.n = ig_md.ac_md.log_int_m1 + ig_md.ac_md.log_int_m2;
    get_abs_z_table3.apply();
    ig_md.ac_md.score = ig_md.ac_md.z ;


    // hdr.calc.a = ig_md.ac_md.log_int_m1;
    // hdr.calc.s = ig_md.ac_md.log_int_m2;
    // hdr.calc.t = ig_md.ac_md.n;
    hdr.calc.score = ig_md.ac_md.score;

    if(ig_intr_md.ingress_port==128) {
        ig_tm_md.ucast_egress_port = 136;
    } else {
        ig_tm_md.ucast_egress_port =128;
    }
        ig_tm_md.bypass_egress = 1w1;
    }

}




Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;