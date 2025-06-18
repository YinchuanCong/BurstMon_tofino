/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header calc_h {
    int<16> a;
    int<16> s;
    int<16> t;
    int<16> score;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    // vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    // ipv6_h ipv6;

    // tcp_h tcp;
    udp_h udp;
    calc_h calc;


    // Add more headers here.
}

struct empty_header_t {}

struct empty_metadata_t {}

// --------------------------------------------------------------
struct approximate_calculation_metadata_t {
    int<16> frac_x;
    int<16> frac_y;
    int<16> sign;
    int<16> frac_z;
    int<16> log_i;
    int<16> log_j;
    int<16> log_k;
    int<16> log_m;
    int<16> n;
    int<16> sign_z;
    int<8>  info;
    int<8>  flag;
    int<16> z;


    int<16> a1;
    int<16> a2;
    int<16> a3;
    int<16> a0;
    int<16> a_avg;
    int<16> s1;
    int<16> s2;
    int<16> s3;
    int<16> s0;
    int<16> s_avg;

    int<16> int_m1;
    int<16> log_int_m1;

    int<16> int_m2;
    int<16> log_int_m2;
    
    int<48> timetstamp;
    int<16> t;


    int<16> m1;
    int<16> m2;

    int<16> at;
    int<16> at_s;
    int<16> s_t_1;
    int<16> score;

    
    int<16> f_sqrt_s_t_1;
    int<16> t_minus_1;
}

#endif /* _HEADERS_ */
