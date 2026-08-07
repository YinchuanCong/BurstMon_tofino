################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2019-present Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.  Dissemination of
# this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a written
# agreement with Barefoot Networks, Inc.
#
################################################################################

import logging
import grpc
import time
import sys

from ptf import config
from ptf.thriftutils import *
import ptf.testutils as testutils
from ptf.testutils import *
from bfruntime_client_base_tests import BfRuntimeTest, BaseTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import google.rpc.code_pb2 as code_pb2
from functools import partial

import random
import math 


# import nnpy
import struct,math 

from ptf.base_tests import BaseTest
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol
import importlib
import unittest
import sys
import ptf


logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

dev_id = 0
if test_param_get("arch") == "tofino":
    MIR_SESS_COUNT = 1024
    MAX_SID_NORM = 1015
    MAX_SID_COAL = 1023
    BASE_SID_NORM = 1
    BASE_SID_COAL = 1016
    EXP_LEN1 = 127
    EXP_LEN2 = 63
elif test_param_get("arch") == "tofino2":
    MIR_SESS_COUNT = 256
    MAX_SID_NORM = 255
    MAX_SID_COAL = 255
    BASE_SID_NORM = 0
    BASE_SID_COAL = 0
    EXP_LEN1 = 127
    EXP_LEN2 = 59
else:
    assert False, "Unsupported arch %s" % test_param_get("arch")

EGRESS_PORT_INVALID = 511

MCID1 = 1
MCID2 = 2
HASH1 = 1
HASH2 = 2

base_pick_path = testutils.test_param_get("base_pick_path")
binary_name = testutils.test_param_get("arch")
if binary_name  is not "tofino2" and binary_name is not "tofino":
    assert 0, "%s is unknown arch" %(binary_name)

if not base_pick_path:
    base_pick_path = "install/share/" + binary_name + "pd/"

base_put_path = testutils.test_param_get("base_put_path")
if not base_put_path:
    base_put_path = "install/share/"+ binary_name + "pd/forwarding"

logger.info("\nbase_put_path=%s \nbase_pick_path=%s", base_pick_path, base_put_path)

def create_path_bf_rt(base_path, p4_name_to_use):
    return base_path + "/" + p4_name_to_use + "/bf-rt.json"

def create_path_context(base_path, p4_name_to_use, profile_name):
    return base_path + "/" + p4_name_to_use + "/" + profile_name + "/context.json"

def create_path_tofino(base_path, p4_name_to_use, profile_name):
    return base_path + "/" + p4_name_to_use + "/" + profile_name + "/" + binary_name +".bin"


def complement_16bit(num):
    """Convert a value to its 16-bit two's-complement representation."""
    if num >= 0:
        return num
    else:
        return (1 << 16) + num

def portToBitIdx(port):
    pipe = port_to_pipe(port)
    index = port_to_pipe_local_port(port)
    return 72 * pipe + index


def set_port_map(indicies):
    bit_map = [0] * ((288 + 7) // 8)
    for i in indicies:
        index = portToBitIdx(i)
        bit_map[index // 8] = (bit_map[index // 8] | (1 << (index % 8))) & 0xFF
    return bytes_to_string(bit_map)


def set_lag_map(indicies):
    bit_map = [0] * ((256 + 7) // 8)
    for i in indicies:
        bit_map[i // 8] = (bit_map[i // 8] | (1 << (i % 8))) & 0xFF
    return bytes_to_string(bit_map)


def verify_coal_pkt(self, pkt, port):
    logging.debug("Checking for pkt on port %r", port)
    (_, rcv_port, rcv_pkt, pkt_time) = self.dataplane.poll(port_number=port, timeout=2, exp_pkt=None)
    self.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % port)
    print()
    hexdump(rcv_pkt)
    sys.stdout.flush()
    # only compare slices
    print()
    hexdump(pkt)
    sys.stdout.flush()


def setup_random(seed_val=0):
    if 0 == seed_val:
        seed_val = int(time.time())
    logger.info("Seed is: %d", seed_val)
    sys.stdout.flush()
    random.seed(seed_val)


def make_port(pipe, local_port):
    assert (pipe >= 0 and pipe < 4)
    assert (local_port >= 0 and local_port < 72)
    return (pipe << 7) | local_port


def port_to_pipe(port):
    local_port = port & 0x7F
    assert (local_port < 72)
    pipe = (port >> 7) & 0x3
    assert (port == ((pipe << 7) | local_port))
    return pipe


def port_to_pipe_local_port(port):
    return port & 0x7F


swports = []
swports_by_pipe = {}
for device, port, ifname in config["interfaces"]:
    pipe = port_to_pipe(port)
    if pipe not in list(range(int(test_param_get('num_pipes')))):
        continue
    if pipe not in swports_by_pipe:
        swports_by_pipe[pipe] = []
    swports.append(port)
    swports.sort()
    swports_by_pipe[pipe].append(port)
    swports_by_pipe[pipe].sort()

if swports == []:
    for pipe in range(int(test_param_get('num_pipes'))):
        for port in range(2):
            swports.append(make_port(pipe, port))
print()
"Using ports:", swports
sys.stdout.flush()

def float_to_half_precision(f):
    # Convert a single-precision (32-bit) float to half precision (16-bit).
    try:
        # Pack the value as a 32-bit single-precision float.
        packed_32bit = struct.pack('!f', f)
        # Unpack it as an integer.
        int_32bit = int.from_bytes(packed_32bit, 'big')
        
        # Extract the sign, exponent, and mantissa fields.
        sign = (int_32bit >> 31) & 0x1
        exponent = (int_32bit >> 23) & 0xFF
        mantissa = int_32bit & 0x7FFFFF
        
        # Convert to half precision.
        if exponent == 0:  # Subnormal number
            half_exponent = 0
            half_mantissa = mantissa >> 13
        elif exponent == 0xFF:  # Infinity or NaN
            half_exponent = 0x1F
            half_mantissa = 0x3FF if mantissa else 0
        else:  # Normal number
            half_exponent = exponent - 127 + 15
            if half_exponent <= 0:  # Convert to a subnormal number
                half_exponent = 0
                half_mantissa = mantissa >> (13 - half_exponent)
            elif half_exponent >= 0x1F:  # Convert to infinity
                half_exponent = 0x1F
                half_mantissa = 0
            else:
                half_mantissa = mantissa >> 13
        
        # Assemble the 16-bit half-precision representation.
        half_float = (sign << 15) | (half_exponent << 10) | half_mantissa
        # Pack as two bytes.
        packed = half_float.to_bytes(2, 'big')
        int_val = int.from_bytes(packed, 'big')
        return int_val
    except struct.error as e:
        print("Error: {e}")
        return None


def int_to_hex_16bit_signed(n):
    # Pack a 16-bit value as two bytes.
    packed = struct.pack('>H', n)  # '>H' is a big-endian unsigned 16-bit integer.
    # Convert the binary data to a hexadecimal string.
    int_val = int.from_bytes(packed, 'big')
    hex_value = hex(int_val)
    return int_val 


def intcode_to_half_float(int_value):
    # Ensure that the input is a 16-bit integer.
    if not (0 <= int_value <= 0xFFFF):
        raise ValueError("input must be a 16-bit integer")
    
    # Extract the sign, exponent, and mantissa fields.
    sign_bit = (int_value >> 15) & 0x1  # Sign bit (bit 15)
    exponent_bits = (int_value >> 10) & 0x1F  # Exponent (bits 10-14)
    mantissa_bits = int_value & 0x3FF  # Mantissa (bits 0-9)
    
    # Calculate the sign.
    sign = (-1) ** sign_bit
    
    # Handle subnormal numbers.
    if exponent_bits == 0:
        if mantissa_bits == 0:
            return sign * 0.0  # Positive or negative zero
        else:
            # Subnormal number
            exponent = -14
            mantissa = mantissa_bits / 1024.0  # 2^10
    # Handle infinity and NaN.
    elif exponent_bits == 0x1F:
        if mantissa_bits == 0:
            return sign * float('inf')  # Infinity
        else:
            return float('nan')  # NaN
    # Handle normal numbers.
    else:
        exponent = exponent_bits - 15
        mantissa = 1 + mantissa_bits / 1024.0  # 2^10
    
    # Calculate the floating-point value.
    return sign * (2 ** exponent) * mantissa


def float_to_binary16(f):
    # Convert to a 32-bit float and then truncate to 16 bits.
    packed = struct.pack('!f', f)
    uint32 = struct.unpack('!I', packed)[0]
    # IEEE 754 Binary16 conversion rules.
    sign = (uint32 >> 31) & 0x1
    exponent = ((uint32 >> 23) & 0xFF) - 127  # Adjust the exponent bias.
    mantissa = uint32 & 0x7FFFFF
    # Handle special cases (NaN, infinity, and subnormal values).
    if exponent == 128:  # Inf/NaN
        binary16 = (sign << 15) | 0x7C00 | ((mantissa != 0) << 9)
    elif exponent <= -15:  # Zero or subnormal
        binary16 = (sign << 15) | (0 if (exponent < -24) else ((mantissa | 0x800000) >> (18 - exponent)))
    else:  # Normal case
        binary16 = (sign << 15) | ((exponent + 15) << 10) | (mantissa >> 13)
    return binary16

def binary16_to_float(bits):
    sign = (bits >> 15) & 0x1
    exponent = (bits >> 10) & 0x1F
    mantissa = bits & 0x3FF
    if exponent == 0:
        return (-1)**sign * (mantissa / 1024.0) * 2**(-14)  # Subnormal
    elif exponent == 0x1F:
        return float('inf') if (mantissa == 0) else float('nan')  # Inf/NaN
    else:
        return (-1)**sign * (1 + mantissa / 1024.0) * 2**(exponent - 15)  # Normal


class BurstMon(BfRuntimeTest):
    port_speed_dict = {}
    port_statistic_dict = {}
    def set_up_pal_module(self):
        try:
            self.pal_client_module = importlib.import_module(".".join(["pal_rpc", "pal"]))
        except:
            self.pal_client_module = None
        logger.info("self.pal setttings")
        thrift_server = 'localhost'
        if testutils.test_param_get('thrift_server') != "":
            thrift_server = testutils.test_param_get('thrift_server')
        self.transport = TSocket.TSocket(thrift_server, 9090)

        self.transport = TTransport.TBufferedTransport(self.transport)
        bprotocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        if self.pal_client_module:
            self.pal_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "pal")
            self.pal = self.pal_client_module.Client(self.pal_protocol)
        else:
            self.pal_protocol = None
            self.pal = None
        self.transport.open()

    def setUp(self):
        client_id =0 
        self.p4_name = 'burstmon'
        BfRuntimeTest.setUp(self, client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        self.get_table()
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.set_up_pal_module()
        self.devPorts = [136,128]
        # self.up_ports() 

    def up_ports(self):
        for sw_port in self.devPorts:
            self.pal.pal_port_add(0, sw_port, pal_port_speed_t.BF_SPEED_10G, pal_fec_type_t.BF_FEC_TYP_NONE)
            # self.pal.pal_port_an_set(0, sw_port, 2)
            self.pal.pal_port_enable(0, sw_port)
            logger.info("add and enable port,", sw_port)
    
    
    def open_port(self, target):
        Speed_dict = {"100G":"BF_SPEED_100G", "10G":"BF_SPEED_10G"}
        Fec_dict = {"RS":"BF_FEC_TYP_RS", "NONE":"BF_FEC_TYP_NONE"}
        AN_dict = {0:"PM_AN_DEFAULT", 1:"PM_AN_FORCE_ENABLE", 2:"PM_AN_FORCE_DISABLE"}
        Loop_Back = {0:"BF_LPBK_NONE", 1:"BF_LPBK_MAC_NEAR"}
        port_lst = [
            {
                "port" : 176,
                "speed" : Speed_dict["100G"],
                "fec" : Fec_dict["RS"],
                "an" : AN_dict[0],
                "lpbk" : Loop_Back[0]

            },
            {
                "port" : 184,
                "speed" : Speed_dict["100G"],
                "fec" : Fec_dict["RS"],
                "an" : AN_dict[0],
                "lpbk" : Loop_Back[0]
            }
        ]
        for index, item in enumerate(port_lst, 1):
            self.port_table.entry_add(
                target,
                [self.port_table.make_key([gc.KeyTuple('$DEV_PORT', item["port"])])],
                [
                    self.port_table.make_data(
                        [
                            gc.DataTuple('$SPEED', str_val=item["speed"]),
                            gc.DataTuple('$FEC', str_val=item["fec"]),
                            gc.DataTuple('$AUTO_NEGOTIATION',str_val=item["an"]),
                            gc.DataTuple('$LOOPBACK_MODE',str_val=item["lpbk"]),
                            gc.DataTuple('$PORT_ENABLE', bool_val=True)
                        ]
                    )
                ]
            )
            self.port_statistic_dict[item["port"]] = {
                "port":item["port"], "tx_pkts":0, "tx_MB":0, "rx_pkts":0, "rx_MB":0
            }
            self.port_speed_dict[item["port"]] = {
                'tx':0, 'tx_MB':0, 'rx':0, 'rx_MB':0
            }
            time.sleep(2)

    def get_table(self):
        pass 
        self.tables = {
            "SwithIngress.get_log_int_m1_table" : self.bfrt_info.table_get("get_log_int_m1_table"),
            "SwithIngress.get_log_int_m2_table" : self.bfrt_info.table_get("get_log_int_m2_table"),
            "SwitchIngress.get_abs_z_table"   : self.bfrt_info.table_get("get_abs_z_table"), 

            "SwithIngress.get_log_int_m1_table2" : self.bfrt_info.table_get("get_log_int_m1_table2"),
            "SwithIngress.get_log_int_m2_table2" : self.bfrt_info.table_get("get_log_int_m2_table2"),
            "SwitchIngress.get_abs_z_table2"   : self.bfrt_info.table_get("get_abs_z_table2"),   

            "SwithIngress.get_log_int_m1_table3" : self.bfrt_info.table_get("get_log_int_m1_table"),
            "SwithIngress.get_log_int_m2_table3" : self.bfrt_info.table_get("get_log_int_m2_table"),
            "SwitchIngress.get_abs_z_table3"   : self.bfrt_info.table_get("get_abs_z_table"), # is this a bug?

        }


    def runTest(self):
        logger.info("=============== BurstMon runtime  ===============")
        bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        # mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
        # self.mirror_fwd_table = bfrt_info.table_get("$mirror_fwd")

        # logger.info(mirror_cfg_table)
        target = gc.Target(device_id=0, pipe_id=0xffff)
        
        
        
        self.port_table = bfrt_info.table_get("$PORT")
        self.port_stat_table = bfrt_info.table_get("$PORT_STAT")
        self.port_hdl_info_table = bfrt_info.table_get("$PORT_HDL_INFO")
        self.port_fp_idx_info_table = bfrt_info.table_get("$PORT_FP_IDX_INFO")
        self.port_str_info_table = bfrt_info.table_get("$PORT_STR_INFO")

        self.open_port(target)
        setup_random()
        self.sids = []
        num_pipes = int(test_param_get('num_pipes'))


        SCALING_FACTOR = 256

        if_log_int_m1_table =  False
        if_log_int_m2_table =  False  
        if_abs_z_table =  False     
        
        
        if_log_int_m1_table2 = False
        if_log_int_m2_table2 = False
        if_abs_z_table2 = False                  
        
        
        
        if_log_int_m1_table3 = True 
        if_log_int_m2_table3 = True  
        if_abs_z_table3 = True    
        
        

        # Calculate a*t; the result remains INT16.

        ##############################################################################
        #############################for debug#################################################
        
            
        #############################for debug#################################################
        ##############################################################################
            
        #  table get_log_int_m1_table
        if if_log_int_m1_table:
            table = bfrt_info.table_get("SwitchIngress.get_log_int_m1_table")
            table.default_entry_reset(target)
            for i in range(1,2**16):
                try:
                    logger.info("table add testing")
                    logger.info("i = %d",i)
                    binary = format(i,'016b')
                    logger.info("binary is : %s",binary)
                    
                    log_i = int(math.log2(i)*SCALING_FACTOR)
                    logger.info("int(log_i* SCALING_FACTOR) = %d",log_i)
                    
                    
                    table.entry_add(
                        target,
                        [table.make_key([gc.KeyTuple("ig_md.ac_md.int_m1",i)])],
                        [table.make_data([gc.DataTuple("log_int",int_to_hex_16bit_signed(log_i))],"SwitchIngress.get_log_int_m1_action")]

                    )
                except:
                    logger.info('Table: get_log_i_action, error at %d',i)
                    break 

        # get_log_int_m2_table
        if if_log_int_m2_table:
            table = bfrt_info.table_get("SwitchIngress.get_log_int_m2_table")
            table.default_entry_reset(target)
            for i in range(1,2**16):
                try:
                    logger.info("table add testing")
                    logger.info("i = %d",i)
                    binary = format(i,'016b')
                    logger.info("binary is : %s",binary)
                    
                    log_i = int(math.log2(i)*SCALING_FACTOR)
                    logger.info("int(log_i* SCALING_FACTOR) = %d",log_i)
                    
                    
                    table.entry_add(
                        target,
                        [table.make_key([gc.KeyTuple("ig_md.ac_md.int_m2",i)])],
                        [table.make_data([gc.DataTuple("log_int",int_to_hex_16bit_signed(log_i))],"SwitchIngress.get_log_int_m2_action")]

                    )
                except:
                    logger.info('Table: get_log_i_action, error at %d',i)
                    break

        # get_abs_z_table 
        if if_abs_z_table:
            table = bfrt_info.table_get("SwitchIngress.get_abs_z_table")
            for i in range(-1*int(15*SCALING_FACTOR),int(15*SCALING_FACTOR)):
                try:
                    print(i,end='   ')
                    # binary_str = bin(i)[2:].zfill(16)
                    binary_str = ''.join(format(by,'08b') for by in struct.pack('!h',i))

                    i_16bit = int_to_hex_16bit_signed(i)
                    print(binary_str)
                    # float_value = struct.unpack('!e', bytes.fromhex(hex(int(binary_str, 2))[2:].zfill(4)))[0]
                    # exp_i = math.log2(1-2**float_value)
                    # print(float_value)
                    exp_i = 2**(i*1.0/SCALING_FACTOR)*1.0
                    print(exp_i)
                    # exp_i_str=float_to_binary(float_value=exp_i)
                    # exp_i_binary_16 = float_to_half_precision(exp_i)
                    exp_i_binary_16 = int_to_hex_16bit_signed(int(exp_i))

                    # exp_i_str=''.join(format(by,'08b') for by in struct.pack('!e',exp_i))
                    # print(exp_i,end='   ')
                    # print(exp_i_str)
                    # print() 
                    table.entry_add(
                        target,
                        [table.make_key([gc.KeyTuple("ig_md.ac_md.n",i_16bit)])],
                        [table.make_data([gc.DataTuple("abs_z",exp_i_binary_16)],"SwitchIngress.get_abs_z_action")]
                    )
                except:
                    print('Table: get_abs_z_table, error at',i)
                



        ###################################################################################################################################################################################################################################################################################################### table1 end 


        # Calculate |s*(t-1)|.
        if if_log_int_m1_table2:
            table = bfrt_info.table_get("SwitchIngress.get_log_int_m1_table2")
            table.default_entry_reset(target)
            for i in range(1,2**16):
                try:
                    logger.info("table add testing")
                    logger.info("i = %d",i)
                    binary = format(i,'016b')
                    logger.info("binary is : %s",binary)
                    
                    log_i = int(math.log2(i)*SCALING_FACTOR)
                    logger.info("int(log_i* SCALING_FACTOR) = %d",log_i)
                    
                    
                    table.entry_add(
                        target,
                        [table.make_key([gc.KeyTuple("ig_md.ac_md.int_m1",i)])],
                        [table.make_data([gc.DataTuple("log_int",int_to_hex_16bit_signed(log_i))],"SwitchIngress.get_log_int_m1_action")]

                    )
                except:
                    logger.info('Table: get_log_i_action, error at %d',i)
                    break 

        # get_log_int_m2_table
        if if_log_int_m2_table2:
            table = bfrt_info.table_get("SwitchIngress.get_log_int_m2_table2")
            table.default_entry_reset(target)
            for i in range(1,2**16):
                try:
                    logger.info("table add testing")
                    logger.info("i = %d",i)
                    binary = format(i,'016b')
                    logger.info("binary is : %s",binary)
                    
                    log_i = int(math.log2(i)*SCALING_FACTOR)
                    logger.info("int(log_i* SCALING_FACTOR) = %d",log_i)
                    
                    
                    table.entry_add(
                        target,
                        [table.make_key([gc.KeyTuple("ig_md.ac_md.int_m2",i)])],
                        [table.make_data([gc.DataTuple("log_int",int_to_hex_16bit_signed(log_i))],"SwitchIngress.get_log_int_m2_action")]
                    )
                except:
                    logger.info('Table: get_log_i_action, error at %d',i)
                    break



        # get_abs_z_table2: combine exp^n and inverse square root in the final table to calculate 1/sqrt(st).
        if if_abs_z_table2:
            table = bfrt_info.table_get("SwitchIngress.get_abs_z_table2")

            for i in range(1,int(16*SCALING_FACTOR)):
                try:
                    print(i,end='   ')
                    # i_16 = struct.unpack("!h",struct.pack("!h",i))[0]
                    exp_i = 1.0/math.sqrt(2**(i*1.0/SCALING_FACTOR))

                    exp_i_binary_16 = float_to_binary16(exp_i)
                    print(exp_i)
                    print(exp_i_binary_16)
                    table.entry_add(
                        target,
                        [table.make_key([gc.KeyTuple("ig_md.ac_md.n",i)])],
                        [table.make_data([gc.DataTuple("abs_z",exp_i_binary_16)],"SwitchIngress.get_abs_z_action")]
                    )
                    # time.sleep(0.5)
                    print()
                except:
                    print('Table: get_abs_z_table2, error at',i)
        
        
        ########################################################################################################################################################################################################################################################################################## Table2 end 


        # Calculate |a*t-s| / sqrt(s*(t-1)); the result remains INT16.

        table = bfrt_info.table_get("SwitchIngress.get_log_int_m1_table3")
        table.default_entry_reset(target)
        for i in range(1,2**16):
            try:
                logger.info("table add testing")
                logger.info("i = %d",i)
                binary = format(i,'016b')
                logger.info("binary is : %s",binary)
                
                log_i = complement_16bit(int(math.log2(i)*SCALING_FACTOR))
                logger.info("int(log_i* SCALING_FACTOR) = %d",log_i)
                
                
                table.entry_add(
                    target,
                    [table.make_key([gc.KeyTuple("ig_md.ac_md.int_m1",i)])],
                    [table.make_data([gc.DataTuple("log_int",int_to_hex_16bit_signed(log_i))],"SwitchIngress.get_log_int_m1_action")]
                    # [table.make_data([gc.DataTuple("log_int",log_i)],"SwitchIngress.get_log_int_m1_action")]
                    

                )
            except:
                logger.info('Table: get_log_int_m1_table3, error at %d',i)
                break 

        
        # get_log_int_m2_table3 handles logarithms of floating-point values below 1.
        table = bfrt_info.table_get("SwitchIngress.get_log_int_m2_table3")
        table.default_entry_reset(target)
        for i in range(1,2**16):
            try:
                logger.info("table add testing")
                logger.info("i = %d",i)
                binary = format(i,'016b')
                logger.info("binary is : %s",binary)
                
                f_i = binary16_to_float(i)  # Logarithm of a floating-point value.
                log_i = complement_16bit(int(math.log2(f_i)*SCALING_FACTOR))
                
                
                logger.info("int(log_i* SCALING_FACTOR) = %d",log_i)
                
                
                table.entry_add(
                    target,
                    [table.make_key([gc.KeyTuple("ig_md.ac_md.int_m2",i)])],
                    # [table.make_data([gc.DataTuple("log_int",int_to_hex_16bit_signed(log_i))],"SwitchIngress.get_log_int_m2_action")]
                    [table.make_data([gc.DataTuple("log_int",log_i)],"SwitchIngress.get_log_int_m2_action")]
                    

                )
            except:
                logger.info('Table: get_log_int_m2_table3, error at %d',i)
                break


        # get_abs_z_table3 performs exponentiation.
        table = bfrt_info.table_get("SwitchIngress.get_abs_z_table3")
        for i in range(-1*int(15*SCALING_FACTOR),int(15*SCALING_FACTOR)):
            try:
                print(i,end='   ')
                # binary_str = bin(i)[2:].zfill(16)
                binary_str = ''.join(format(by,'08b') for by in struct.pack('!h',i))

                i_16bit = int_to_hex_16bit_signed(i)
                print(binary_str)
                # float_value = struct.unpack('!e', bytes.fromhex(hex(int(binary_str, 2))[2:].zfill(4)))[0]
                # exp_i = math.log2(1-2**float_value)
                # print(float_value)
                exp_i = 2**(i*1.0/SCALING_FACTOR)*1.0
                print(exp_i)
                exp_i_binary_16=float_to_binary(float_value=exp_i)
                # exp_i_binary_16 = float_to_half_precision(exp_i)
                # exp_i_binary_16 = int_to_hex_16bit_signed(int(exp_i))

                # exp_i_str=''.join(format(by,'08b') for by in struct.pack('!e',exp_i))
                # print(exp_i,end='   ')
                # print(exp_i_str)
                # print() 
                table.entry_add(
                    target,
                    [table.make_key([gc.KeyTuple("ig_md.ac_md.n",i_16bit)])],
                    [table.make_data([gc.DataTuple("abs_z",exp_i_binary_16)],"SwitchIngress.get_abs_z_action")]
                )
            except:
                print('Table: get_abs_z_table, error at',i)
        return 

        print("table load finished!!!")



       

            
    
