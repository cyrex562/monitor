import argparse
import csv
import ctypes
import datetime
import os
import shutil
import sys
import struct
import multiprocessing
from _ctypes import POINTER

from net.ethernet import mac_to_str, EtherType
from net.pcap import pcap_open_live, PcapPktHdr, pcap_next_ex, c_ubyte

import monitor.processor.mesh.node as nodes
import nodes.pcap_input as pcap_input

PCAP_ERR_BUF_SZ = 4096

# WIFI DEV_NAME
DEF_DEV_NAME = r"\Device\NPF_{78DADAC0-4EF1-4558-B473-9975EF249D9E}"


class Context(object):
    def __init__(self,
                 out_file,
                 redis_key,
                 dev_name,
                 snap_len=0xffff,
                 timeout=1000,
                 store_to_file=False,
                 store_to_redis=False,
                 print_to_screen=False,
                 mode="overwrite"):
        self.store_to_file = store_to_file
        self.store_to_redis = store_to_redis
        self.print_to_screen = print_to_screen
        self.out_file = out_file
        self.redis_key = redis_key
        self.dev_name = dev_name
        self.snap_len = snap_len
        self.promiscuous = True
        self.timeout = timeout
        self.mode = mode


def parse_cmd_line():
    parser = argparse.ArgumentParser(
        description="collect mac addresses from traffic and store it")
    parser.add_argument(
        "--store_to_file",
        "-f",
        action="store_true",
        help="store mac addresses to file",
        default=False)
    parser.add_argument(
        "--store_to_redis",
        "-r",
        action="store_true",
        help="store mac addresses to redis",
        default=False)
    parser.add_argument(
        "--print_to_screen",
        "-p",
        action="store_true",
        help="print the table to the screen",
        default=False)
    parser.add_argument(
        "--out_file",
        "-o",
        help="path for the output file",
        default=os.path.join(os.getcwd(), "mac.addresses"))
    parser.add_argument(
        "--redis_key",
        "-k",
        help="key to store mac address information in",
        default="titan:mac_addresses")
    parser.add_argument(
        "--dev_name",
        "-d",
        help="device name",
        default=DEF_DEV_NAME)
    parser.add_argument(
        "--snap_len",
        "-s",
        help="snap len",
        default=0xffff)
    parser.add_argument(
        "--timeout",
        "-t",
        help="timeout",
        default=1000)
    parser.add_argument(
        "--mode",
        "-m",
        help="overwrite,cycle,update",
        default="overwrite")

    args = parser.parse_args()
    return Context(args.out_file, args.redis_key, args.dev_name, args.snap_len,
                   args.timeout,
                   args.store_to_file, args.store_to_redis,
                   args.print_to_screen,
                   args.mode)


def print_mac_addresses(mac_addresses):
    print("mac address, ref count")
    for mac in mac_addresses:
        print("{}, {}".format(mac_to_str(mac["mac"]), mac["refcount"]))


def parse_pkt(ctx, pkt_len, pkt_str, mac_addresses):
    # u_char dest mac[6]
    # u_char src_mac[6]
    # u_char 802_1q_tag[4]
    # u_char ether_type[2]
    ptr = 0
    dst_mac = struct.unpack('6B', pkt_str[ptr:ptr + 6])
    ptr += 6
    src_mac = struct.unpack('6B', pkt_str[ptr:ptr + 6])
    ptr += 6
    ether_type = struct.unpack('!H', pkt_str[ptr:ptr + 2])[0]
    ptr += 2
    len = -1
    if ether_type <= 1500:
        len = ether_type
    elif ether_type == 0x8100:  # 802.1q
        # PCP 3 bits
        # DEI 1 bit
        # VID 12 bits
        vlan_tag = struct.unpack('!H', pkt_str[ptr:ptr + 2])[0]
        ptr += 2
        pcp = vlan_tag & 0b1110000000000000
        dei = vlan_tag & 0b0001000000000000
        vid = vlan_tag & 0b0000111111111111
    # else:
    #     ether_type_str = EtherType[ether_type]
    # print("ether type: {:04X}, dest mac: {}, src mac: {}"
    #       .format(ether_type,
    #               mac_to_str(dst_mac),
    #               mac_to_str(src_mac)))

    src_mac_exists = False
    dst_mac_exists = False
    for mac_addr in mac_addresses:
        if mac_addr['mac'] == src_mac:
            mac_addr['refcount'] += 1
            src_mac_exists = True
        elif mac_addr['mac'] == dst_mac:
            mac_addr['refcount'] += 1
            dst_mac_exists = True
    if src_mac_exists is False:
        mac_addresses.append(dict(mac=src_mac, refcount=1))
    if dst_mac_exists is False:
        mac_addresses.append(dict(mac=dst_mac, refcount=1))

    if src_mac_exists is False or dst_mac_exists is False:
        # TODO: print if enabled
        if ctx.print_to_screen is True:
            print_mac_addresses(mac_addresses)
    # TODO: save to file
    if ctx.store_to_file is True:
        if ctx.mode == "overwrite":
            write_out_file(ctx, mac_addresses)
        elif ctx.mode == "update":
            with open(ctx.out_file, 'w') as fd:
                csvr = csv.DictReader(fd)
                for row in csvr:
                    mac_updated = False
                    for mac in mac_addresses:
                        if mac["mac"] == row["mac"]:
                            mac["refcount"] += 1
                            mac_updated = True
                            break
                    if mac_updated is False:
                        mac_addresses.append(row)
            write_out_file(ctx, mac_addresses)
        elif ctx.mode == "cycle":
            d = datetime.datetime.utcnow()
            s = d.strftime("%d%H%M%S%m%Y")
            out_file_2 = os.path.join(ctx.out_file, ".{}.bak".format(s))
            shutil.copy(ctx.out_file, out_file_2)
            write_out_file(ctx, mac_addresses)

        # TODO: save to redis

    return mac_addresses


def write_out_file(ctx, mac_addresses):
    with open(ctx.out_file, 'w') as of:
        csvw = csv.DictWriter(of, fieldnames=["mac", "refcount"])
        csvw.writeheader()
        for mac in mac_addresses:
            _mac = dict(mac=mac_to_str(mac["mac"]), refcount=mac["refcount"])
            csvw.writerow(_mac)


def run():
    ctx = parse_cmd_line()
    # h_pcap = None
    #dev_name = ctx.dev_name.encode('utf-8')
    #snap_len = ctx.snap_len
    #promisc = ctx.promiscuous
    #timeout = ctx.timeout
    #err_buf = ctypes.create_string_buffer(PCAP_ERR_BUF_SZ)

    # nodes:
    #   pcap input
    #   ethernet parser
    #   output for mac addresses
    #   output for ethernet flows
    # datastructures
    #   packet table -- memached entries
    #   mac address table -- redis
    #   ethernet flow table -- redis
    # datastores
    #   mac 
    # pcap input gets packet from device
    # pcap iput copies packet to packet table
    # pcap input passes packet table packet ref (index of packet in table) to parser
    # parser gets packet ref from pcap input
    # parser parses ethernet headers: mac addresses and ethernet flows
    # parser

    int_name = "Ethernet"
    
    pcap_input_proc = multiprocessing.process(target=pcap_input.run, 
                                              args=(int_name))

    # parsing process

    
    

        #print("pkt str: \"{}\", len: {}".format(pkt_str, pkt_len))
    print_mac_addresses(mac_addresses)

if __name__ == "__main__":
    run()
