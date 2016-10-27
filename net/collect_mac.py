import argparse
import ctypes
import os
from _ctypes import POINTER

import sys

import struct

from net.ethernet import mac_to_str, EtherType
from net.pcap import pcap_open_live, PcapPktHdr, pcap_next_ex, c_ubyte

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
                 print_to_screen=False):
        self.store_to_file = store_to_file
        self.store_to_redis = store_to_redis
        self.print_to_screen = print_to_screen
        self.out_file = out_file
        self.redis_key = redis_key
        self.dev_name = dev_name
        self.snap_len = snap_len
        self.promiscuous = True
        self.timeout = timeout


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
        default="titan:mac_addresses"
    )
    parser.add_argument(
        "--dev_name",
        "-d",
        help="device name",
        default=DEF_DEV_NAME)
    parser.add_argument(
        "--snap_len",
        "-s",
        help="snap len",
        default=0xffff
    )
    parser.add_argument(
        "--timeout",
        "-t",
        help="timeout",
        default=1000
    )
    args = parser.parse_args()
    return Context(args.out_file, args.redis_key, args.dev_name, args.snap_len,
                   args.timeout,
                   args.store_to_file, args.store_to_redis,
                   args.print_to_screen,
                   )


def print_mac_addresses(mac_addresses):
    print("mac address, ref count")
    for mac in mac_addresses:
        print("{}, {}".format(mac_to_str(mac["mac"]), mac["refcount"]))


def parse_pkt(pkt_len, pkt_str, mac_addresses):
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
        print_mac_addresses(mac_addresses)
        # TODO: save to redis
        # TODO: save to file

    return mac_addresses


def run():
    ctx = parse_cmd_line()
    # h_pcap = None
    dev_name = ctx.dev_name.encode('utf-8')
    snap_len = ctx.snap_len
    promisc = ctx.promiscuous
    timeout = ctx.timeout
    err_buf = ctypes.create_string_buffer(PCAP_ERR_BUF_SZ)

    h_pcap = pcap_open_live(dev_name, snap_len, promisc, timeout, err_buf)
    pcap_hdr = POINTER(PcapPktHdr)()
    pcap_data = POINTER(c_ubyte)()

    # FIXME: this loop should have an upper bound
    mac_addresses = []
    while True:
        result = pcap_next_ex(h_pcap,
                              pcap_hdr,
                              pcap_data)
        pkt_len = -1
        pkt_str = b""
        if result == 1:
            pkt_len = pcap_hdr.contents.len
            pkt_str = ctypes.string_at(pcap_data, pkt_len)
            mac_addresses = parse_pkt(pkt_len, pkt_str, mac_addresses)
        elif result == 0:
            print("timeout occurred")
        elif result == -1:
            print("error occurred getting packet: {}".format(err_buf))
            sys.exit()
        elif result == -2:
            print("EOF")
            break

        #print("pkt str: \"{}\", len: {}".format(pkt_str, pkt_len))
    print_mac_addresses(mac_addresses)

if __name__ == "__main__":
    run()
