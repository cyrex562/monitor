import struct
from enum import Enum


class EtherType(Enum):
    IPv4 = 0x0800
    ARP = 0x0806
    WoL = 0x0842
    IETF_TRILL = 0x22F3
    DECnet_Phase_4 = 0x6003
    RARP = 0x8035
    AppleTalk_EtherTalk = 0x809B
    AppleTalk_ARP = 0x80F3
    VLAN_8021Q_SPB = 0x8100
    IPX = 0x8137
    QNX_Qnet = 0x8204
    IPv6 = 0x86DD
    Ethernet_Flow_Ctrl = 0x8808
    CobraNet = 0x8819
    MPLS_Unicast = 0x8847
    MPLS_Multicast = 0x8848
    PPPoE_Discovery = 0x8863
    PPPoE_Session = 0x8864
    Jumbo_Frames = 0x8870
    EAP_LAN_8021X = 0x888E
    PROFINET = 0x8892
    Hyper_SCSI = 0x889A
    ATA_o_Eth = 0x88A2
    EtherCAT = 0x88A4
    Provider_Bridging = 0x88A8
    LLDP = 0x88CC
    SERCOS_3 = 0x88CD
    HomePlug_AV_MME = 0x88E1
    Media_Redundancy = 0x88E3
    MAC_Security = 0x88E5
    Provider_Backbone_Bridges = 0x88E7
    Precision_Time_protocol = 0x88F7
    Parallel_Redundancy_Protocol = 0x88FB
    IEEE_8021AG = 0x8902
    fcoe = 0x8906
    RDMA_o_CE = 0x8915
    TTEthernet = 0x891D
    HSR = 0x892F
    EthernetConfigurationTestingProto = 0x9000
    unknown = 1535,
    invalid = 1534


def mac_to_str(mac_addr_bytes):
    return "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
        mac_addr_bytes[0], mac_addr_bytes[1], mac_addr_bytes[2],
        mac_addr_bytes[3], mac_addr_bytes[4], mac_addr_bytes[5])


def mac_str_to_list(mac_addr_str):
    if mac_addr_str is None:
        raise ValueError("mac_addr_str canno be None")

    a = mac_addr_str.split(":")
    if len(a) != 6:
        raise ValueError(
            "invalid mac address string: \"{}\"".format(mac_addr_str))

    c = []
    for b in a:
        c.append(int("0x" + b, 16))
    return c


def compare_mac_addr(mac_a, mac_b):
    """
    compare two mac addresses represented by lists of bytes
    :param mac_a:
    :param mac_b:
    :return: 0 if equal, -1 if a < b, 1 if a > b
    """
    _map = []
    for i in range(6):
        if mac_a[i] < mac_b[i]:
            _map.append(-1)
        elif mac_a[i] == mac_b[i]:
            _map.append(0)
        else:
            _map.append(1)
    if _map == [0, 0, 0, 0, 0, 0]:
        return 0
    elif _map[0] == -1 or \
                    _map[:2] == [0, -1] or \
                    _map[:3] == [0, 0, -1] or \
                    _map[:4] == [0, 0, 0, -1] or \
                    _map[:5] == [0, 0, 0, 0, -1] or \
                    _map == [0, 0, 0, 0, 0, -1]:
        return -1
    elif _map[0] == 1 or \
                    _map[:2] == [0, 1] or \
                    _map[:3] == [0, 0, 1] or \
                    _map[:4] == [0, 0, 0, 1] or \
                    _map[:5] == [0, 0, 0, 0, 1] or \
                    _map == [0, 0, 0, 0, 0, 1]:
        return 1
    raise ValueError("invalid comparison result")


def get_ether_type(ether_type_int):
    for etherType in EtherType:
        if etherType.value == ether_type_int:
            return etherType
    return EtherType.unknown


class EthernetPacket(object):
    def __init__(self, pkt_data, pkt_len):
        self.eth_pkt_len = pkt_len
        pkt_ptr = 0
        self.dest_mac = list(struct.unpack('6B', pkt_data[pkt_ptr:pkt_ptr + 6]))
        pkt_ptr += 6
        self.src_mac = list(struct.unpack('6B', pkt_data[pkt_ptr:pkt_ptr + 6]))
        pkt_ptr += 6
        self.ether_type_int = \
            struct.unpack('!H', pkt_data[pkt_ptr:pkt_ptr + 2])[0]
        if self.ether_type_int >= 1536:
            self.ether_type = get_ether_type(self.ether_type_int)
        elif 1500 < self.ether_type_int < 1536:
            print("invalid ethertype: {:4x}".format(self.ether_type_int))
            self.ether_type = EtherType.invalid
        else:
            print("EtherType <= 1500: {}".format(self.ether_type_int))
            self.ether_type = EtherType.invalid
        pkt_ptr += 2
        self.payload = pkt_data[pkt_ptr:]
        self.payload_len = pkt_len - pkt_ptr
        self.raw_eth_pkt = pkt_data
        self.raw_eth_pkt_len = pkt_len

    def __repr__(self):
        return "dest_mac: {}, src_mac: {}, ether_type: {}({:04x}), " \
               "payload_len: {}, payload: {}".format(
            mac_to_str(self.dest_mac), mac_to_str(self.src_mac),
            self.ether_type, self.ether_type_int, self.payload_len,
            self.payload[:10])
