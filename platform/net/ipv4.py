import struct
from enum import Enum


class IPv4Proto(Enum):
    # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    HOPOPT = 0, "IPv6 Hop-by-Hop Option", "HOPOPT"
    ICMP = 1, "Internet Control Message Protocol", "ICMP"
    IGMP = 2, "Internet Group Management Protocol", "IGMP"
    GGP = 3, "Gateway-to-Gateway Protocol", "GGP"
    IPinIP = 4, "IP in IP", "IPinIP"
    ST = 5, "Internet Stream Protocol"
    TCP = 6, "Transmission Control Protocol", "TCP"
    CBT = 7, "Core-based trees",
    EGP = 8, "Exterior Gateway Protocol", "EGP"
    IGP = 9, "Interior Gateway Protocol", "IGP"
    BBN_RCC_MON = 10, "BBN RCC Monitoring", "BBN-RCC-MON"
    NVP_2 = 11, "Network Voice Protocol", "NVP-II"
    PUP = 12, "Xerox PUP", "PUP"
    ARGUS = 13, "ARGUS", "ARGUS"
    EMCON = 14, "EMCON", "EMCON"
    XNET = 15, "Cross Net Debugger", "XNET"
    CHAOS = 16, "Chaos", "CHAOS"
    UDP = 17, "User Datagram Protocol", "UDP"
    MUX = 18, "Multiplexing", "MUX"
    DCN_MEAS = 19, "DCN Measurement Subsystems", "DCN-MEAS"
    HMP = 20, "Host Monitoring Protocol", "HMP"
    PRM = 21, "Packet Radio Measurement", "PRM"
    XNS_IDP = 22, "XEROX NS IDP", "XNS-IDP"
    TRUNK_1 = 23, "Trunk-1", "TRUNK-1"
    TRUNK_2 = 24, "Trunk-2", "TRUNK-2"
    LEAF_1 = 25, "Leaf-1", "LEAF-1"
    LEAF_2 = 26, "Leaf-2", "LEAF-2"
    RDP = 27, "Reliable Datagram Protocol", "RDP"
    IRTP = 28, "Internet Reliable Transaction Protocol", "IRTP"
    ISO_TP4 = 29, "ISO Transport Protocol Class 4", "ISO-TP4"
    NETBLT = 30, "Bulk Data Transfer Protocol", "NETBLT"
    MFE_NSP = 31, "MFE Network Services Protocol", "MFE-NSP"
    MERIT_INP = 32, "MERIT Internodal Protocol", "MERIT-INP"
    DCCP = 33, "Datagram Congestion Control Protocol", "DCCP"
    _3PC = 34, "Third Party Connect Protocol", "3PC"
    IDPR = 35, "Inter-Domain Policy Routing Protocol", "IDPR"
    XTP = 36, "Xpress Transport Protocol", "XTP"
    DDP = 37, "Datagram Delivery Protocol", "DDP"
    IDPR_CMTP = 38, "IDPR Control Message Transport Protocol", "IDPR-CMTP"
    TP = 39, "TP++ Transport Protocol", "TP++"
    IL = 40, "IL Transport Protocol", "IL"
    ENCAP = 41, "IPv6 encapsulation", "ENCAP"
    SDRP = 42, "Source Demand Routing Protocol", "SDRP"
    IPv6_Route = 43, "Routing Header for IPv6", "IPv6-Route"
    IPv6_Frag = 44, "Fragment Header for IPv6", "IPv6-Frag"
    IDRP = 45, "Inter-Domain Routing Protocol", "IDRP"
    RSVP = 46, "Resource Reservation Protocol", "RSVP"
    GRE = 47, "Generic Routing Encapsulation", "GRE"
    MHRP = 48, "Mobile Host Routing Protocol", "MHRP"
    BNA = 49, "BNA", "BNA"
    ESP = 50, "Encapsulating Security Payload", "ESP"
    AH = 51, "Authentication Header", "AH"
    I_NLSP = 52, "Integrated Net Layer Security Protocol", "I-NLSP"
    SWIPE = 53, "SwIPe", "SWIPE"
    NARP = 54, "NMBA Address Resolution Protocol", "NARP"
    MOBILE = 55, "IP Mobility", "MOBILE"
    TLSP = 56, "Transport Layer Security Protocol", "TLSP"
    SKIP = 57, "Simple Key Management for Internet Protocol"
    IPV6_ICMP = 58, "ICMP fo IPv6", "IPv6-ICMP", "IPv6-ICMP"
    IPV6_NONXT = 59, "No Next Header for IPv6", "IPv6-NoNxt"
    IPV6_OPTS = 60, "Destination Options for IPv6"
    AHIP = 61, "Any host internal protocol", "AHIP"
    CFTP = 62, "CFTP", "CFTP"
    ALN = 63, "Any local network", "ALP"
    SAT_EXPAK = 64, "SATNET and Backroom EXPAK", "SAT-EXPAK"
    KRYPTOLAN = 65, "Kryptolan", "KRYPTOLAN"
    RVD = 66, "MIT Remote Virtual Disk Protocol", "RVD"
    IPPC = 67, "Internet Pluribus Packet Core", "IPPC"
    ADFS = 68, "Any distributed file system", "ADFS"
    SAT_MON = 69, "SATNET Monitoring", "SAT-MON"
    VISA = 70, "VISA Protocol", "VISA"
    IPCU = 71, "Internet Packet Core Utility", "IPCU"
    CPNX = 72, "Computer Protocol Network Executive", "CPNX"
    CPHB = 73, "Computer Protocol Heart Beat", "CPHB"
    WSN = 74, "Wang Span Network", "WSN"
    PVP = 75, "Packet Video Protocol", "PVP"
    BR_SAT_MON = 76, "Backroom SATNET Monitoring", 'BR-SAT-MON'
    SUN_ND = 77, "SUN ND PROTOCOL-Temporary", "SUN-ND"
    WB_MON = 78, "WIDEBAND Monitoring", "WB-MON"
    WB_EXPAK = 79, "WIDEBAND EXPAK", "WB-EXPAK"
    ISO_IP = 80, "International Organzation for Standardization Internet " \
                 "Protocol", "ISO-IP"
    VMTP = 81, "Versatile Message Transaction Protocol", "VMTP"
    SECURE_VMTP = 82, "Secure Versatile Message Transaction Protocol", \
                  "SECURE-VMTP"
    VINES = 83, "VINES", "VINES"
    TTP = 84, "TTP", "TTP"
    IPTM = 85, "Internet Protocol Traffic Manager", "IPTM"
    NSFNET_IGP = 86, "NSFNET-IGP", "NSFNET-IGP"
    DGP = 87, "TCF", "TCP"
    EIGRP = 88, "EIGRP", "EIGRP"
    OSPF = 89, "Open Shortest Path First", "OSPF"
    SPRITE_RPC = 90, "Sprite RPC Protocol", "Sprite-RPC"
    LARP = 91, "Locus Address Resolution Protocol"
    MTP = 92, "Multicast Transport Protocol"
    AX_25 = 93, "AX.25", "AX.25"
    IPIP = 94, "IP-within-IP Encapsulation Protocol", "IPIP"
    MICP = 95, "Mobile Internetworking Control Protocol", "MICP"
    SCC_SP = 96, "Semaphore Communications Security Protocol", "SCC_SP"
    ETHERIP = 97, "Ethernet-within-IP Encapsulation", "ETHERIP"
    ENCAP_1241 = 98, "Encapsulation Header", "ENCAP"
    PRIVATE_CRYPT = 99, "Any private encryption scheme", ""
    GMTP = 100, "GMTP", "GMTP"
    IFMP = 101, "Ipsilon Flow Management Protocol", "IFMP"
    PNNI = 102, "PNNI over IP", "PNNI"
    PIM = 103, "Protocol Independent Multicast", "PIM"
    ARIS = 104, "IBM's ARIS Protocol", "ARIS"
    SCPS = 105, "Space Communications Protocol Standards", "SCPS"
    QNX = 106, "QNX", "QNX"
    AN = 107, "Active Networks", "A/N"
    IPCOMP = 108, "IP Payload Compression Protocol", "IPComp"
    SNP = 109, "Sitara Networks Protocol", "SNP"
    COMPAQ_PEER = 110, "Compaq Peer Protocol", "Compaq-Peer"
    IPX_IN_IP = 111, "IPX in IP", "IPX-in-IP"
    VRRP = 112, "Virtual Router Redundancy Protocol, Common Address Redundancy Protocol", "VRRP"
    PGM = 113, "PGM Reliable Transport Protocol", "PGM"
    ZHP = 114, "Any 0-hop protocol", ""
    L2TP = 115, "Layer Two Tunneling Protocol v3", "L2TP"
    DDX = 116, "D-II Data Exchange", "DDX"
    IATP = 117, "Interactive Agent Transfer Protocol", "IATP"
    STP = 118, "Schedule Transfer Protocol", "STP"
    SRP = 119, "SpectraLink Radio Protocol", "SRP"
    UTI = 120, "Universal Transport Interface Protocol", "UTI"
    SMP = 121, "Simple Message Protocol", "SMP"
    SM = 122, "Simple Multicast Protocol", "SM"
    PTP = 123, "Performance Transparency Protocol", "PTP"
    ISIS_IPV4 = 124, "IS-IS over IPv4", "IS-IS over IPv4"
    FIRE = 125, "Flexible Intra-AS Routing Environment", "FIRE"
    CRTP = 126, "Combat Radio Transport Protocol", "CRTP"
    CRUDP = 127, "Combat Radio User Datagram", "CRUDP"
    SSCOPMCE = 128, "Service-Specific Connection-Oriented Protocol in a " \
                    "Multilink and Connectionless Environment", "SSCOPMCE"
    IPLT = 129, "IPLT", "IPLT"
    SPS = 130, "Secure Packet Shield", "SPS"
    PIPE = 131, "Private IP Encapsulation within IP", "PIPE"
    SCTP = 132, "Stream Control Transmission Protocol", "SCTP"
    FC = 133, "Fibre Channel", "FC"
    RSVP_E2E_IGNORE = 134, "RSVP End-to-End Ignore", "RSVP-E2E-IGNORE"
    MOB_HDR = 135, "Mobility Header for IPv6", "Mobility Header"
    UDP_LITE = 136, "Lightweight UDP", "UDPLite"
    MPLS_IP = 137, "MPLS in IP", "MPLS-in-IP"
    MANET = 138, "MANET Protocols", "MANET"
    HIP = 139, "Host Identity Protocol", "HIP"
    SHIM6 = 140, "Site Multihoming by IPv6 Intermediation", "Shim6"
    WESP = 141, "Wrapped Encapsulating Security Payload", "WESP"
    ROHC = 142, "Robust Header Compression", "ROHC"
    # 143-252 unassigned
    # 253 - 254 used for expirementation and testing
    # 255 - Reserved
    UNK = -1, "Unknown", "UNK"


def ip_int_to_str(ip_int):
    return "{}.{}.{}.{}".format(ip_int >> 24, (ip_int & 0xFF0000) >> 16,
                                (ip_int & 0xFF00) >> 8, ip_int & 0xFF)


def ip_str_to_list(ip_str):
    if ip_str is None:
        raise ValueError("ip_str was none")
    a = ip_str.split(".")
    if len(a) != 4:
        raise ValueError("invalid ip str: {}".format(ip_str))
    b = []
    for _a in a:
        b.append(int(_a))
    return b


def ip_list_to_str(ip_list):
    return "{}.{}.{}.{}".format(ip_list[0], ip_list[1], ip_list[2], ip_list[3])


def compare_ip_addr(ip_a, ip_b):
    map_a = []
    for i in range(4):
        if ip_a[i] == ip_b[i]:
            map_a.append(0)
        elif ip_a[i] < ip_b[i]:
            map_a.append(-1)
        else:
            map_a.append(1)
    if map_a == [0, 0, 0, 0]:
        return 0
    elif map_a[0] == -1 or \
                    map_a[:2] == [0, -1] or \
                    map_a[:3] == [0, 0, -1] or \
                    map_a == [0, 0, 0, -1]:
        return -1
    elif map_a[0] == 1 or \
                    map_a[:2] == [0, 1] or \
                    map_a[:3] == [0, 0, 1] or \
                    map_a == [0, 0, 0, 1]:
        return 1
    raise ValueError("invalid comparison result: map: {}".format(map_a))


class Ipv4Packet(object):
    def __init__(self, ip_pkt, ip_pkt_len):
        pkt_ptr = 0

        self.version_ihl = struct.unpack('B', ip_pkt[pkt_ptr:pkt_ptr + 1])[0]

        # version
        self.version = self.version_ihl >> 4

        # ihl
        self.ihl = self.version_ihl & 0x0f
        pkt_ptr += 1

        self.dscp_ecn = struct.unpack('B', ip_pkt[pkt_ptr:pkt_ptr + 1])[0]
        pkt_ptr += 1

        # dscp
        self.dscp = self.dscp_ecn & 0b11111100

        # ecn
        self.ecn = self.dscp_ecn & 0b00000011

        # tot len
        self.tot_len = struct.unpack('!H', ip_pkt[pkt_ptr:pkt_ptr + 2])[0]
        pkt_ptr += 2

        # ip id
        self.ip_id = struct.unpack('!H', ip_pkt[pkt_ptr:pkt_ptr + 2])[0]
        pkt_ptr += 2

        self.flags_frag_off = struct.unpack('!H', ip_pkt[pkt_ptr:pkt_ptr + 2])[
            0]
        pkt_ptr += 2

        # flags
        self.flags = (self.flags_frag_off & 0xe000) >> 13
        # frag off
        self.frag_off = self.flags_frag_off & 0x1fff

        # ttl
        self.ttl = struct.unpack('B', ip_pkt[pkt_ptr:pkt_ptr + 1])[0]
        pkt_ptr += 1

        # proto
        self.proto_num = struct.unpack('B', ip_pkt[pkt_ptr:pkt_ptr + 1])[0]
        self.proto = self.parse_proto()
        pkt_ptr += 1

        # header checksum
        self.hdr_csum = struct.unpack('!H', ip_pkt[pkt_ptr:pkt_ptr + 2])[0]
        pkt_ptr += 2

        # src ip address
        self.src_ip = struct.unpack('4B', ip_pkt[pkt_ptr:pkt_ptr + 4])
        self.src_ip_str = ip_list_to_str(self.src_ip)
        pkt_ptr += 4

        # dst ip address
        self.dst_ip = struct.unpack('4B', ip_pkt[pkt_ptr:pkt_ptr + 4])
        self.dst_ip_str = ip_list_to_str(self.dst_ip)
        pkt_ptr += 4

        # ip options
        self.ip_options = 0
        self.payload = ip_pkt[pkt_ptr:]
        self.payload_len = ip_pkt_len - pkt_ptr

        self.raw_ip_pkt = ip_pkt
        self.raw_ip_pkt_len = ip_pkt_len

    def parse_proto(self):
        for proto in IPv4Proto:
            if self.proto_num == proto.value[0]:
                return proto
        return IPv4Proto.UNK

    def __repr__(self):
        return "version: {}, ihl: {}, dscp:{}, ecn:{}, tot_len: {}, " \
               "ip_id: {:x}, flags: {:03b}, frag_off: {}, ttl: {}, proto: {}, " \
               "hdr_csum: {}, src_ip: {}, dst_ip: {}, ip_options: {}, " \
               "payload_len: {}, payload: {}".format(
            self.version, self.ihl, self.dscp, self.ecn, self.tot_len,
            self.ip_id, self.flags, self.frag_off, self.ttl, self.proto,
            self.hdr_csum, self.src_ip_str, self.dst_ip_str, self.ip_options,
            self.payload_len, self.payload[0:10])

# END OF FILE
