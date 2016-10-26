import struct

from net import ethernet, ipv4


class ArpPacket:
    def __init__(self, arp_pkt):
        pkt_ptr = 0
        # raw pkt
        self.raw_arp_pkt = arp_pkt
        # raw pkt len
        self.raw_arp_pkt_len = len(arp_pkt)
        # htype (2B)
        self.htype = (struct.unpack("!H", arp_pkt[pkt_ptr:pkt_ptr + 2]))[0]
        pkt_ptr += 2
        # ptype (2B)
        self.ptype_int = (struct.unpack("!H", arp_pkt[pkt_ptr:pkt_ptr + 2]))[0]
        self.ptype = ethernet.get_ether_type(self.ptype_int)
        pkt_ptr += 2
        # hlen (1B)
        self.hlen = (struct.unpack("B", arp_pkt[pkt_ptr:pkt_ptr + 1]))[0]
        pkt_ptr += 1
        # plen (1B)
        self.plen = (struct.unpack("B", arp_pkt[pkt_ptr:pkt_ptr + 1]))[0]
        pkt_ptr += 1
        # oper (2B)
        self.oper = (struct.unpack("!H", arp_pkt[pkt_ptr:pkt_ptr + 2]))[0]
        pkt_ptr += 2
        # sha (6B)
        self.sha = (struct.unpack("6B", arp_pkt[pkt_ptr:pkt_ptr + 6]))
        self.sha_str = ethernet.mac_to_str(self.sha)
        pkt_ptr += 6
        # spa (4B)
        self.spa = (struct.unpack("4B", arp_pkt[pkt_ptr:pkt_ptr + 4]))
        self.spa_str = ipv4.ip_list_to_str(self.spa)
        pkt_ptr += 4
        # tha (6B)
        self.tha = (struct.unpack("6B", arp_pkt[pkt_ptr:pkt_ptr + 6]))
        self.tha_str = ethernet.mac_to_str(self.tha)
        # tpa (2B)
        self.tpa = (struct.unpack("4B", arp_pkt[pkt_ptr:pkt_ptr + 4]))
        self.tpa_str = ipv4.ip_list_to_str(self.tpa)

    def __repr__(self):
        return "htype: {}, ptype: {}, hlen: {}, plen: {}, oper: {}, " \
               "sha: {}, spa: {}, tha: {}, tpa: {}".format(
            self.htype, self.ptype, self.hlen, self.plen, self.oper,
            self.sha_str, self.spa_str, self.tha_str, self.tpa_str
        )

        # END OF FILE #
