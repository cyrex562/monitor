import struct


class UDPPacket(object):
    def __init__(self, udp_pkt, udp_pkt_len):
        pkt_ptr = 0
        # src port
        self.src_port = struct.unpack("!H", udp_pkt[pkt_ptr:pkt_ptr + 2])
        pkt_ptr += 2
        # dst port
        self.dst_port = struct.unpack("!H", udp_pkt[pkt_ptr:pkt_ptr + 2])
        pkt_ptr += 2
        # length
        self.length = struct.unpack("!H", udp_pkt[pkt_ptr:pkt_ptr + 2])
        pkt_ptr += 2
        # checksum
        self.checksum = struct.unpack("!H", udp_pkt[pkt_ptr:pkt_ptr + 2])
        pkt_ptr += 2
        # packet len
        self.packet_len = udp_pkt_len
        # payload
        self.payload = udp_pkt[pkt_ptr:]
        # payload len
        self.payload_len = udp_pkt_len - pkt_ptr
        # raw packet
        self.raw_udp_pkt = udp_pkt
        # raw packet length
        self.raw_udp_pkt_len = udp_pkt_len

    def __repr__(self):
        return "src_port: {}, dst_port: {}, len: {}, checksum: {:04x}, " \
               "payload: \"{}\"".format(self.src_port, self.dst_port,
                                        self.length, self.checksum,
                                        self.payload[:10])

# END OF FILE
