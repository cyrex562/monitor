from enum import Enum

from net import ethernet, ipv4
from net.ethernet import compare_mac_addr


class IPv4MulticastGroup(Enum):
    # address string, mask bits (-1 if none), list of addr bytes, description,
    # reserved flag
    base_address = ["224.0.0.0"], "base address"
    all_hosts = ["224.0.0.1"], "all hosts"
    all_routers = ["224.0.0.2"], "all routers"
    dvmrp = ["224.0.0.4"], "dvmrp"
    ospf_all = ["224.0.0.5"], "osp all routers"
    ospf_dr = ["224.0.0.6"], "ospf all designated routers"
    rip_v2 = ["224.0.0.9"], "rip v2"
    eigrp = ["224.0.0.10"], "eigrp"
    pim_v2 = ["224.0.0.13"], "pim v2"
    vrrp = ["224.0.0.18"], "vrrp"
    isis_ip = ["224.0.0.18", "224.0.0.21"], 32, "isis over ip"
    igmp_3 = ["224.0.0.22"], "igmp v3"
    hsrp_v2_glbp = ["224.0.0.102"], "hsrp v2 / glbp"
    ptp_v2 = ["224.0.0.107"], "ptp v2"
    mdns = ["224.0.0.251"], "mdns"
    llmnr = ["224.0.0.252"], "llmnr"
    teredo_disc = ["224.0.0.253"], "teredo tunneling client discovery"
    ntp_mc = ["224.0.1.1"], "ntp multicast client"
    slp_1_gen = ["224.0.1.22"], "slp v1 gen"
    slp_1_dir_agent = ["224.0.1.35"], "slp v1 directory agent"
    cisco_auto_rp_announce = ["224.0.1.39"], \
                             "cisco multicast router auto-rp-announce"
    cisco_auto_rp_discovery = ["224.0.1.40"], \
                              "cisco multicast router auto-rp-discovery"
    h323_gatekeeper_disc = ["224.0.1.41"], "h.323 gatekeeper discovery"
    ptp_v1 = ["224.0.1.129", "224.0.1.132"], "ptp v1 messages"
    ptp_v2_msg = ["224.0.1.129"], "ptp v2 messages"
    ssdp = ["239.255.255.250"], "ssdp"
    slp_v2 = ["239.255.255.253"], "slp v2"
    local_subnet = ["224.0.0.0", "224.0.0.255"], \
                   "IANA reserved local subnet"
    internetwork_control_block = ["224.0.1.0", "224.0.1.255"], \
                                 "IANA reserved internetwork control block"
    ad_hoc_block_1 = ["224.0.2.0", "224.0.255.255"], "ad hoc block"
    ad_hoc_block_2 = ["224.0.3.0", "224.4.255.255"], "ad hoc block"
    ad_hoc_block_3 = ["233.252.0.0", "233.255.255.255"], "ad hoc block"
    source_specific_multicast = ["232.0.0.0", "232.255.255.255"], \
                                "ad hoc block"
    glop_address = ["233.0.0.0", "233.255.255.255"], "glop addressing"
    unicast_prefix = ["234.0.0.0", "234.255.255.255"], \
                     "unicast prefix based ipv4 multicast address"
    administratively_scoped = ["239.0.0.0", "239.255.255.255"], \
                              "administratively scoped"
    gen_multicast = ["224.0.0.0", "239.255.255.255"], "multicast assignments"


def is_ip_pkt_multicast(ip_pkt):
    """
    an ip packet is multicast if its destination ip address matches a
    registered ip multicast address.
    :param ip_pkt:
    :return:
    """
    dst_ip = ip_pkt.dst_ip
    for ipmcg in IPv4MulticastGroup:
        scope = ipmcg.value[0]
        if len(scope) == 1:
            filter_ip = ipv4.ip_str_to_list(scope[0])
            if ipv4.compare_ip_addr(dst_ip, filter_ip) == 0:
                return True
        elif len(scope) == 2:
            lower_ip = ipv4.ip_str_to_list(scope[0])
            upper_ip = ipv4.ip_str_to_list(scope[1])
            lower_res = ipv4.compare_ip_addr(dst_ip, lower_ip)
            upper_res = ipv4.compare_ip_addr(dst_ip, upper_ip)
            if lower_res >= 0 >= upper_res:
                return True
        elif len(scope) > 2:
            for ip_str in scope:
                if ipv4.compare_ip_addr(
                        dst_ip,
                        ipv4.ip_str_to_list(ip_str)) == 0:
                    return True
    return False


class EthernetMulticastGroup(Enum):
    broadcast = ["ff:ff:ff:ff:ff:ff"], "broadcast"
    cdp_vtp = ["01:00:0c:cc:cc:cc"], "cdp / vtp"
    csstpa = ["01:00:0c:cc:cc:cd"], \
             "cisco shared spanning tree protocol address"
    stp_8021d = ["01:80:C2:00:00:00"], "spanning tree protocol 802.1d"
    lldp = ["01:80:c2:00:00:00", "01:80:c2:00:00:03", "01:80:c2:00:00:0e"], \
           "lldp"
    stp_8021ad = ["01:80:c2:00:00:08"], "stp 802.1ad"
    eth_flow_ctrl_8023x = ["01:80:c2:00:00:01"], \
                          "ethernet flow control pause frame 802.3x"
    ethernet_oam = ["01:80:c2:00:00:02"], "ethernet oam 802.3ah"
    ethernet_cfm = ["01:80:c2:00:00:30", "01:80:c2:00:00:3f"], \
                   "ethernet cfm 802.1ag"
    ipv4_mcast = ["01:00:5e:00:00:00", "01:00:5e:7f:ff:ff"], "ipv4 multicast"
    ipv6_mcast = ["33:33:00:00:00:00", "33:33:ff:ff:ff:ff"], "ipv6 multicast"
    iec_61850_8_1 = ["01:0c:cd:01:00:00", "01:0c:cd:01:01:ff"], \
                    "iec 61850-8-1 GOOSE Type 1/1A"
    gsse = ["01:0c:cd:02:00:00", "01:0c:cd:02:01:ff"], "GSSE IEC 61850 8-1"
    mcast_sample = ["01:0c:cd:04:00:00", "01:0c:cd:04:01:ff"], \
                   "multicast sampled values iec 61850 8-1"
    ptp_v2_eth = ["01:1b:19:00:00:00", "01:80:C2:00:00:0E"], \
                 "ptp v2 over ethernet"


def is_ether_pkt_multicast(ether_pkt):
    """
    an ethernet packet is multicast if its destination mac address matches a
    registered ethernet multicast address

    :param ether_pkt:
    :return:
    """
    for emcg in EthernetMulticastGroup:
        # if the first element of the value tuple is a list with one element,
        # then it's a single address to match. if the tuple contains two
        # elements, then it's a range, if more than two, then it's a set.
        if len(emcg.value[0]) == 1:
            # match single address
            filter_mac = ethernet.mac_str_to_list(emcg.value[0][0])
            if compare_mac_addr(ether_pkt.dest_mac, filter_mac) == 0:
                return True
        elif len(emcg.value[0]) == 2:
            compare_min_result = compare_mac_addr(
                ether_pkt.dest_mac,
                ethernet.mac_str_to_list(emcg.value[0][0]))
            compare_max_result = compare_mac_addr(
                ether_pkt.dest_mac,
                ethernet.mac_str_to_list(emcg.value[0][1]))
            if compare_min_result >= 0 >= compare_max_result:
                return True
        elif len(emcg.value[0]) > 2:
            for mc_mac_addr in emcg.value[0]:
                if compare_mac_addr(
                        ether_pkt.dest_mac,
                        ethernet.mac_str_to_list(mc_mac_addr)) == 0:
                    return True
    return False

# END OF FILE #
