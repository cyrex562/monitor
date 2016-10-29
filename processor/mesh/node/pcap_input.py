import sys
import ctypes
import monitor.platform.net.pcap as pcap
import argparse

PROMISC_MODE = 1

def parse_cmd_line():
    # TODO: parse command line
    # interface name
    # snap len
    # timeout
    # place to store traffic
    parser = argparse.ArgumentParser(description="create a pcap-based input")
    parser.add_argument('--name', 
                        '-n', 
                        help="interface name")
    parser.add_argument('--snap_len', 
                        '-s', 
                        help="snap len", 
                        default=0xffff)
    parser.add_argument('--timeout',
                        '-t',
                        help="timeout in milliseconds",
                        default=1000)
    parser.add_argument('--output',
                        '-o',
                        help="url location to send captured packets")
    args = parser.parse_args()
    return args.name, args.snap_len, args.timeout, args.output
    

def parse_output_url(output_url):
    # TODO: implement output url parsing function
    pass    

def write_to_output(output):
    # TODO: implement output writing function
    pass

def on_packet_captured(pkt_ts, pk_str, pkt_len, output):
    """
    packet capture handler. writes to specified output
    """
    write_to_output(pkt_ts, pk_str, pkt_len, output)



def run(interface_name, snap_len=0xffff, timeout=1000, output_url="stdout"):
    """

    """
    output = parse_output_url(output_url)

    try:
        h_pcap = pcap.open_pcap(interface_name, snap_len, PROMISC_MODE, timeout)
        if h_pcap is None:
            sys.stderr("failed to open deivce for packet capture")
            sys.exit(-1)
        while True:
            pkt_ts, pkt_len, pkt_str = pcap.get_next_pkt(h_pcap)
            if pkt_len <= 0:
                sys.stdout("no packet retrieved")
            else:
                on_packet_captured(pkt_ts, pkt_str, pkt_len, output)
    except pcap.PcapError as pe:
        sys.stderr("pcap error occurred, {}".format(pe))
        sys.exit(-1)
    

if __name__ == "__main__":
    params = parse_cmd_line()
    run()