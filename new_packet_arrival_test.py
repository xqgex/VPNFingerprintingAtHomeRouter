from scapy.all import rdpcap

from analyze_packet import analyze
from parse_packet import parse

_INPUT_FILE = 'test_pcap_file.pcap'


if __name__ == '__main__':
    pcap = rdpcap(_INPUT_FILE)
    for packet in pcap:
        ip_source, ip_destination = parse(bytes(packet),
                                          filter_internal_communication=True,
                                          internal_as_source=True)
        if ip_source is not None and ip_destination is not None:
            analyze(ip_source, ip_destination, packet.time)
