from pathlib import Path

from scapy.all import rdpcap

from analyze_packet import analyze
from parse_packet import parse_from_l2

_PCAP_FILE_EXT = ('.pcap', '.pcapng')
_PCAPS_FOLDER = Path('<add_the_path_here>').resolve()


if __name__ == '__main__':
    for pcap_file in (f for f in _PCAPS_FOLDER.iterdir() if f.suffix in _PCAP_FILE_EXT):
        print(f'Parsing {pcap_file}')
        for packet in rdpcap(str(pcap_file)):
            ip_source, ip_destination = parse_from_l2(bytes(packet),
                                                      filter_internal_communication=True,
                                                      internal_as_source=True)
            if ip_source is not None and ip_destination is not None:
                if ip_source.is_private() and not ip_destination.is_private():  # Patch for PCAP files
                    analyze(ip_source, ip_destination, packet.time)
