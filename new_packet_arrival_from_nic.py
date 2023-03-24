from netfilterqueue import NetfilterQueue, Packet

from analyze_packet import analyze
from parse_packet import parse_from_l3

_ETHERTYPE_IPV4 = 0x0800
_PACKET_LENGTH_TO_STORE_BYTES = 20  # Enough for the IP source and destination
_QUEUE_LENGTH = 2048
_QUEUE_NUMBER = 1


def _packet_arrival_callback(packet: Packet) -> None:
    if packet.hw_protocol == _ETHERTYPE_IPV4:
        ip_source, ip_destination = parse_from_l3(packet.get_payload(),
                                                  filter_internal_communication=True,
                                                  internal_as_source=True)
        if ip_source is not None and ip_destination is not None:
            analyze(ip_source, ip_destination, packet.get_timestamp())  # XXX
    packet.accept()


def register_netfilter_queue() -> None:
    nfqueue = NetfilterQueue()
    nfqueue.bind(
        queue_num=_QUEUE_NUMBER,
        user_callback=_packet_arrival_callback,
        max_len=_QUEUE_LENGTH,
        range=_PACKET_LENGTH_TO_STORE_BYTES)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    nfqueue.unbind()


if __name__ == '__main__':
    register_netfilter_queue()
