from enum import Enum
from typing import NamedTuple, Optional, Tuple, Union

_ENDIANNESS = 'big'


class _PacketField(NamedTuple):
    start_index: int
    length: int

    def parse_raw(self, raw: bytes) -> bytes:
        """ Parse the field from raw bytes. """
        return raw[self.start_index:self.start_index + self.length]


class _EtherType(Enum):
    AARP = 0x80F3  # AppleTalk Address Resolution Protocol
    AOE = 0x88A2  # ATA over Ethernet
    ARP = 0x0806  # Address Resolution Protocol
    AVTP = 0x22F0  # Audio Video Transport Protocol
    CFM = 0x8902  # IEEE 802.1ag Connectivity Fault Management Protocol
    EAPOL = 0x888E  # IEEE 802.1X EAP over LAN
    ECTP = 0x9000  # Ethernet Configuration Testing Protocol
    EFP = 0x8808  # Ethernet flow control
    ETHERCAT = 0x88A4  # EtherCAT Protocol
    ETHERTALK = 0x809B  # AppleTalk Ethertalk
    FCOE = 0x8906  # Fibre Channel over Ethernet
    FCOE_INIT = 0x8914  # Fibre Channel over Ethernet Initialization
    GOOSE = 0x88B8  # Generic Object Oriented Substation event
    GSE = 0x88B9  # Generic Substation Events Management Services
    HOMEPLUG = 0x887B  # HomePlug
    HOMEPLUG_GREEN = 0x88E1  # HomePlug Green PHY
    HSR = 0x892F  # High-availability Seamless Redundancy
    HYPERSCSI = 0x889A  # SCSI over Ethernet
    IEEE_1905 = 0x893a  # 1905.1 IEEE Protocol
    IETF_TRILL = 0x22F3  # IETF TRILL Protocol
    IPV4 = 0x0800  # Internet Protocol version 4
    IPV6 = 0x86DD  # Internet Protocol Version 6
    IPX = 0x8137  # Internetwork Packet Exchange
    LACP = 0x8809  # Link Aggregation Control Protocol
    LAT = 0x6004  # Local Area Transport
    LLDP = 0x88CC  # Link Layer Discovery Protocol
    MACSEC = 0x88E5  # IEEE 802.1AE MAC security
    MOP_RC = 0x6002  # Maintenance Operation Protocol
    MPLS_MULTICAST = 0x8848  # MPLS multicast
    MPLS_UNICAST = 0x8847  # MPLS unicast
    MRP = 0x88E3  # Media Redundancy Protocol
    NC_SI = 0x88F8  # network controller sideband interface
    PBB = 0x88E7  # IEEE 802.1ah Provider Backbone Bridges
    POWERLINK = 0x88AB  # Ethernet Powerlink
    PPPOE_DESCOVERY = 0x8863  # PPPoE Discovery Stage
    PPPOE_SESSION = 0x8864  # PPPoE Session Stage
    PROFINET = 0x8892  # PROFINET Protocol
    PRP = 0x88FB  # Parallel Redundancy Protocol
    PTP = 0x88F7  # IEEE 802.3 Precision Time Protocol
    QNX_QNET = 0x8204  # QNX Qnet
    RARP = 0x8035  # Reverse Address Resolution Protocol
    ROCE = 0x8915  # RDMA over Converged Ethernet
    ROMON = 0x88BF  # MikroTik RoMON
    SERCOS = 0x88CD  # SERCOS III
    SLPP = 0x8102  # Simple Loop Prevention Protocol
    SRP = 0x22EA  # Stream Reservation Protocol
    S_TAG = 0x88A8  # Service VLAN tag identifier
    SV = 0x88BA  # Sampled Value Transmission
    TSN = 0xF1C1  # IEEE 802.1CB Redundancy Tag
    TTE = 0x891D  # TTEthernet Protocol Control Frame
    VLACP = 0x8103  # Virtual Link Aggregation Control Protocol
    VLAN = 0x8100  # VLAN-tagged frame
    WOL = 0x0842  # Wake-on-LAN

    @classmethod
    def from_bytes(cls, raw: bytes, field: _PacketField) -> Optional['_EtherType']:
        """ Return an instance of the class based on the given field. """
        try:
            return cls(int.from_bytes(field.parse_raw(raw), byteorder=_ENDIANNESS))
        except ValueError:
            return None


class IPv4(int):

    def __str__(self) -> str:
        """
        >>> str(IPv4(134744072))
        '8.8.8.8'
        >>> str(IPv4(167772160))
        '10.0.0.0'
        """
        return '.'.join([str((self >> (i << 3)) & 0xff) for i in range(4)][::-1])

    def is_private(self) -> bool:
        """
        >>> IPv4.from_string('8.8.8.8').is_private()
        False
        >>> IPv4.from_string('127.222.222.222').is_private()
        True
        >>> IPv4.from_string('10.0.0.0').is_private()
        True
        """
        for range_start, range_end in IPv4_PRIVATE_RANGES:
            if range_start <= self <= range_end:
                return True
        return False

    @classmethod
    def from_bytes(cls, raw: bytes, field: _PacketField) -> 'IPv4':
        """
        >>> mock_field = _PacketField(start_index=1, length=2)
        >>> hex(IPv4.from_bytes(b'\\x01\\x23\\x45\\x67\\x89', mock_field))
        '0x2345'
        """
        return cls(int.from_bytes(field.parse_raw(raw), byteorder=_ENDIANNESS))

    @classmethod
    def from_string(cls, string: str) -> 'IPv4':
        """
        >>> IPv4.from_string('0.0.0.1')
        1
        >>> IPv4.from_string('10.0.0.1')
        167772161
        >>> IPv4.from_string('255.255.255.255')
        4294967295
        """
        octets = string.split('.', 4)
        return cls(  (int(octets[0]) << 24) \
                   + (int(octets[1]) << 16) \
                   + (int(octets[2]) << 8) \
                   + int(octets[3]))


def parse_from_l2(
        raw: bytes,
        filter_internal_communication: bool=True,
        internal_as_source: bool=True,
        ) -> Union[Tuple[IPv4, IPv4], Tuple[None, None]]:
    """ A Python function that receive a raw L2 packet and returns the packet source IP and destination IP.

    :param bytes raw: A raw packet.
    :param bool filter_internal_communication: When the field is `True`, the function will return `None` if both source
                                               IP and the destination IP are private.
    :param bool internal_as_source: When the field is `True`, the returned tuple will always have the internal IP
                                    address as the source (flip the values for incoming packets).
    :return: The extracted source and destination IPv4 addresses.
    :rtype: Union[Tuple[IPv4, IPv4], Tuple[None, None]]
    """
    l3_payload_start = -1
    for ethertype_option in _ETHERTYPE_OPTIONS:
        ethertype = _EtherType.from_bytes(raw, ethertype_option)
        if ethertype != _EtherType.VLAN and ethertype != _EtherType.S_TAG:
            l3_payload_start = ethertype_option.start_index + ethertype_option.length
            break
    if ethertype == _EtherType.IPV4:
        return parse_from_l3(raw[l3_payload_start:], filter_internal_communication, internal_as_source)
    return None, None


def parse_from_l3(
        raw: bytes,
        filter_internal_communication: bool=True,
        internal_as_source: bool=True,
        ) -> Union[Tuple[IPv4, IPv4], Tuple[None, None]]:
    """ A Python function that receive a raw L3 packet and returns the packet source IP and destination IP.

    :param bytes raw: A raw packet.
    :param bool filter_internal_communication: When the field is `True`, the function will return `None` if both source
                                               IP and the destination IP are private.
    :param bool internal_as_source: When the field is `True`, the returned tuple will always have the internal IP
                                    address as the source (flip the values for incoming packets).
    :return: The extracted source and destination IPv4 addresses.
    :rtype: Union[Tuple[IPv4, IPv4], Tuple[None, None]]
    """
    ip_source = IPv4.from_bytes(raw, _IP_SOURCE)
    ip_destination = IPv4.from_bytes(raw, _IP_DESTINATION)
    if internal_as_source and not ip_source.is_private():  # At least one should be private
        ip_source, ip_destination = ip_destination, ip_source  # Flip
    if not filter_internal_communication or not ip_source.is_private() or not ip_destination.is_private():
        return ip_source, ip_destination
    return None, None


_ETHERTYPE_OPTIONS = (
    _PacketField(start_index=12, length=2),  # No VLAN
    _PacketField(start_index=16, length=2),  # Single TAG
    _PacketField(start_index=20, length=2),  # Double TAG
    _PacketField(start_index=24, length=2),  # Triple TAG
    )
_IP_DESTINATION = _PacketField(start_index=16, length=4)
_IP_SOURCE = _PacketField(start_index=12, length=4)
IPv4_PRIVATE_RANGES = (
    (IPv4.from_string('10.0.0.0'), IPv4.from_string('10.255.255.255')),
    (IPv4.from_string('127.0.0.0'), IPv4.from_string('127.255.255.255')),
    (IPv4.from_string('172.16.0.0'), IPv4.from_string('172.31.255.255')),
    (IPv4.from_string('192.168.0.0'), IPv4.from_string('192.168.255.255')),
    (IPv4.from_string('224.0.0.0'), IPv4.from_string('239.255.255.255')),
    (IPv4.from_string('255.255.255.255'), IPv4.from_string('255.255.255.255')),
    )
