""" Tests for the packet parsing class. """

from enum import Enum, auto
from typing import NamedTuple, Optional

from hamcrest import assert_that, calling, equal_to, is_, not_, raises
import pytest

from parse_packet import IPv4, parse_from_l2


class _Direction(Enum):
    INCOMING = auto()  # Source IP outside the network AND destination IP inside the network
    INTERNAL = auto()  # Source IP inside the network AND destination IP inside the network
    OUTGOING = auto()  # Source IP inside the network AND destination IP outside the network


class _TestPacket(NamedTuple):
    raw: bytes
    ip_source: Optional[IPv4]
    ip_destination: Optional[IPv4]
    communication_direction: Optional[_Direction]


_TEST_IPV4_PACKETS = (
    _TestPacket(raw=bytes.fromhex(
                    '08 00 27 4a be 45 08 00 27 bb 22 84 08 00 45 00'
                    '00 3c cd 48 40 00 40 06 7b 55 c0 a8 38 67 c0 a8'
                    '38 66 c7 91 04 aa 8e 58 cc bf 00 00 00 00 a0 02'
                    '39 08 f3 91 00 00 02 04 05 b4 04 02 08 0a 00 03'
                    '01 f7 00 00 00 00 01 03 03 01'
                    ),
                ip_source=IPv4.from_string('192.168.56.103'),  # 'c0 a8 38 67'
                ip_destination=IPv4.from_string('192.168.56.102'),  # 'c0 a8 38 66'
                communication_direction=_Direction.INTERNAL),
    _TestPacket(raw=bytes.fromhex(
                    '08 00 27 bb 22 84 08 00 27 4a be 45 08 00 45 00'
                    '00 6c 29 8d 40 00 40 06 1e e1 c0 a8 38 66 c0 a8'
                    '38 67 04 aa c7 91 ee 2e db c3 8e 58 cc ec 80 18'
                    '1c 48 86 0d 00 00 01 01 08 0a 00 04 f3 4c 00 03'
                    '02 f4 00 36 40 59 3c 3c 23 23 2b b9 0a 81 03 1a'
                    'c1 c7 fa 0b c6 4c 2e 29 e4 a7 32 94 7a 60 84 f5'
                    'aa 00 00 00 01 50 ff 20 fc 01 00 00 00 00 28 e1'
                    '32 8a 71 85 e6 ca 00 00 00 00'
                    ),
                ip_source=IPv4.from_string('192.168.56.102'),  # 'c0 a8 38 66'
                ip_destination=IPv4.from_string('192.168.56.103'),  # 'c0 a8 38 67'
                communication_direction=_Direction.INTERNAL),
    _TestPacket(raw=bytes.fromhex(
                    'a4 5e 60 f1 7d 93 94 10 3e 05 36 d3 08 00 45 28'
                    '00 4c 00 00 40 00 34 11 65 4c 11 fd 0c fd c0 a8'
                    '01 8b 00 7b 00 7b 00 38 ea 4f 24 01 06 ec 00 00'
                    '00 00 00 00 00 47 47 50 53 73 d9 7b 64 77 91 fd'
                    'bd c8 d9 7b 64 7e 29 6a f5 31 d9 7b 64 7e 48 be'
                    'c5 7c d9 7b 64 7e 48 bf af d4'
                    ),
                ip_source=IPv4.from_string('17.253.12.253'),  # '11 fd 0c fd'
                ip_destination=IPv4.from_string('192.168.1.139'),  # 'c0 a8 01 8b'
                communication_direction=_Direction.INCOMING),
    _TestPacket(raw=bytes.fromhex(
                    '94 10 3e 05 36 d3 a4 5e 60 f1 7d 93 08 00 45 00'
                    '00 34 d9 7a 40 00 40 06 6f b5 c0 a8 01 8b 4a 7d'
                    'e4 e3 c7 25 01 bb 2b ce 30 90 43 54 83 c3 80 10'
                    '10 14 4c 78 00 00 01 01 08 0a 4b 2a 91 55 e4 57'
                    '7b 6e'
                    ),
                ip_source=IPv4.from_string('192.168.1.139'),  # 'c0 a8 01 8b'
                ip_destination=IPv4.from_string('74.125.228.227'),  # '4a 7d e4 e3'
                communication_direction=_Direction.OUTGOING),
    _TestPacket(raw=bytes.fromhex(
                    'a4 5e 60 f1 7d 93 94 10 3e 05 36 d3 08 00 45 28'
                    '00 34 40 fc 00 00 35 06 53 0c 4a 7d e4 e3 c0 a8'
                    '01 8b 01 bb c7 25 43 54 83 c3 2b ce 35 e8 80 10'
                    '01 68 55 ae 00 00 01 01 08 0a e4 57 7b 8c 4b 2a'
                    '91 55'
                    ),
                ip_source=IPv4.from_string('74.125.228.227'),  # '4a 7d e4 e3'
                ip_destination=IPv4.from_string('192.168.1.139'),  # 'c0 a8 01 8b'
                communication_direction=_Direction.INCOMING),
    _TestPacket(raw=bytes.fromhex(
                    '00 60 08 9f b1 f3 00 40 05 40 ef 24 81 00 00 20'
                    '08 00 45 00 00 30 3b c3 00 b9 ff 01 37 8c 0a 97'
                    '20 81 83 97 20 15 c0 c1 c2 c3 c4 c5 c6 c7 c8 c9'
                    'ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9'
                    'da db'
                    ),
                ip_source=IPv4.from_string('10.151.32.129'),  # '0a 97 20 81'
                ip_destination=IPv4.from_string('131.151.32.21'),  # '83 97 20 15'
                communication_direction=_Direction.OUTGOING),
    _TestPacket(raw=bytes.fromhex(
                    '00 10 94 00 00 0c 00 10 94 00 00 14 88 a8 00 1e'
                    '81 00 00 64 08 00 45 00 05 c2 54 b0 00 00 ff fd'
                    'dd bf c0 55 01 16 0a 7c c8 03 00 00 00 00 00 00'
                    ),
                ip_source=IPv4.from_string('192.85.1.22'),  # 'c0 55 01 16'
                ip_destination=IPv4.from_string('10.124.200.3'),  # '0a 7c c8 03'
                communication_direction=_Direction.INCOMING),
    _TestPacket(raw=bytes.fromhex(
                    'ff ff ff ff ff ff aa bb cc dd ee ff 08 00 45 00'
                    '00 3c cd 48 40 00 40 06 7b 55 c0 a8 38 67 ff ff'
                    'ff ff c7 91 04 aa 8e 58 cc bf 00 00 00 00 a0 02'
                    '39 08 f3 91 00 00 02 04 05 b4 04 02 08 0a 00 03'
                    '01 f7 00 00 00 00 01 03 03 01'
                    ),
                ip_source=IPv4.from_string('192.168.56.103'),  # 'c0 a8 38 67'
                ip_destination=IPv4.from_string('255.255.255.255'),  # 'ff ff ff ff'
                communication_direction=_Direction.INTERNAL),
    )
_TEST_NON_IPV4_PACKETS = (
    _TestPacket(raw=bytes.fromhex(
                    '01 00 0c 00 00 07 00 02 fd 2c b8 97 00 00 aa aa'
                    '03 00 00 00 01 bd 00 00 00 00 01 80 c2 00 00 00'
                    '00 02 fd 2c b8 98 00 26 42 42 03 00 00 00 00 00'
                    '80 00 00 02 fd 2c b8 82 00 00 00 00 80 00 00 02'
                    'fd 2c b8 82 80 26 00 00 14 00 02 00 0f 00 00 00'
                    '00 00 00 00 00 00 c8 ae 70 0f'
                    ),
                ip_source=None,
                ip_destination=None,
                communication_direction=None),
    _TestPacket(raw=bytes.fromhex(
                    'ff ff ff ff ff ff 08 00 07 84 12 de 81 00 00 68'
                    '81 37 ff ff 00 28 00 01 00 00 00 00 ff ff ff ff'
                    'ff ff 04 53 00 05 68 00 08 00 07 84 12 de 04 53'
                    '00 01 00 05 25 82 ff ff ff ff 00 00 00 00 00 00'
                    ),
                ip_source=None,
                ip_destination=None,
                communication_direction=None),
    )


class TestPacketParsing:
    @pytest.mark.parametrize('packet,_1,_2,_3', [
        *_TEST_IPV4_PACKETS
        ])
    def test_that_calling_packet_parse_with_an_ipv4_packet_does_not_raise_an_exception(
            self,
            packet: bytes,
            _1: Optional[IPv4],
            _2: Optional[IPv4],
            _3: Optional[_Direction],
            ) -> None:
        assert_that(calling(parse_from_l2).with_args(packet), not_(raises(Exception)))

    @pytest.mark.parametrize('packet,_1,_2,_3', [
        *_TEST_NON_IPV4_PACKETS
        ])
    def test_that_calling_packet_parse_with_a_non_ipv4_packet_does_not_raise_an_exception(
            self,
            packet: bytes,
            _1: Optional[IPv4],
            _2: Optional[IPv4],
            _3: Optional[_Direction],
            ) -> None:
        assert_that(calling(parse_from_l2).with_args(packet), not_(raises(Exception)))

    @pytest.mark.parametrize('packet,ip_source,ip_destination,_', [
        *_TEST_IPV4_PACKETS
        ])
    def test_that_calling_packet_parse_with_an_ipv4_packet_returns_an_expected_results(
            self,
            packet: bytes,
            ip_source: Optional[IPv4],
            ip_destination: Optional[IPv4],
            _: Optional[_Direction],
            ) -> None:
        assert_that(parse_from_l2(packet, filter_internal_communication=False, internal_as_source=False),
                    is_(equal_to((ip_source, ip_destination))))

    @pytest.mark.parametrize('packet,ip_source,ip_destination,_', [
        *_TEST_NON_IPV4_PACKETS
        ])
    def test_that_calling_packet_parse_with_a_non_ipv4_packet_returns_an_expected_results(
            self,
            packet: bytes,
            ip_source: Optional[IPv4],
            ip_destination: Optional[IPv4],
            _: Optional[_Direction],
            ) -> None:
        assert_that(parse_from_l2(packet, filter_internal_communication=False, internal_as_source=False),
                    is_(equal_to((ip_source, ip_destination))))

    @pytest.mark.parametrize('packet,ip_source,ip_destination,communication_direction', [
        *_TEST_IPV4_PACKETS
        ])
    def test_that_filter_internal_communication_variable_returns_an_expected_results(
            self,
            packet: bytes,
            ip_source: Optional[IPv4],
            ip_destination: Optional[IPv4],
            communication_direction: Optional[_Direction],
            ) -> None:
        expected = (None, None) if communication_direction == _Direction.INTERNAL else (ip_source, ip_destination)
        assert_that(parse_from_l2(packet, filter_internal_communication=True, internal_as_source=False),
                    is_(equal_to(expected)))

    @pytest.mark.parametrize('packet,ip_source,ip_destination,communication_direction', [
        *_TEST_IPV4_PACKETS
        ])
    def test_that_internal_as_source_variable_returns_an_expected_results(
            self,
            packet: bytes,
            ip_source: Optional[IPv4],
            ip_destination: Optional[IPv4],
            communication_direction: Optional[_Direction],
            ) -> None:
        if communication_direction == _Direction.INCOMING:
            ip_source, ip_destination = ip_destination, ip_source  # Flip
        assert_that(parse_from_l2(packet, filter_internal_communication=False, internal_as_source=True),
                    is_(equal_to((ip_source, ip_destination))))
