from argparse import ArgumentParser, RawTextHelpFormatter
from enum import Enum
from itertools import groupby
from pathlib import Path
from re import fullmatch
from statistics import mean
from typing import Iterable, NamedTuple, Optional, Tuple

_REGEX_DMESG_DEBUG_LINE = r'[ :\w]+ kern.debug kernel: \[\d+.\d{6}\] \[Debug\] - analyze\(\) - ([ \w]+) - ([.\d]+) - ([.\d]+) - (\d+) - (\d+)'
_REGEX_DMESG_NOTICE_LINE = r'[ :\w]+ kern.debug kernel: \[\d+.\d{6}\] \[Notice\] - reporter\(\) - ([ \w]+) - ([.\d]+) - ([.\d]+) - (\d+)'


class DmesgLineType(Enum):
    FOUND_VPN = 'Found VPN connection'
    INITIAL_RECORD = 'Initial record'
    NEW_CONNECTION = 'New connection'
    NEW_WINDOW = 'Start a new window'


class DmesgLine(NamedTuple):
    source_ip: str
    destination_ip: str
    timestamp_sec: int
    packets_count: Optional[int]
    message_tupe: DmesgLineType

    @classmethod
    def from_string(cls, log_line: str) -> Optional['DmesgLine']:
        try:
            message, src, dst, timestamp, count = fullmatch(_REGEX_DMESG_DEBUG_LINE, log_line).groups()
        except (AttributeError, ValueError):
            try:
                message, src, dst, timestamp = fullmatch(_REGEX_DMESG_NOTICE_LINE, log_line).groups()
            except (AttributeError, ValueError):
                return None
            count = None
        return cls(source_ip=src,
                   destination_ip=dst,
                   timestamp_sec=int(timestamp),
                   packets_count=int(count) if count else count,
                   message_tupe=DmesgLineType(message))


class Session(NamedTuple):
    destination_ip: str
    timestamp_start: int
    timestamp_end: int
    packets_count: int

    @property
    def duration(self) -> int:
        return self.timestamp_end - self.timestamp_start

    @classmethod
    def from_two_lines(cls, first_line: DmesgLine, second_line: DmesgLine) -> 'Session':
        return cls(destination_ip=first_line.destination_ip,
                   timestamp_start=first_line.timestamp_sec,
                   timestamp_end=second_line.timestamp_sec,
                   packets_count=second_line.packets_count)


class IPSessions(NamedTuple):
    source_ip: str
    sessions: Tuple[Session, ...]

    @property
    def average_session(self) -> Optional[float]:
        if len(self.sessions) == 0:
            return None
        return round(mean(s.duration for s in self.sessions), 4)

    @property
    def destination_address_of_longest_session(self) -> Optional[str]:
        longest_session = self.longest_session
        packets_in_longest_session = self.packets_in_longest_session
        for session in self.sessions:
            if session.duration == longest_session and session.packets_count == packets_in_longest_session:
                return session.destination_ip
        return None

    @property
    def longest_session(self) -> Optional[int]:
        if len(self.sessions) == 0:
            return None
        return max(s.duration for s in self.sessions)

    @property
    def packets_in_longest_session(self) -> Optional[int]:
        if len(self.sessions) == 0:
            return None
        longest_session = self.longest_session
        return max(s.packets_count for s in self.sessions if s.duration == longest_session)

    @property
    def unique_destination_addresses(self) -> int:
        return len(set(s.destination_ip for s in self.sessions))

    @classmethod
    def from_groupby(cls, groupby_data: Tuple[str, Iterable[DmesgLine]]) -> 'IPSessions':
        source_ip, dmesg_lines = groupby_data
        dmesg_lines = tuple(dmesg_lines)
        sessions = []
        for line_index, dmesg_line in enumerate(dmesg_lines):
            if dmesg_line.source_ip != source_ip:
                raise ValueError(
                    f'Invalid input, data source IP address does not match\nIP: {source_ip}\n{dmesg_line}')
            if line_index > 0 and dmesg_line.message_tupe == DmesgLineType.NEW_CONNECTION:
                sessions.append(Session.from_two_lines(dmesg_lines[line_index - 1], dmesg_line))
        return cls(source_ip=source_ip, sessions=tuple(sessions))


def main(log_file_path: Path) -> None:
    dmesg_lines = filter(None, map(DmesgLine.from_string, log_file_path.read_text().splitlines()))
    dmesg_lines_sorted = sorted(dmesg_lines, key=lambda l: l.source_ip)
    ip_sessions = tuple(map(IPSessions.from_groupby, groupby(dmesg_lines_sorted, lambda l: l.source_ip)))
    for ip_session in ip_sessions:
        print('=' * 50)
        print(f'Source IP address: {ip_session.source_ip}')
        print(f'How many sessions switches: {len(ip_session.sessions)}')
        print(f'Unique destination IP addresses: {ip_session.unique_destination_addresses}')
        print(f'Average session duration: {ip_session.average_session}')
        print(f'Longest session duration: {ip_session.longest_session}')
        print(f'Number of packets in the longest session: {ip_session.packets_in_longest_session}')
        print(f'Destination IP address of the longest session: {ip_session.destination_address_of_longest_session}')


if __name__ == '__main__':
    argparser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    argparser.add_argument(
        '--path',
        dest='log_file_path',
        help='The path to the dmesg log file',
        metavar='<log_file_path>',
        required=True,
        )
    main(log_file_path=Path(argparser.parse_args().log_file_path).resolve())
