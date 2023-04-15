from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union


@dataclass
class TrackedConnection:
    count_this_window: int
    ip_destination: int
    last_timestamp: float
    timestamp: float

    def to_list(self) -> List[Union[int, float]]:
        return [self.ip_destination, self.timestamp, self.last_timestamp, self.count_this_window]

    @classmethod
    def empty(cls) -> 'TrackedConnection':
        return cls(**{f: 0 for f in cls.__annotations__.keys()})


def analyze(
        hosts: Dict[int, TrackedConnection],
        ip_source: Optional[int],
        ip_destination: Optional[int],
        timestamp: float
        ) -> Optional[Tuple[int, int, float, float, int]]:
    """ For every new packet, track the session interval and make decision with this is a suspected VPN connection.

    Note, this is the function that is responsible for the analysis logic.
    Note, the function update the values of hosts that are stored at the caller.

    ;param Dict[int, TrackedConnection] hosts: The hosts database.
    :param Optional[int] ip_source: Packet source IPv4 address.
    :param Optional[int] ip_destination: Packet destination IPv4 address.
    :param float timestamp: The time at which this packet was received by the kernel, as a floating-point Unix timestamp
                            with microsecond precision.
    :return: If a new connection have been started, return the data of the previous one.
    :rtype: Optional[Tuple[int, int, float, float, int]]
    """
    ret = None
    if ip_source not in hosts:  # Initial record
        hosts[ip_source] = TrackedConnection.empty()
        hosts[ip_source].last_timestamp = timestamp
    if hosts[ip_source].ip_destination != ip_destination:  # New connection
        if hosts[ip_source].ip_destination:  # Ignore initial records
            ret = tuple([ip_source] + hosts[ip_source].to_list())
        hosts[ip_source].ip_destination = ip_destination
        hosts[ip_source].timestamp = timestamp
        hosts[ip_source].count_this_window = 0
    else:
        hosts[ip_source].last_timestamp = timestamp
    hosts[ip_source].count_this_window += 1
    return ret
