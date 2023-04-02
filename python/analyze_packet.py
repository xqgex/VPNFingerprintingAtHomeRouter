from dataclasses import dataclass
from logging import INFO, basicConfig, getLogger
from typing import Dict, Optional, Tuple

basicConfig(format='[%(asctime)s] %(levelname)s - %(message)s', level=INFO)

_COUNT_PACKETS = 10000
_LOGGER = getLogger()
_TIME_WINDOW_SEC = 20 * 60 # 20 minutes
_WINDOW_OVERLAP_THRESHOLD = 0.75 * _COUNT_PACKETS


@dataclass
class TrackedConnection:
    ip_destination: int
    timestamp: float
    count_this_window: int
    count_prev_window: int

    @classmethod
    def empty(cls) -> 'TrackedConnection':
        return cls(**{f: 0 for f in cls.__annotations__.keys()})


HOSTS: Dict[int, TrackedConnection] = {}
VPN_SERVERS: Dict[int, Tuple[int, float, int]] = {}


def _report(ip_source: int, ip_destination: int, timestamp: float) -> None:
    global VPN_SERVERS
    VPN_SERVERS[ip_source] = (
        ip_destination,
        timestamp - HOSTS[ip_source].timestamp,
        HOSTS[ip_source].count_this_window,
        )
    _LOGGER.info(f'Suspected VPN: {ip_source} with {ip_destination}, {HOSTS[ip_source].count_this_window} ' \
                 f'packets in a {timestamp - HOSTS[ip_source].timestamp} seconds window')


def analyze(ip_source: Optional[int], ip_destination: Optional[int], timestamp: float) -> None:
    """ For every new packet, track the session interval and make decision with this is a suspected VPN connection.

    Note, this is the function that is responsible for the analysis logic.

    :param Optional[int] ip_source: Packet source IPv4 address.
    :param Optional[int] ip_destination: Packet destination IPv4 address.
    :param float timestamp: The time at which this packet was received by the kernel, as a floating-point Unix timestamp
                            with microsecond precision.
    :rtype: None
    """
    def _is_suspected_vpn() -> bool:
        if _COUNT_PACKETS < HOSTS[ip_source].count_this_window:
            return True
        if _WINDOW_OVERLAP_THRESHOLD < HOSTS[ip_source].count_prev_window + HOSTS[ip_source].count_this_window:
            return True
        return False
    global HOSTS
    if ip_source is not None and ip_destination is not None:
        if ip_source not in HOSTS:  # Initial record
            HOSTS[ip_source] = TrackedConnection.empty()
        if HOSTS[ip_source].ip_destination != ip_destination:  # New connection
            HOSTS[ip_source].ip_destination = ip_destination
            HOSTS[ip_source].timestamp = timestamp
            HOSTS[ip_source].count_this_window = 0
        HOSTS[ip_source].count_this_window += 1
        if _TIME_WINDOW_SEC < timestamp - HOSTS[ip_source].timestamp:  # Start a new window
            _LOGGER.debug(f'New window for {ip_source} with {ip_destination}')
            if _is_suspected_vpn():
                _report(ip_source, ip_destination, timestamp)
            HOSTS[ip_source].timestamp = timestamp
            HOSTS[ip_source].count_prev_window = HOSTS[ip_source].count_this_window
            HOSTS[ip_source].count_this_window = 0
