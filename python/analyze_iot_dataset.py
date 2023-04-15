from argparse import ArgumentParser, RawTextHelpFormatter
from csv import writer as csv_writer
from logging import DEBUG, basicConfig, getLogger
from multiprocessing import cpu_count
from pathlib import Path
from queue import Queue
from threading import Thread
from typing import Dict, Tuple

from scapy.all import Ether, IP, RawPcapReader

from analyze_packet import TrackedConnection, analyze
from parse_packet import parse_from_l2

basicConfig(format='[%(asctime)s] %(levelname)s - %(threadName)s - %(message)s', level=DEBUG)
Ether.payload_guess = [({'type': 0x800}, IP)]  # Try to speed up the process
IP.payload_guess = []

_CSV_FILE_EXT = '.csv'
_CSV_HEADER = ('ip_source', 'ip_destination', 'timestamp_first', 'timestamp_last', 'packets_count')
_FILE_WRITE_MODE = 'w'
_LOGGER = getLogger()
_MAX_QUEUE_SIZE = 0  # When less than or equal zero, the queue size have no limit
_PCAP_FILE_EXT = ('.pcap', '.pcapng')
_USEC_IN_SEC = 1000000


def _get_workers_count() -> int:
    return cpu_count() - 2  # Hardcoded number representing the 2 threads of the manager and writer


def _manager(input_directory: Path, tasks_queue: Queue) -> None:
    _LOGGER.info(f'Searching for PCAP files at: {input_directory}')
    for pcap_file in (f for f in input_directory.iterdir() if f.suffix in _PCAP_FILE_EXT):
        _LOGGER.debug(f'Found: {pcap_file.name}')
        tasks_queue.put(pcap_file)


def _worker(tasks_queue: Queue, results_queue: Queue) -> None:
    while True:
        pcap_file_path = tasks_queue.get()
        _LOGGER.info(f'Loading: {pcap_file_path.name}')
        hosts: Dict[int, TrackedConnection] = {}
        pcap_results: List[Tuple[int, float, int, float]] = []
        for pkt_data, pkt_metadata in RawPcapReader(str(pcap_file_path)):
            ip_source, ip_destination = parse_from_l2(pkt_data,
                                                      filter_internal_communication=True,
                                                      internal_as_source=True)
            if ip_source is not None and ip_destination is not None:
                if ip_source.is_private() and not ip_destination.is_private():
                    timestamp = pkt_metadata.sec + (pkt_metadata.usec / _USEC_IN_SEC)
                    results = analyze(hosts, ip_source, ip_destination, timestamp)
                    if results is not None:
                        pcap_results.append(results)
        results_queue.put((pcap_file_path, pcap_results))
        tasks_queue.task_done()


def _writer(results_queue: Queue) -> None:
    while True:
        pcap_file_path, pcap_results = results_queue.get()
        _LOGGER.info(f'Writing results for {pcap_file_path.name}')
        with open(pcap_file_path.with_suffix(_CSV_FILE_EXT), _FILE_WRITE_MODE, newline='') as output_file:
            writer = csv_writer(output_file)
            writer.writerow(_CSV_HEADER)
            writer.writerows(pcap_results)
        results_queue.task_done()


def main(pcap_files_directory: Path) -> None:
    _LOGGER.debug(f'Creating work queue of size: {_MAX_QUEUE_SIZE if _MAX_QUEUE_SIZE > 0 else "unlimited"}')
    tasks_queue = Queue(maxsize=_MAX_QUEUE_SIZE)
    results_queue = Queue(maxsize=_MAX_QUEUE_SIZE)
    _LOGGER.debug('Creating the manager')
    worker_manager = Thread(target=_manager, args=(pcap_files_directory, tasks_queue))
    worker_manager.start()
    _LOGGER.debug('Manager have been created')
    num_of_workers = _get_workers_count()
    _LOGGER.info(f'Creating {num_of_workers} workers')
    workers = [Thread(target=_worker, args=(tasks_queue, results_queue), daemon=True) for _ in range(num_of_workers)]
    for worker in workers:
        worker.start()
    _LOGGER.debug('Workers have been created')
    _LOGGER.debug('Creating the results writer')
    results_writer = Thread(target=_writer, args=(results_queue,), daemon=True)
    results_writer.start()
    _LOGGER.debug('Writer have been created')
    _LOGGER.debug('Wait until the manager finish to create all tasks')
    worker_manager.join()
    _LOGGER.debug('Wait until the tasks queue is empty')
    tasks_queue.join()
    _LOGGER.debug('Wait until the results queue is empty')
    results_queue.join()
    _LOGGER.debug('Done')


if __name__ == '__main__':
    argparser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    argparser.add_argument(
        '--path',
        dest='pcap_files_directory',
        help='The directory that contains the PCAP files',
        metavar='<pcap_directory>',
        required=True,
        )
    main(pcap_files_directory=Path(argparser.parse_args().pcap_files_directory).resolve())
