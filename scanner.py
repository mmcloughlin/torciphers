import sys
import json
import logging
import random

from sslyze.concurrent_scanner import ConcurrentScanner
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.plugins.openssl_cipher_suites_plugin import *


def split_host_port(addr):
    ip, port_str = addr.split(':')
    return ip, int(port_str)


def scan_commands():
    return [
            Tlsv10ScanCommand(),
            ]


def scan_cipher_lists(addresses):
    # prepare scanner
    s = ConcurrentScanner()
    for addr in addresses:
        ip, port = split_host_port(addr)
        server_info = ServerConnectivityInfo(hostname=addr, ip_address=ip, port=port)
        try:
            server_info.test_connectivity_to_server()
            logging.info('connected to %s', addr)
        except:
            logging.warn('connection to %s failed', addr)
            continue
        for cmd in scan_commands():
            s.queue_scan_command(server_info, cmd)

    # execute
    for result in s.get_results(): 
        addr = result.server_info.hostname
        logging.info('results for %s', addr)
        for cipher in result.accepted_cipher_list:
            print addr, cipher.name, cipher.ssl_version


def read_or_addresses(f):
    """
    Extract or_addresses from output of
    https://onionoo.torproject.org/details.
    """
    data = json.load(f)
    relays = data['relays']

    addresses = []
    for relay in relays:
        if not relay['running']:
            continue
        addresses.append(relay['or_addresses'][0])

    return addresses


def main(args):
    logging.basicConfig(level=logging.DEBUG)

    filename = args[0]
    sample_size = int(args[1])

    with open(filename) as f:
        addresses = read_or_addresses(f)

    sample = random.sample(addresses, sample_size)
    logging.info('sampled %d of %d running relays', sample_size, len(addresses))

    scan_cipher_lists(sample)


if __name__ == '__main__':
    main(sys.argv[1:])
