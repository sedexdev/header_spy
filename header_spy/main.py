#!/usr/bin/bash python

import argparse
import os
import urllib3

from threading import Thread
from queue import Queue

s_domains = Queue()
word_list_path = "{}/subdomains.txt".format(os.path.abspath(os.path.dirname(__file__)))


class TerminalColours:
    """
    Colours for displaying success or failure of
    request on stdout
    """
    PURPLE = '\033[95m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'


def get_args() -> argparse.Namespace:
    """
    Gets command line arguments from the user
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain", help="Web domain whose headers you want to inspect")
    parser.add_argument("-e", "--enum_sub", action="store_true", help="Enumerate subdomains from this domain")
    parser.add_argument("-s", "--secure", action="store_true", help="Send requests using HTTPS")
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help="Number of threads to use to enumerate subdomains. Default is 10",
        default=10,
        type=int)
    args = parser.parse_args()
    if not args.domain:
        parser.error("\n\n[-] Expected a domain for the HTTP GET request\n")
    return args


def make_request(domain: str) -> urllib3.HTTPResponse:
    """
    Sends an HTTP GET request to the domain supplied
    by the user

    Args:
        domain (str): domain to send the request to
    """
    http = urllib3.PoolManager()
    return http.request('GET', domain, timeout=3.0)


def enumerate_subdomains() -> None:
    """
    Enumerate subdomains for the domain passed in by
    the user so that headers can be inspected for those
    as well. Subdomain search is based on the file
    subdomains.txt. A list is returned with a dictionary
    containing each subdomain found and the response from
    the server
    """
    global s_domains

    http = urllib3.PoolManager()

    while True:
        url = s_domains.get()
        try:
            response = http.request('GET', url, timeout=3.0)
        except urllib3.exceptions.MaxRetryError:
            print(TerminalColours.FAIL + "[-] {}".format(url))
        except urllib3.exceptions.TimeoutError:
            print(TerminalColours.FAIL + "[-] {}".format(url))
        except urllib3.exceptions.ConnectionError:
            print(TerminalColours.FAIL + "[-] {}".format(url))
        else:
            print(TerminalColours.OKGREEN + "\n[+] Received response from {}\n".format(url))
            for header in response.headers:
                print(TerminalColours.PURPLE + "{x}: {y}".format(x=header, y=response.headers[header]))
            print()
        s_domains.task_done()


def update_queue(domain: str, protocol: str) -> None:
    """
    Populate the deque with urls using words from
    subdomains.txt

    Args:
        domain (str): the domain passed in by the user
        protocol (str): protocol to use for the request
    """
    with open(word_list_path, 'r') as file:
        words = file.read().splitlines()
        for word in words:
            s_domains.put("{x}{y}.{z}".format(x=protocol, y=word, z=domain))


def main() -> None:
    """
    Main method for the HeaderSpy tool
    """
    global s_domains

    args = get_args()
    protocol = "https://" if args.secure else "http://"
    try:
        print("\n[+] Sending requests and awaiting responses...")
        if args.enum_sub:
            update_queue(args.domain, protocol)
            threads = [Thread(target=enumerate_subdomains) for _ in range(args.threads)]
            for thread in threads:
                thread.daemon = True
                thread.start()
            for thread in threads:
                thread.join()
        else:
            response = make_request("{x}{y}".format(x=protocol, y=args.domain))
            print(TerminalColours.OKGREEN + "[+] Received response from {x}{y}\n".format(x=protocol, y=args.domain))
            for header in response.headers:
                print(TerminalColours.PURPLE + "{x}: {y}".format(x=header, y=response.headers[header]))
            print()
    except urllib3.exceptions.MaxRetryError:
        print(TerminalColours.FAIL + "[-] {x}{y}".format(x=protocol, y=args.domain))
        print("\n[-] Request failed. Either the server is unresponsive or the domain is not valid\n")


if __name__ == "__main__":
    main()
