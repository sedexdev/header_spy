#!/usr/bin/bash python

import argparse
import os
import urllib.request
import urllib.error

from concurrent.futures import as_completed, ThreadPoolExecutor
from http.client import HTTPMessage
from socket import timeout
from typing import Callable

URLS = []
OUTPUT_FILE_PATH = "{}/output.txt".format(os.path.abspath(os.path.dirname(__file__)))
WORD_LIST_PATH = "{}/subdomains.txt".format(os.path.abspath(os.path.dirname(__file__)))


class TerminalColours:
    """
    Colours for displaying success or failure of
    request on stdout
    """
    PURPLE = '\033[95m'
    OKGREEN = '\033[92m'
    YELLOW = '\033[33m'
    FAIL = '\033[91m'


def get_args() -> argparse.Namespace:
    """
    Gets command line arguments from the user
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain", help="Web domain whose headers you want to inspect")
    parser.add_argument("-e", "--enum_sub", action="store_true", help="Enumerate subdomains from this domain")
    parser.add_argument("-s", "--secure", action="store_true", help="Send requests using HTTPS")
    parser.add_argument("-o", "--output", action="store_true", help="Sends the results to a file called hs_output.txt")
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


def make_request(url: str) -> HTTPMessage:
    """
    Send a get request to the url passed in and return
    the headers in the response

    Args:
        url (str): url to send GET request to
    """
    with urllib.request.urlopen(url, timeout=30) as conn:
        return conn.info()


def update_domains(domain: str, protocol: str) -> None:
    """
    Populate the deque with urls using words from
    subdomains.txt

    Args:
        domain (str): the domain passed in by the user
        protocol (str): protocol to use for the request
    """
    global URLS

    with open(WORD_LIST_PATH, 'r') as file:
        words = file.read().splitlines()
        URLS = ["{x}{y}.{z}".format(x=protocol, y=word, z=domain) for word in words]
        URLS = ["{x}{y}".format(x=protocol, y=domain)] + URLS


def write_file(headers: HTTPMessage, subdomain: str) -> None:
    """
    Write the response headers to a file located at
    OUTPUT_FILE_PATH

    Args:
        headers (HTTPResponse): response received from GET request
        subdomain (str): url the request was sent to
    """
    with open(OUTPUT_FILE_PATH, 'a') as file:
        file.write("[+] Received response from {}\n\n".format(subdomain))
        file.write(str(headers))
        file.write("")


def write_stdout(headers: HTTPMessage, subdomain: str) -> None:
    """
    Write the response headers to stdout

    Args:
        headers (HTTPMessage): response received from GET request
        subdomain (str): url the request was sent to
    """
    print(TerminalColours.OKGREEN + "\n[+] Received response from {}\n".format(subdomain))
    print(TerminalColours.PURPLE + str(headers), end="")


def execute(func: Callable, num_threads: int, output=False) -> None:
    """
    Creates a thread pool with <args.threads> number
    of threads for making parallel requests

    Args:
        func (Callable): function for thread to call
        num_threads (int): number of threads in the pool
        output (bool): write headers to file if True
    """
    global URLS

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_url = {executor.submit(func, url): url for url in URLS}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                response = future.result()
                if output:
                    write_file(response, url)
                else:
                    write_stdout(response, url)
            except timeout as e:
                if not output:
                    print(TerminalColours.FAIL + "[-] {x}: {y}".format(x=url, y=e))
            except urllib.error.URLError as e:
                if not output:
                    print(TerminalColours.FAIL + "[-] {x}: {y}".format(x=url, y=e.reason))


def main() -> None:
    """
    Main method for the HeaderSpy tool
    """
    args = get_args()
    protocol = "https://" if args.secure else "http://"
    url = "{x}{y}".format(x=protocol, y=args.domain)
    try:
        if args.enum_sub:
            update_domains(args.domain, protocol)
            if args.output:
                print("\n[+] Sending requests and awaiting responses...")
                print("[+] Writing results to output.txt, this may take some time...\n")
                execute(make_request, args.threads, True)
            else:
                print("\n[+] Sending requests and awaiting responses...\n")
                execute(make_request, args.threads)
            print(TerminalColours.OKGREEN + "\n[+] Processes complete\n")
        else:
            headers = make_request(url)
            if args.output:
                write_file(headers, url)
            else:
                write_stdout(headers, url)
    except urllib.error.URLError as e:
        print(TerminalColours.FAIL + "[-] {x}: {y}".format(x=url, y=e.reason))


if __name__ == "__main__":
    main()
