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
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_FILE_PATH = "{}/output.txt".format(BASE_DIR)
WORD_LIST_PATH_100 = "{}/data_files/subdomains-100.txt".format(BASE_DIR)
WORD_LIST_PATH_1000 = "{}/data_files/subdomains-1000.txt".format(BASE_DIR)
WORD_LIST_PATH_10000 = "{}/data_files/subdomains-10000.txt".format(BASE_DIR)


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
    parser.add_argument(
        "-n",
        "--num_sub",
        dest="num_sub",
        help="Number of subdomains to enumerate. Options are 100, 1000, or 10000",
        type=int)
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
    if args.enum_sub and not args.num_sub:
        parser.error("\n\n[-] Cannot enumerate subdomains without number to use (use -n switch, see -h for details)\n")
    if args.num_sub not in [100, 1000, 10000]:
        parser.error("\n\n[-] Subdomain count is invalid. Choose 100, 1000, or 10000\n")
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


def update_domains(domain: str, num_sub: int, protocol: str) -> None:
    """
    Populate the deque with urls using words from
    subdomains-10000.txt

    Args:
        domain (str): the domain passed in by the user
        num_sub (int): subdomain number that identifies the file to use as
                       a word list for subdomain enumeration
        protocol (str): protocol to use for the request
    """
    global URLS

    subdomain_files = {
        100: WORD_LIST_PATH_100,
        1000: WORD_LIST_PATH_1000,
        10000: WORD_LIST_PATH_10000,
    }

    with open(subdomain_files[num_sub], 'r') as file:
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
            update_domains(args.domain, args.num_sub, protocol)
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
