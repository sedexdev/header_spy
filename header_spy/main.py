#!/usr/bin/bash python

import argparse
import os
import urllib.request
import urllib.error

from colours import TerminalColours
from concurrent.futures import as_completed, ThreadPoolExecutor
from http.client import HTTPMessage
from socket import timeout
from typing import Callable

from output import (
    uni_file_heading,
    write_file_uni,
    write_file,
    write_stdout_uni,
    write_stdout
)

URLS = []
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
WORD_LIST_PATH_100 = "{}/data_files/subdomains-100.txt".format(BASE_DIR)
WORD_LIST_PATH_1000 = "{}/data_files/subdomains-1000.txt".format(BASE_DIR)
WORD_LIST_PATH_10000 = "{}/data_files/subdomains-10000.txt".format(BASE_DIR)


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
    parser.add_argument("-o", "--output", action="store_true", help="Send the results to a file called header_data.txt")
    parser.add_argument("-u", "--uni-header", dest="uni", help="Display which responses contain a specific header")
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help="Number of threads to use to enumerate subdomains. Default is 10",
        default=10,
        type=int)
    parser.add_argument("-v", "--verbose", action="store_true", help="Outputs additional details")
    args = parser.parse_args()
    if not args.domain:
        parser.error("\n\n[-] Expected a domain for the HTTP GET request\n")
    if args.enum_sub and not args.num_sub:
        parser.error("\n\n[-] Cannot enumerate subdomains without count to use (use -n switch, see -h for details)\n")
    if args.num_sub and args.num_sub not in [100, 1000, 10000]:
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


def handle_output(output: bool, args: argparse.Namespace, response: HTTPMessage, url: str) -> None:
    """
    Processes responses by sending data to the correct
    output function depending on input provided by the
    user

    Args:
        output (bool): write headers to file if True
        args (argparse.Namespace): arguments provided by the user
        response (HTTPMessage): response from HTTP GET request
        url (str): url to send the HTTP GET request to
    """
    if output:
        if args.uni:
            write_file_uni(response, args.uni, url)
        else:
            write_file(response, url, args.verbose)
    else:
        if args.uni:
            write_stdout_uni(response, args.uni, url)
        else:
            write_stdout(response, url, args.verbose)


def execute(func: Callable, args: argparse.Namespace, output=False) -> None:
    """
    Creates a thread pool with <args.threads> number
    of threads for making parallel requests

    Args:
        func (Callable): function for thread to call
        args (argparse.Namespace): arguments provided by the user
        output (bool): write headers to file if True
    """
    global URLS

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(func, url): url for url in URLS}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                response = future.result()
                handle_output(output, args, response, url)
            except timeout as e:
                if not output:
                    print(TerminalColours.RED + "[-] {x}: {y}".format(x=url, y=e))
            except urllib.error.URLError as e:
                if not output:
                    print(TerminalColours.RED + "[-] {x}: {y}".format(x=url, y=e.reason))


def handle_multiple(args: argparse.Namespace, protocol: str) -> None:
    """
    Perform all necessary actions when the user has
    specified that subdomains should be enumerated

    Args:
        args (argParse.Namespace): command line args from
                                   the user
        protocol (str): protocol to use when sending requests
    """
    update_domains(args.domain, args.num_sub, protocol)
    if args.output:
        print("\n[+] Sending requests and awaiting responses...")
        print("[+] Writing results to header_data.txt, this may take some time...\n")
        if not args.enum_sub:
            uni_file_heading(args.uni, args.domain, False)
        execute(make_request, args, True)
    else:
        print("\n[+] Sending requests and awaiting responses...\n")
        execute(make_request, args)
    print(TerminalColours.GREEN + "\n[+] Processes complete\n")


def handle_single(args: argparse.Namespace, url: str) -> None:
    """
    Perform all necessary actions when the user has
    specified that only a single domain should be
    inspected

    Args:
        args (argParse.Namespace): command line args from
                                   the user
        url (str): url to send the HTTP GET request to
    """
    headers = make_request(url)
    if args.output:
        print("\n[+] Sending requests and awaiting responses...")
        if args.uni:
            print(TerminalColours.GREEN + "[+] Inspecting responses for header '{}'".format(args.uni))
            print(TerminalColours.GREEN + "[+] Writing results to header_data.txt...")
            uni_file_heading(args.uni, url)
        else:
            print("[+] Writing results to header_data.txt...")
            write_file(headers, url, args.verbose)
    else:
        if args.uni:
            print("\n[+] Inspecting responses for header '{}'\n".format(args.uni))
            write_stdout_uni(headers, args.uni, url)
        else:
            write_stdout(headers, url, args.verbose)
    print(TerminalColours.GREEN + "\n[+] Processes complete\n")


def main() -> None:
    """
    Main method for the HeaderSpy tool
    """
    args = get_args()
    protocol = "https://" if args.secure else "http://"
    url = "{x}{y}".format(x=protocol, y=args.domain)
    try:
        if args.enum_sub:
            handle_multiple(args, protocol)
        else:
            handle_single(args, url)
    except urllib.error.URLError as e:
        print(TerminalColours.RED + "[-] {x}: {y}".format(x=url, y=e.reason))


if __name__ == "__main__":
    main()
