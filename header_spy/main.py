#!/usr/bin/bash python

import argparse
import os
import urllib.request
import urllib.error

from secure_headers import *
from collections import defaultdict
from concurrent.futures import as_completed, ThreadPoolExecutor
from http.client import HTTPMessage
from socket import timeout
from typing import Callable, List

URLS = []
BASE_DIR = os.getcwd()
OUTPUT_FILE_PATH = "{}/header_data.txt".format(BASE_DIR)
WORD_LIST_PATH_100 = "{}/data_files/subdomains-100.txt".format(BASE_DIR)
WORD_LIST_PATH_1000 = "{}/data_files/subdomains-1000.txt".format(BASE_DIR)
WORD_LIST_PATH_10000 = "{}/data_files/subdomains-10000.txt".format(BASE_DIR)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "Referrer-Policy",
    "Permissions-Policy",
    "Clear-Site-Data",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cache-Control",
]

SECURITY_HEADER_INSTANCES = {
    "Strict-Transport-Security": StrictTransportSecurity(),
    "X-Frame-Options": XFrameOptions(),
    "X-Content-Type-Options": XContentTypeOptions(),
    "Content-Security-Policy": ContentSecurityPolicy(),
    "X-Permitted-Cross-Domain-Policies": XPermittedCrossDomainPolicies(),
    "Referrer-Policy": ReferrerPolicy(),
    "Permissions-Policy": PermissionsPolicy(),
    "Clear-Site-Data": ClearSiteData(),
    "Cross-Origin-Embedder-Policy": CrossOriginEmbedderPolicy(),
    "Cross-Origin-Opener-Policy": CrossOriginOpenerPolicy(),
    "Cross-Origin-Resource-Policy": CrossOriginResourcePolicy(),
    "Cache-Control": CacheControl()
}


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
    parser.add_argument("-o", "--output", action="store_true", help="Send the results to a file called header_data.txt")
    parser.add_argument("-u", "--uni-header", dest="uni", help="Display which responses contain a specific header")
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


def parse_headers(headers: HTTPMessage) -> defaultdict:
    """
    Parse the response headers and their values into a
    dictionary
    """
    header_dict = defaultdict()
    for header in str(headers).split("\n"):
        delimiter = header.find(":")
        key = header[:delimiter]
        value = header[delimiter + 2:]
        header_dict[key] = value
    return header_dict


def verify_security(headers_dict: defaultdict) -> List:
    """
    Check the headers contained in the HTTP response against
    the list of security headers recommended by the OWASP
    Secure Headers Project
    """
    found_headers = headers_dict.keys()
    missing_headers = [x for x in SECURITY_HEADERS if x not in found_headers]
    return missing_headers


def write_file_uni(headers: HTTPMessage, header: str, subdomain: str) -> None:
    """
    Write the results of an inspection for a single header to
    an output file

    Args:
        headers (HTTPResponse): response received from GET request
        header (str): the header being looked for
        subdomain (str): url the request was sent to
    """
    header_dict = parse_headers(headers)
    found_headers = header_dict.keys()
    if header in found_headers:
        with open(OUTPUT_FILE_PATH, 'a') as file:
            file.write("{}\n".format(subdomain))


def write_file(headers: HTTPMessage, subdomain: str) -> None:
    """
    Write the response headers to a file located at
    OUTPUT_FILE_PATH

    Args:
        headers (HTTPResponse): response received from GET request
        subdomain (str): url the request was sent to
    """
    header_dict = parse_headers(headers)
    with open(OUTPUT_FILE_PATH, 'a') as file:
        file.write("[+] Received response from {}\n\n".format(subdomain))
        file.write(str(headers))
        file.write("")
        secure_headers = verify_security(header_dict)
        if len(secure_headers):
            file.write("[-] Response is missing the following security headers:\n")
            file.write("\n=======================================================\n")
            for sh in secure_headers:
                file.write("{}\n".format(sh))
            file.write("=======================================================\n\n")


def write_stdout_uni(headers: HTTPMessage, header: str, subdomain: str) -> None:
    """
    Write the results of an inspection for a single header to stdout

    Args:
        headers (HTTPResponse): response received from GET request
        header (str): the header being looked for
        subdomain (str): url the request was sent to
    """
    header_dict = parse_headers(headers)
    found_headers = header_dict.keys()
    if header in found_headers:
        print(TerminalColours.OKGREEN + "[+] {}".format(subdomain))
    else:
        print(TerminalColours.FAIL + "[-] {}".format(subdomain))


def write_stdout(headers: HTTPMessage, subdomain: str) -> None:
    """
    Write the response headers to stdout

    Args:
        headers (HTTPMessage): response received from GET request
        subdomain (str): url the request was sent to
    """
    header_dict = parse_headers(headers)
    print(TerminalColours.OKGREEN + "\n[+] Received response from {}\n".format(subdomain))
    print(TerminalColours.PURPLE + str(headers), end="")
    secure_headers = verify_security(header_dict)
    if len(secure_headers):
        print(TerminalColours.YELLOW + "[-] Response is missing the following security headers:\n")
        print("=======================================================")
        for sh in secure_headers:
            print(TerminalColours.YELLOW + sh)
        print("=======================================================\n")


def handle_output(output: bool, search_header: str, response: HTTPMessage, url: str) -> None:
    """
    Processes responses by sending data to the correct
    output function depending on input provided by the
    user

    Args:
        output (bool): write headers to file if True
        search_header (str): single header to search for in responses
        response (HTTPMessage): response from HTTP GET request
        url (str): url to send the HTTP GET request to
    """
    if output:
        if search_header:
            write_file_uni(response, search_header, url)
        else:
            write_file(response, url)
    else:
        if search_header:
            write_stdout_uni(response, search_header, url)
        else:
            write_stdout(response, url)


def execute(func: Callable, num_threads: int, search_header: str, output=False) -> None:
    """
    Creates a thread pool with <args.threads> number
    of threads for making parallel requests

    Args:
        func (Callable): function for thread to call
        num_threads (int): number of threads in the pool
        search_header (str): single header to search for in responses
        output (bool): write headers to file if True
    """
    global URLS

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_url = {executor.submit(func, url): url for url in URLS}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                response = future.result()
                handle_output(output, search_header, response, url)
            except timeout as e:
                if not output:
                    print(TerminalColours.FAIL + "[-] {x}: {y}".format(x=url, y=e))
            except urllib.error.URLError as e:
                if not output:
                    print(TerminalColours.FAIL + "[-] {x}: {y}".format(x=url, y=e.reason))


def handle_enumeration(args: argparse.Namespace, protocol: str) -> None:
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
        print("[+] Writing results to header_data.txt, this may take some time...")
        execute(make_request, args.threads, args.uni, True)
    else:
        print("\n[+] Sending requests and awaiting responses...\n")
        execute(make_request, args.threads, args.uni)
    print(TerminalColours.OKGREEN + "\n[+] Processes complete\n")


def handle_single_request(args: argparse.Namespace, url: str) -> None:
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
        if args.uni:
            print(TerminalColours.OKGREEN + "\n[+] Inspecting responses for header '{}'".format(args.uni))
            print(TerminalColours.OKGREEN + "[+] Writing results to output file...\n\n")
            write_file_uni(headers, args.uni, url)
        else:
            write_file(headers, url)
    else:
        if args.uni:
            print("\n[+] Inspecting responses for header '{}'\n".format(args.uni))
            write_stdout_uni(headers, args.uni, url)
        else:
            write_stdout(headers, url)
    print(TerminalColours.OKGREEN + "\n[+] Processes complete\n")


def main() -> None:
    """
    Main method for the HeaderSpy tool
    """
    args = get_args()
    protocol = "https://" if args.secure else "http://"
    url = "{x}{y}".format(x=protocol, y=args.domain)
    try:
        if args.enum_sub:
            handle_enumeration(args, protocol)
        else:
            handle_single_request(args, url)
    except urllib.error.URLError as e:
        print(TerminalColours.FAIL + "[-] {x}: {y}".format(x=url, y=e.reason))


if __name__ == "__main__":
    main()
