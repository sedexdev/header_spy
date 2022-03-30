#!/usr/bin/bash python

import argparse
import os
import pwd
import sys
import urllib.request
import urllib.error

from colours import TerminalColours
from concurrent.futures import as_completed, ThreadPoolExecutor
from http.client import HTTPMessage
from socket import timeout
from typing import Callable, List

from output import (
    uni_file_heading,
    write_file_uni,
    write_file,
    write_stdout_uni,
    write_stdout
)


def add_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """
    Adds arguments to an instance of argparse.ArgumentParser
    then returns the generated Namespace object

    Args:
        parser (argparse.ArgumentParser): argument parsing object
    Returns:
        argparse.ArgumentParser: argument parsing object
    """
    parser.add_argument("-d", "--domain", dest="domain", help="Web domain whose headers you want to inspect")
    parser.add_argument("-e", "--enum_sub", action="store_true", help="Enumerate subdomains from this domain")
    parser.add_argument("-o", "--output", dest="output", help="Path of save location for output file")
    parser.add_argument("-s", "--secure", action="store_true", help="Send requests using HTTPS")
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help="Number of threads to use to enumerate subdomains. Default is 10",
        default=10,
        type=int)
    parser.add_argument("-u", "--uni-header", dest="uni", help="Display which responses contain a specific header")
    parser.add_argument("-v", "--verbose", action="store_true", help="Outputs additional details")
    parser.add_argument("-w", "--word-list", dest="word_list", help="Word list path for subdomain enumeration")
    return parser


def verify_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """
    Check Namespace object to verify that the arguments
    passed in by the user are coherent

    Args:
        args (argparse.Namespace)        : terminal arguments from user
        parser (argparse.ArgumentParser) : argument parsing object
    """
    if not args.domain:
        parser.error("\n\n[-] Expected a domain for the HTTP GET request\n")
    if args.enum_sub and not args.word_list:
        parser.error("\n\n[-] Cannot enumerate subdomains without a word list (use -w, see --help for details)\n")
    if os.path.isdir(args.output):
        parser.error(f"\n\n[-] Cannot write over directory '{args.output}', provide a filename for output file\n")


def get_args() -> argparse.Namespace:
    """
    Gets command line arguments from the user

    Returns:
        argparse.Namespace: terminal arguments from user
    """
    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()
    verify_args(args, parser)
    return args


def get_source_path(path: str) -> str:
    """
    Get the path to the word list file that is going to be
    used for subdomain enumeration

    Args:
        path (str): the file path provided by the user
    Returns:
        str: full path the supplied word list
    """
    if os.path.isabs(path):
        return path
    return os.path.join(os.getcwd(), path)


def make_request(url: str) -> HTTPMessage:
    """
    Send a get request to the url passed in and return
    the headers in the response

    Args:
        url (str): url to send GET request to
    Returns:
        HTTPMessage: http response object
    """
    with urllib.request.urlopen(url, timeout=30) as conn:
        return conn.info()


def update_domains(domain: str, word_list: str, protocol: str) -> List:
    """
    Populate the deque with urls using words from
    subdomains-10000.txt

    Args:
        domain (str)    : the domain passed in by the user
        word_list (str) : a word list for subdomain enumeration
        protocol (str)  : protocol to use for the request
    Returns:
        List: list of subdomains
    """
    try:
        with open(word_list, 'r') as file:
            words = file.read().splitlines()
            sub_d = ["{x}{y}.{z}".format(x=protocol, y=word, z=domain) for word in words]
            sub_d = ["{x}{y}".format(x=protocol, y=domain)] + sub_d
            return sub_d
    except FileNotFoundError:
        print(f"\n[-] Bad path. Word list not found at {word_list}\n")
        sys.exit(1)


def handle_output(output: bool, args: argparse.Namespace, response: HTTPMessage, url: str) -> None:
    """
    Processes responses by sending data to the correct
    output function depending on input provided by the
    user

    Args:
        output (bool)             : write headers to file if True
        args (argparse.Namespace) : arguments provided by the user
        response (HTTPMessage)    : response from HTTP GET request
        url (str)                 : url to send the HTTP GET request to
    """
    if output:
        if args.uni:
            write_file_uni(response, args.uni, url, args.output)
        else:
            write_file(response, url, args.verbose, args.output)
    else:
        if args.uni:
            write_stdout_uni(response, args.uni, url)
        else:
            write_stdout(response, url, args.verbose)


def execute(func: Callable, args: argparse.Namespace, sub_d: List, output=False) -> None:
    """
    Creates a thread pool with <args.threads> number
    of threads for making parallel requests

    Args:
        func (Callable)           : function for thread to call
        args (argparse.Namespace) : arguments provided by the user
        sub_d (List)              : list of subdomains
        output (bool)             : write headers to file if True
    """
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(func, s): s for s in sub_d}
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
        args (argParse.Namespace) : command line args from the user
        protocol (str)            : protocol to use when sending requests
    """
    sub_d = update_domains(args.domain, args.word_list, protocol)
    if args.output:
        print("\n[+] Sending requests and awaiting responses...")
        print(f"[+] Writing results to {args.output}, this may take some time...\n")
        if not args.enum_sub:
            uni_file_heading(args.uni, args.domain, args.output, False)
        execute(make_request, args, sub_d, True)
    else:
        print("\n[+] Sending requests and awaiting responses...\n")
        execute(make_request, args, sub_d)
    print(TerminalColours.GREEN + "\n[+] Processes complete\n")


def handle_single(args: argparse.Namespace, url: str) -> None:
    """
    Perform all necessary actions when the user has
    specified that only a single domain should be
    inspected

    Args:
        args (argParse.Namespace) : command line args from the user
        url (str)                 : url to send the HTTP GET request to
    """
    headers = make_request(url)
    if args.output:
        print("\n[+] Sending requests and awaiting responses...")
        if args.uni:
            print(TerminalColours.GREEN + "[+] Inspecting responses for header '{}'".format(args.uni))
            print(TerminalColours.GREEN + f"[+] Writing results to {args.output}...")
            uni_file_heading(args.uni, url, args.output)
        else:
            print(f"[+] Writing results to {args.output}...")
            write_file(headers, url, args.verbose, args.output)
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
