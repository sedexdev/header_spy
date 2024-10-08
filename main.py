"""
Main module for Header Spy tool
"""

#!/usr/bin/bash python

import argparse
import os
import urllib.error

from src.colours import TerminalColours
from src.executor import Executor


def add_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """
    Adds arguments to an instance of argparse.ArgumentParser
    then returns the generated Namespace object

    Args:
        parser (argparse.ArgumentParser): argument parsing object
    Returns:
        argparse.ArgumentParser: argument parsing object
    """
    parser.add_argument("-d", "--domain", dest="domain",
                        help="Web domain whose headers you want to inspect")
    parser.add_argument("-e", "--enum-sub", action="store_true",
                        help="Enumerate subdomains from this domain")
    parser.add_argument("-o", "--output", dest="output",
                        help="Path of save location for output file")
    parser.add_argument("-s", "--secure", action="store_true",
                        help="Send requests using HTTPS")
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help="Number of threads to use to enumerate subdomains. Default is 10",
        default=10,
        type=int)
    parser.add_argument("-u", "--uni-header", dest="uni",
                        help="Display which responses contain a specific header")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Outputs additional details")
    parser.add_argument("-w", "--wordlist", dest="word_list",
                        help="Word list path for subdomain enumeration")
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
        parser.error("\n\n[-] Cannot enumerate subdomains without word list\n")
    if args.output is not None:
        if os.path.isdir(args.output):
            parser.error(f"\n\n[-] Path is directory: '{args.output}'\n")


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


def main() -> None:
    """
    Main method for the HeaderSpy tool
    """
    executor = Executor(get_args())
    try:
        if executor.enum_sub:
            executor.handle_multiple_domains()
        else:
            executor.handle_single_domain()
    except urllib.error.URLError as e:
        print(TerminalColours.RED + f"[-] {executor.url}: {e.reason}")


if __name__ == "__main__":
    main()
