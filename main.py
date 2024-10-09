"""
Main module for Header Spy tool
"""

#!/usr/bin/bash python

import argparse
import os
import urllib.error

from src.colours import TerminalColours
from src.executor import Executor


def create_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
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
    parser.add_argument("-o", "--output", dest="output",
                        help="Absolute or relative path to file to send output to")
    parser.add_argument("-s", "--secure", action="store_true",
                        help="Send requests using HTTPS")
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help="Number of threads to use to enumerate subdomains. Default is 10",
        default=10,
        type=int)
    parser.add_argument("-i", "--inspect-header", dest="inspect",
                        help="Highlight which responses contain a specific header")
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
    if args.output is not None:
        if os.path.isdir(args.output):
            parser.error(f"\n\n[-] Path is directory: '{args.output}'\n")
        if os.path.exists(args.output) and os.path.getsize(args.output) > 0:
            parser.error("\n\n[-] Path exists and is not empty, aborting\n")



def get_args() -> argparse.Namespace:
    """
    Gets command line arguments from the user

    Returns:
        argparse.Namespace: terminal arguments from user
    """
    parser = argparse.ArgumentParser()
    create_parser(parser)
    args = parser.parse_args()
    verify_args(args, parser)
    return args


def main() -> None:
    """
    Main method for the HeaderSpy tool
    """
    executor = Executor(get_args())
    try:
        if executor.word_list is None:
            executor.handle_single()
        else:
            executor.handle_multiple()
    except urllib.error.URLError as e:
        print(TerminalColours.RED + f"[-] {executor.domain}: {e.reason}")


if __name__ == "__main__":
    main()
