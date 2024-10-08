"""
Executor module for core functionality
"""

# pylint: disable=line-too-long

import argparse
import sys
import urllib.request
import urllib.error

from concurrent.futures import as_completed, ThreadPoolExecutor

from http.client import HTTPMessage
from socket import timeout
from typing import Callable, List

from src.colours import TerminalColours
from src.output import (
    uni_file_heading,
    write_file_uni,
    write_file,
    write_stdout_uni,
    write_stdout
)


class Executor:
    """
    Class defining behaviour for header response
    analysis
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.domain = args.domain
        self.enum_sub = args.enum_sub
        self.output = args.output
        self.secure = args.secure
        self.threads = args.threads
        self.uni = args.uni
        self.verbose = args.verbose
        self.word_list = args.word_list
        self.protocol = "https://" if self.secure else "http://"
        self.url = f"{self.protocol}{self.domain}"

    def make_request(self) -> HTTPMessage:
        """
        Send a get request to the url passed in and return
        the headers in the response

        Args:
            url (str): url to send GET request to
        Returns:
            HTTPMessage: http response object
        """
        with urllib.request.urlopen(self.url, timeout=10) as conn:
            return conn.info()

    def update_domains(self) -> List:
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
            with open(self.word_list, 'r', encoding="utf-8") as file:
                words = file.read().splitlines()
                sub_d = [f"{self.protocol}{word}.{
                    self.domain}" for word in words]
                sub_d = [f"{self.protocol}{self.domain}"] + sub_d
                return sub_d
        except FileNotFoundError:
            print(
                f"\n[-] Bad path. Word list not found at {self.word_list}\n")
            sys.exit(1)

    def handle_output(self, output: bool, response: HTTPMessage) -> None:
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
            if self.uni:
                write_file_uni(response, self.uni, self.url, output)
            else:
                write_file(response, self.url, self.verbose, output)
        else:
            if self.uni:
                write_stdout_uni(response, self.uni, self.url)
            else:
                write_stdout(response, self.url, self.verbose)

    def execute(self, func: Callable, sub_d: List, output=False) -> None:
        """
        Creates a thread pool with <args.threads> number
        of threads for making parallel requests

        Args:
            func (Callable)           : function for thread to call
            args (argparse.Namespace) : arguments provided by the user
            sub_d (List)              : list of subdomains
            output (bool)             : write headers to file if True
        """
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(func, s): s for s in sub_d}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    response = future.result()
                    self.handle_output(output, response)
                except timeout as e:
                    if not output:
                        print(TerminalColours.RED + f"[-] {url}: {e}")
                except urllib.error.URLError as e:
                    if not output:
                        print(TerminalColours.RED + f"[-] {url}: {e.reason}")

    def handle_multiple_domains(self) -> None:
        """
        Perform all necessary actions when the user has
        specified that subdomains should be enumerated

        Args:
            args (argParse.Namespace) : command line args from the user
            protocol (str)            : protocol to use when sending requests
        """
        sub_d = self.update_domains()
        if self.output:
            print("\n[+] Sending requests and awaiting responses...")
            print(
                f"[+] Writing results to {self.output}, this may take some time...\n")
            if not self.enum_sub:
                uni_file_heading(self.uni, self.domain, self.output, False)
            self.execute(self.make_request, sub_d, True)
        else:
            print("\n[+] Sending requests and awaiting responses...\n")
            self.execute(self.make_request, self, sub_d)
        print(TerminalColours.GREEN + "\n[+] Processes complete\n")

    def handle_single_domain(self) -> None:
        """
        Perform all necessary actions when the user has
        specified that only a single domain should be
        inspected

        Args:
            args (argParse.Namespace) : command line args from the user
            url (str)                 : url to send the HTTP GET request to
        """
        headers = self.make_request()
        if self.output:
            print("\n[+] Sending requests and awaiting responses...")
            if self.uni:
                print(TerminalColours.GREEN +
                      f"[+] Inspecting responses for header '{self.uni}'")
                print(TerminalColours.GREEN +
                      f"[+] Writing results to {self.output}...")
                uni_file_heading(self.uni, self.url,
                                 self.output)
            else:
                print(f"[+] Writing results to {self.output}...")
                write_file(headers, self.url,
                           self.verbose, self.output)
        else:
            if self.uni:
                print(
                    f"\n[+] Inspecting responses for header '{self.uni}'\n")
                write_stdout_uni(headers, self.uni, self.url)
            else:
                write_stdout(headers, self.url, self.verbose)
        print(TerminalColours.GREEN + "\n[+] Processes complete\n")
