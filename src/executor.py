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
from typing import List

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
        """
        Class constructor

        Args:
            args (argparse.Namespace): cmd args
        """
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

    def make_request(self, url: str) -> HTTPMessage:
        """
        Send a get request to the url passed in and return
        the headers in the response

        Args:
            url (str): url to analyse headers for
        Returns:
            HTTPMessage: http response object
        """
        with urllib.request.urlopen(url, timeout=10) as conn:
            return conn.info()

    def update_domains(self) -> List:
        """
        Populate the deque with urls using words from
        subdomains-10000.txt

        Returns:
            List: list of subdomains
        """
        try:
            with open(self.word_list, 'r', encoding="utf-8") as file:
                words = file.read().splitlines()
                sub_d = [f"{self.protocol}{w}.{self.domain}" for w in words]
                # add root domain to list
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
            output (bool):          write headers to file if True
            response (HTTPMessage): response from HTTP GET request
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

    def execute(self, sub_d: List, output=False) -> None:
        """
        Creates a thread pool with <args.threads> number
        of threads for making parallel requests

        Args:
            sub_d (List):    list of subdomains
            output (bool):   write headers to file if True
        """
        with ThreadPoolExecutor(max_workers=self.threads) as e:
            future_to_url = {e.submit(self.make_request, s): s for s in sub_d}
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
        """
        sub_d = self.update_domains()
        if self.output:
            print("\n[+] Sending requests and awaiting responses...")
            print(
                f"[+] Writing results to {self.output}, this may take some time...\n")
            if not self.enum_sub:
                uni_file_heading(self.uni, self.domain, self.output, False)
            self.execute(sub_d, True)
        else:
            print("\n[+] Sending requests and awaiting responses...\n")
            self.execute(sub_d)
        print(TerminalColours.GREEN + "\n[+] Processes complete\n")

    def handle_single_domain(self) -> None:
        """
        Perform all necessary actions when the user has
        specified that only a single domain should be
        inspected
        """
        headers = self.make_request(self.url)
        if self.output:
            print("\n[+] Sending requests and awaiting responses...")
            if self.uni:
                print(TerminalColours.GREEN +
                      f"[+] Inspecting responses for header '{self.uni}'")
                print(TerminalColours.GREEN +
                      f"[+] Writing results to {self.output}...")
                uni_file_heading(self.uni, self.url, self.output)
            else:
                print(f"[+] Writing results to {self.output}...")
                write_file(headers, self.url, self.verbose, self.output)
        else:
            if self.uni:
                print(
                    f"\n[+] Inspecting responses for header '{self.uni}'\n")
                write_stdout_uni(headers, self.uni, self.url)
            else:
                write_stdout(headers, self.url, self.verbose)
        print(TerminalColours.GREEN + "\n[+] Processes complete\n")
