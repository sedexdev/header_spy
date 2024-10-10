"""
Executor module for core functionality
"""

# pylint: disable=line-too-long, too-many-instance-attributes

import argparse
import sys
import urllib.request
import urllib.error

from http.client import HTTPMessage
from concurrent.futures import as_completed, ThreadPoolExecutor
from socket import timeout
from typing import List

from src.colours import TerminalColours
from src.output import HeaderSpyIO


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


class Executor:
    """
    Class defining behaviour for header response
    analysis

    TODO
        - collect all missing headers from all requests
          when enumerating subdomains
        - fix write_header_stdout printing bug - since
          threads run at different times the heading is
          printed anywhere in the results
    """

    def __init__(self, args: argparse.Namespace):
        """
        Class constructor

        Args:
            args (argparse.Namespace): cmd args
        """
        self.domain = args.domain
        self.output = args.output
        self.secure = args.secure
        self.threads = args.threads
        self.inspect = args.inspect
        self.verbose = args.verbose
        self.word_list = args.word_list
        self.protocol = "https://" if self.secure else "http://"
        self.io = HeaderSpyIO()

    def get_urls(self) -> List:
        """
        Populate a list with urls using words from
        self.word_list

        Returns:
            List: list of subdomains
        """
        try:
            with open(self.word_list, 'r', encoding="utf-8") as file:
                words = file.read().splitlines()
                urls = [f"{self.protocol}{w}.{self.domain}" for w in words]
                # add root domain to list
                urls = [f"{self.protocol}{self.domain}"] + urls
                return urls
        except FileNotFoundError:
            print(f"\n[-] Bad path. Word list not found at {self.word_list}\n")
            sys.exit(1)

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

    def parse_headers(self, response: HTTPMessage) -> list:
        """
        Parse the missing response headers into a list

        Returns:
            list: list of missing headers
        """
        headers = []
        for row in str(response).split("\n"):
            delimiter = row.find(":")
            header = row[:delimiter]
            headers.append(header)
        return [x for x in SECURITY_HEADERS if x not in headers]

    def handle_header(self, header: str) -> None:
        """
        Writes the header data for a single header lookup to file 
        or sends it to stdout based on self.output

        Args:
            header (str): header being looked up
        """
        if self.output is not None:
            self.io.write_header(header, self.output)
        else:
            self.io.write_header_stdout(header)

    def handle_verbose(self, missing_headers: list) -> None:
        """
        Adds verbose output at the end of processing
        if requested by the user

        Args:
            missing_headers (list) : missing header list 
        """
        if self.verbose:
            if self.output is not None:
                self.io.write_verbose(missing_headers, self.output)
            else:
                self.io.write_verbose_stdout(missing_headers)

    def handle_output(self, data: dict) -> None:
        """
        Processes responses by sending data to the correct
        output function depending on input provided by the
        user

        Args:
            data (dict): scan data
        """
        if self.output is not None:
            if self.inspect is not None:
                self.io.write_inspection(data, self.output)
            else:
                self.io.write_file(data, self.output)
        else:
            # otherwise send to stdout
            if self.inspect is not None:
                self.io.write_inspection_stdout(data)
            else:
                self.io.write_stdout(data)

    def execute(self, urls: List) -> None:
        """
        Creates a thread pool with <args.threads> number
        of threads for making parallel requests

        TODO - need to collect all missing headers, not just from last request

        Args:
            urls (List): list of subdomains
        """
        with ThreadPoolExecutor(max_workers=self.threads) as e:
            future_to_url = {e.submit(self.make_request, s): s for s in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    response = future.result()
                    data = {
                        "inspect_header": self.inspect,
                        "url": url,
                        "response": response,
                        "missing_headers": self.parse_headers(response),
                    }
                    self.handle_output(data)
                except timeout as e:
                    print(TerminalColours.RED + f"[-] {url}: {e}")
                except urllib.error.URLError as e:
                    print(TerminalColours.RED + f"[-] {url}: {e.reason}")
        self.handle_verbose(data["missing_headers"])

    def handle_single(self) -> None:
        """
        Perform all necessary actions when the user has
        specified that only a single domain should be
        scanned
        """
        url = f"{self.protocol}{self.domain}"
        print("\n[+] Sending request and awaiting response...")
        if self.output is not None:
            print(f"[+] Writing results to '{self.output}'...")
        response = self.make_request(url)
        data = {
            "inspect_header": self.inspect,
            "url": url,
            "response": response,
            "missing_headers": self.parse_headers(response),
        }
        if self.inspect is not None:
            self.handle_header(self.inspect)
        self.handle_output(data)
        self.handle_verbose(data["missing_headers"])
        print(TerminalColours.GREEN + "\n[+] Scan complete\n")

    def handle_multiple(self) -> None:
        """
        Perform all necessary actions when the user has
        provided a word list of subdomains that will be
        enumerated while scanning
        """
        urls = self.get_urls()
        if self.inspect is not None:
            self.handle_header(self.inspect)
        print("\n[+] Sending requests and awaiting responses...\n")
        if self.output is not None:
            print(f"[+] Writing results to '{self.output}'...\n")
        self.execute(urls)
        print(TerminalColours.GREEN + "\n[+] Scan complete\n")
