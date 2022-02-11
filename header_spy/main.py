#!/usr/bin/bash python

import argparse
import urllib3


def get_args() -> argparse.Namespace:
    """
    Gets command line arguments from the user
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain", help="Web domain whose headers you want to inspect")
    args = parser.parse_args()
    if not args.domain:
        parser.error("\n\n[-] Expected a domain for the HTTP GET request\n")
    return args


def make_request(domain: str) -> urllib3.HTTPResponse:
    """
    Sends a HTTP GET request to the domain supplied
    by the user

    Args:
        domain (str): domain to send the request to
    """
    http = urllib3.PoolManager()
    return http.request('GET', domain)


def main() -> None:
    """
    Main method for the HeaderSpy tool
    """
    args = get_args()
    try:
        response = make_request(args.domain)
        headers = response.headers
        print(f"\n[+] Received response from {args.domain}")
        print("[+] Detected the following headers in the HTTP response:\n")
        for k in headers:
            print(f"{k}: {headers[k]}")
        print()
    except urllib3.exceptions.MaxRetryError:
        print("\n[-] Request timed out. Either the server is unresponsive or the domain is not valid\n")


if __name__ == "__main__":
    main()
