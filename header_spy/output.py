import sys

from colours import TerminalColours
from http.client import HTTPMessage
from secure_headers import *
from typing import List

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


def parse_headers(headers: HTTPMessage) -> dict:
    """
    Parse the response headers and their values into a
    dictionary
    """
    header_dict = dict()
    for header in str(headers).split("\n"):
        delimiter = header.find(":")
        key = header[:delimiter]
        value = header[delimiter + 2:]
        header_dict[key] = value
    return header_dict


def verify_security(headers_dict: dict) -> List:
    """
    Check the headers contained in the HTTP response against
    the list of security headers recommended by the OWASP
    Secure Headers Project

    Args:
        headers_dict (dict): dict of header names and descriptions
    Returns:
        List: a list of missing OWASP recommended security headers
    """
    found_headers = headers_dict.keys()
    missing_headers = [x for x in SECURITY_HEADERS if x not in found_headers]
    return missing_headers


def uni_file_heading(header: str, subdomain: str, file_path: str, single=True) -> None:
    """
    Write extra information at the start of the output file
    relating to the possible vulnerabilities that may exist
    as a result of the specified header not being present

    Args:
        header (str)    : the header being looked for
        subdomain (str) : url the request was sent to
        file_path (str) : output file path
        single (bool)   : states that a single domain is being inspected.
                          If False, subdomains are also being inspected
    """
    header_obj = SECURITY_HEADER_INSTANCES.get(header, None)
    vulns = header_obj.get_vulnerabilities() if header_obj else None
    try:
        with open(file_path, 'a') as file:
            if single:
                file.write("[*] Inspecting presence of {x} header in response from {y}\n".format(x=header, y=subdomain))
                file.write("[*] {} header not found\n".format(header))
            else:
                file.write("[*] Inspecting presence of {x} header in responses from {y} and "
                           "its subdomains\n".format(x=header, y=subdomain))
                file.write("[*] {} header not found in the domains listed below\n".format(header))
            file.write("\n[*] Missing {} header can lead to the following vulnerabilities:\n\n".format(header))
            if vulns:
                for v in vulns:
                    file.write("[*] {x}: {y}\n".format(x=v, y=vulns[v]))
            file.write("\n")
    except FileNotFoundError:
        print("\n[-] File write error, check output path\n")
        sys.exit(1)
    except PermissionError:
        print(f"\n[-] You do not have permission to write to '{file_path}'\n")
        sys.exit(1)


def verbose_write_file(secure_headers: List, file_path: str) -> None:
    """
    Write verbose output about the implications of
    each missing security header to stdout

    Args:
        secure_headers (List) : list of missing headers
        file_path (str)       : output file path
    """
    try:
        with open(file_path, 'a') as file:
            for sh in secure_headers:
                file.write("================================================"
                           "===============================================\n")
                header_obj = SECURITY_HEADER_INSTANCES[sh]
                file.write("Header: {}\n".format(sh))
                file.write("\nDescription: {}\n".format(header_obj.get_description()))
                vulns = header_obj.get_vulnerabilities()
                file.write("\n--- POTENTIAL VULNERABILITIES ---\n\n")
                for v in vulns:
                    file.write("{x}: {y}\n\n".format(x=v, y=vulns[v]))
                file.write("\nOWASP Web Link: {}".format(header_obj.get_link()))
                file.write("\n=================================================="
                           "=============================================\n\n")
    except FileNotFoundError:
        print("\n[-] File write error, check output path\n")
        sys.exit(1)
    except PermissionError:
        print(f"\n[-] You do not have permission to write to '{file_path}'\n")
        sys.exit(1)


def write_file_uni(headers: HTTPMessage, header: str, subdomain: str, file_path: str) -> None:
    """
    Write the results of an inspection for a single header to
    an output file if the header is not found in the response

    Args:
        headers (HTTPResponse) : response received from GET request
        header (str)           : the header being looked for
        subdomain (str)        : url the request was sent to
        file_path (str)        : output file path
    """
    header_dict = parse_headers(headers)
    found_headers = header_dict.keys()
    if header not in found_headers:
        try:
            with open(file_path, 'a') as file:
                file.write("{}\n".format(subdomain))
        except FileNotFoundError:
            print("\n[-] File write error, check output path\n")
            sys.exit(1)
        except PermissionError:
            print(f"\n[-] You do not have permission to write to '{file_path}'\n")
            sys.exit(1)


def write_file(headers: HTTPMessage, subdomain: str, verbose: bool, file_path: str) -> None:
    """
    Write the response headers to a file located at
    OUTPUT_FILE_PATH

    Args:
        headers (HTTPResponse) : response received from GET request
        subdomain (str)        : url the request was sent to
        verbose (bool)         : add additional information if True
        file_path (str)        : output file path
    """
    header_dict = parse_headers(headers)
    secure_headers = verify_security(header_dict)
    try:
        with open(file_path, 'a') as file:
            file.write("[+] Received response from {}\n\n".format(subdomain))
            file.write(str(headers))
            file.write("")
            if len(secure_headers):
                file.write("[-] Response is missing the following security headers:\n")
                file.write("\n=================================================="
                           "=============================================\n")
                for sh in secure_headers:
                    file.write("{}\n".format(sh))
                file.write("=================================================="
                           "=============================================\n\n")
        if verbose:
            verbose_write_file(secure_headers, file_path)
    except FileNotFoundError:
        print("\n[-] File write error, check output path\n")
        sys.exit(1)
    except PermissionError:
        print(f"\n[-] You do not have permission to write to '{file_path}'\n")
        sys.exit(1)


def verbose_write_stdout(secure_headers: List) -> None:
    """
    Write verbose output about the implications of
    each missing security header to stdout

    Args:
        secure_headers (List): list of missing headers
    """
    for sh in secure_headers:
        print(TerminalColours.BLUE + "================================================================"
                                     "===============================")
        header_obj = SECURITY_HEADER_INSTANCES[sh]
        print(TerminalColours.BLUE + "Header: {}".format(sh))
        print(TerminalColours.BLUE + "\nDescription: {}\n".format(header_obj.get_description()))
        vulns = header_obj.get_vulnerabilities()
        print(TerminalColours.BLUE + "--- POTENTIAL VULNERABILITIES ---\n")
        for v in vulns:
            print(TerminalColours.BLUE + "{x}: {y}\n".format(x=v, y=vulns[v]))
        print(TerminalColours.BLUE + "\nOWASP Web Link: {}".format(header_obj.get_link()))
        print(TerminalColours.BLUE + "================================================================"
                                     "===============================\n")


def write_stdout_uni(headers: HTTPMessage, header: str, subdomain: str) -> None:
    """
    Write the results of an inspection for a single header to stdout
    to show which responses do not contain the specified header

    Args:
        headers (HTTPResponse) : response received from GET request
        header (str)           : the header being looked for
        subdomain (str)        : url the request was sent to
    """
    header_dict = parse_headers(headers)
    found_headers = header_dict.keys()
    if header in found_headers:
        print(TerminalColours.GREEN + "[+] {}".format(subdomain))
    else:
        print(TerminalColours.RED + "[-] {}".format(subdomain))


def write_stdout(headers: HTTPMessage, subdomain: str, verbose: bool) -> None:
    """
    Write the response headers to stdout

    Args:
        headers (HTTPMessage) : response received from GET request
        subdomain (str)       : url the request was sent to
        verbose (bool)        : add additional information if True
    """
    header_dict = parse_headers(headers)
    print(TerminalColours.GREEN + "\n[+] Received response from {}\n".format(subdomain))
    print(TerminalColours.PURPLE + str(headers), end="")
    secure_headers = verify_security(header_dict)
    if len(secure_headers):
        print(TerminalColours.YELLOW + "[-] Response is missing the following security headers:\n")
        print("=======================================================")
        for sh in secure_headers:
            print(TerminalColours.YELLOW + sh)
        print("=======================================================\n")
        if verbose:
            verbose_write_stdout(secure_headers)
