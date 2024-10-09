"""
Output handling module    
"""

# pylint: disable=line-too-long

import sys

from src.colours import TerminalColours
from src.secure_headers import (
    StrictTransportSecurity,
    XFrameOptions,
    XContentTypeOptions,
    ContentSecurityPolicy,
    XPermittedCrossDomainPolicies,
    ReferrerPolicy,
    PermissionsPolicy,
    ClearSiteData,
    CrossOriginEmbedderPolicy,
    CrossOriginOpenerPolicy,
    CrossOriginResourcePolicy,
    CacheControl
)


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


class HeaderSpyIO:
    """
    File and output processing behaviour
    """

    def __init__(self):
        self.file_heading = False
        self.stdout_heading = False

    def write_file(self, data: dict, file_path: str) -> None:
        """
        Writes the output to a file defined by self.file_path

        Args:
            data (dict)     : scan data
            file_path (str) : output file path
        """
        try:
            with open(file_path, 'a', encoding="utf-8") as file:
                file.write(f"[+] Received response from {data["url"]}\n\n")
                file.write(str(data["response"]))
                file.write("")
                if len(data["missing_headers"]):
                    file.write(
                        "[-] Response is missing the following security headers:\n")
                    file.write(f"\n{100 * "="}\n")
                    for h in data["missing_headers"]:
                        file.write(f"{h}\n")
                    file.write(f"{100 * "="}\n\n")
        except FileNotFoundError:
            print("\n[-] File write error, check output path\n")
            sys.exit(1)
        except PermissionError:
            print(
                f"\n[-] You do not have permission to write to '{file_path}'\n")
            sys.exit(1)

    def write_verbose(self, missing_headers: list, file_path: str) -> None:
        """
        Writes verbose descriptions of all the missing
        headers discovered during the scan to file

        Args:
            missing_headers (list) : missing header list
            file_path (str)        : output file path
        """
        try:
            with open(file_path, 'a', encoding="utf-8") as file:
                file.write("[+] Verbose output\n")
                for h in missing_headers:
                    file.write(f"\n{100 * "="}\n")
                    header_obj = SECURITY_HEADER_INSTANCES[h]
                    file.write(f"Header: {h}\n")
                    file.write(f"\nDescription: {
                               header_obj.get_description()}\n")
                    vulns = header_obj.get_vulnerabilities()
                    file.write("\n--- POTENTIAL VULNERABILITIES ---\n\n")
                    for v in vulns:
                        file.write(f"{v}: {vulns[v]}\n\n")
                    file.write(f"\nOWASP Web Link: {header_obj.get_link()}")
                    file.write(f"\n{100 * "="}\n\n")
        except FileNotFoundError:
            print("\n[-] File write error, check output path\n")
            sys.exit(1)
        except PermissionError:
            print(
                f"\n[-] You do not have permission to write to '{file_path}'\n")
            sys.exit(1)

    def write_header(self, header: str, file_path: str) -> None:
        """
        Writes a heading at the top of the file
        when a single header is being inspected 

        Args:
            header (str)    : header under inspection
            file_path (str) : output file path
        """
        if not self.file_heading:
            try:
                with open(file_path, 'a', encoding="utf-8") as file:
                    file.write(f"Results when scanning for '{header}'\n")
                    self.file_heading = True
            except FileNotFoundError:
                print("\n[-] File write error, check output path\n")
                sys.exit(1)
            except PermissionError:
                print(
                    f"\n[-] You do not have permission to write to '{file_path}'\n")
                sys.exit(1)

    def write_inspection(self, data: dict, file_path: str) -> None:
        """
        Writes a single line showing whether the header
        was present in the response or not

        Args:
            data (dict)     : scan data
            file_path (str) : output file path
        """
        try:
            with open(file_path, 'a', encoding="utf-8") as file:
                if data["inspect_header"] in data["missing_headers"]:
                    file.write(f"[-] {data["url"]}\n")
                else:
                    file.write(f"[+] {data["url"]}\n")
        except FileNotFoundError:
            print("\n[-] File write error, check output path\n")
            sys.exit(1)
        except PermissionError:
            print(
                f"\n[-] You do not have permission to write to '{file_path}'\n")
            sys.exit(1)

    def write_stdout(self, data: dict) -> None:
        """
        Writes the output to stdout

        Args:
            data (dict): data to be written
        """
        print(TerminalColours.GREEN +
              f"\n[+] Received response from {data["url"]}\n")
        print(TerminalColours.PURPLE + str(data["response"]), end="")
        if len(data["missing_headers"]):
            print(TerminalColours.YELLOW +
                  "[-] Response is missing the following security headers:\n")
            print(f"{100 * "="}")
            for h in data["missing_headers"]:
                print(TerminalColours.YELLOW + h)
            print(f"{100 * "="}\n")

    def write_verbose_stdout(self, missing_headers: list) -> None:
        """
        Send verbose descriptions of all the missing
        headers discovered during the scan to stdout

        Args:
            missing_headers (list): missing header list
        """
        print(TerminalColours.BLUE + "[+] Verbose output\n")
        for h in missing_headers:
            header_obj = SECURITY_HEADER_INSTANCES[h]
            print(TerminalColours.BLUE + f"{100 * "="}")
            print(TerminalColours.BLUE + f"Header: {h}")
            print(TerminalColours.BLUE +
                  f"\nDescription: {header_obj.get_description()}\n")
            vulns = header_obj.get_vulnerabilities()
            print(TerminalColours.BLUE + "--- POTENTIAL VULNERABILITIES ---\n")
            for v in vulns:
                print(TerminalColours.BLUE + f"{v}: {vulns[v]}\n")
            print(TerminalColours.BLUE +
                  f"\nOWASP Web Link: {header_obj.get_link()}")
            print(TerminalColours.BLUE + f"{100 * "="}\n")

    def write_header_stdout(self, header: str) -> None:
        """
        Sends a heading to the top of stdout
        when a single header is being inspected

        Args:
            header (str): header under inspection
        """
        if not self.stdout_heading:
            print(f"[+] Results when scanning for '{header}'\n")
            self.stdout_heading = True

    def write_inspection_stdout(self, data: dict) -> None:
        """
        Send additional data to the end of the stdout stream
        if the user has chosen to inspect a single header 
        during the scan

        Args:
            data (dict): scan data
        """
        if data["inspect_header"] in data["missing_headers"]:
            print(TerminalColours.RED + f"[-] {data["url"]}")
        else:
            print(TerminalColours.GREEN + f"[+] {data["url"]}")
