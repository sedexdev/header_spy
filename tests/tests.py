"""
Header Spy tool test module
"""

import argparse
import os
import urllib.error

from types import SimpleNamespace

import pytest

from main import create_parser, verify_args
from src.executor import Executor


ARGS_SINGLE = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": False,
    "threads": None,
    "inspect": None,
    "verbose": False,
    "word_list": None
}
ARGS_SINGLE_SECURE = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": True,
    "threads": None,
    "inspect": None,
    "verbose": False,
    "word_list": None
}
ARGS_SINGLE_INSPECT = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": False,
    "threads": None,
    "inspect": "Strict-Transport-Security",
    "verbose": False,
    "word_list": None
}
ARGS_SINGLE_OUTPUT = {
    "domain": "127.0.0.1:5000",
    "output": "test_scan.txt",
    "secure": False,
    "threads": None,
    "inspect": None,
    "verbose": False,
    "word_list": None
}
ARGS_SINGLE_VERBOSE = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": False,
    "threads": None,
    "inspect": None,
    "verbose": True,
    "word_list": None
}
ARGS_MULTI = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": False,
    "threads": None,
    "inspect": None,
    "verbose": False,
    "word_list": "word_lists/subdomains-100.txt"
}
ARGS_MULTI_SECURE = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": True,
    "threads": None,
    "inspect": None,
    "verbose": False,
    "word_list": "word_lists/subdomains-100.txt"
}
ARGS_MULTI_INSPECT = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": False,
    "threads": None,
    "inspect": "Strict-Transport-Security",
    "verbose": False,
    "word_list": "word_lists/subdomains-100.txt"
}
ARGS_MULTI_OUTPUT = {
    "domain": "127.0.0.1:5000",
    "output": "test_scan.txt",
    "secure": False,
    "threads": None,
    "inspect": None,
    "verbose": False,
    "word_list": "word_lists/subdomains-100.txt"
}
ARGS_MULTI_VERBOSE = {
    "domain": "127.0.0.1:5000",
    "output": None,
    "secure": False,
    "threads": None,
    "inspect": None,
    "verbose": True,
    "word_list": "word_lists/subdomains-100.txt"
}


class TestParser:
    """
    Tests the available options of the argparse parser
    """

    @classmethod
    def setup_class(cls) -> None:
        """
        Class setup runs before any tests
        """
        cls.parser = create_parser(argparse.ArgumentParser())

    @classmethod
    def teardown_class(cls) -> None:
        """
        Class teardown after all tests
        """
        cls.parser = None
        os.remove("test_parser.txt")

    def setup_method(self) -> None:
        """
        Method setup called before each test
        """
        self.parser = create_parser(argparse.ArgumentParser())

    def teardown_method(self) -> None:
        """
        Method teardown called after each test
        """
        self.parser = None

    def test_parser_domain_is_collected_correctly(self) -> None:
        """
        Assert the -d, --domain switch assigns value to 'domain'
        """
        self.parser = self.parser.parse_args(["-d", "test.com"])
        assert self.parser.domain == "test.com"

    def test_parser_output_is_collected_correctly(self) -> None:
        """
        Assert the -o, --output switch assigns value to 'output'
        """
        self.parser = self.parser.parse_args(["-o", "test_parser.txt"])
        assert self.parser.output == "test_parser.txt"

    def test_parser_secure_is_collected_correctly(self) -> None:
        """
        Assert the -s, --secure switch assigns value to 'secure'
        """
        self.parser = self.parser.parse_args(["-s"])
        assert self.parser.secure

    def test_parser_threads_is_collected_correctly(self) -> None:
        """
        Assert the -t, --threads switch assigns value to 'threads'
        """
        self.parser = self.parser.parse_args(["-t", "20"])
        assert self.parser.threads == 20

    def test_parser_inspect_is_collected_correctly(self) -> None:
        """
        Assert the -i, --inspect-header switch assigns value to 'inspect'
        """
        self.parser = self.parser.parse_args(
            ["-i", "Strict-Transport-Security"])
        assert self.parser.inspect == "Strict-Transport-Security"

    def test_parser_verbose_is_collected_correctly(self) -> None:
        """
        Assert the -v, --verbose switch assigns value to 'verbose'
        """
        self.parser = self.parser.parse_args(["-v"])
        assert self.parser.verbose

    def test_parser_wordlist_is_collected_correctly(self) -> None:
        """
        Assert the -w, --wordlist switch assigns value to 'word_list'
        """
        self.parser = self.parser.parse_args(
            ["-w", "word_lists/subdomains-100.txt"])
        assert self.parser.word_list == "word_lists/subdomains-100.txt"

    def test_verify_args_throws_error_without_domain(self, capsys) -> None:
        """
        Assert non-zero exit code and message if domain not passed in
        """
        args = self.parser.parse_args(["-o", "test_scan.txt", "-v"])
        with pytest.raises(SystemExit) as error:
            verify_args(args, self.parser)
        _, msg = capsys.readouterr()
        assert error.value.code != 0 and "[-] Expected a domain" in msg

    def test_verify_args_throws_error_with_dir_as_path(self, capsys) -> None:
        """
        Asserts non-zero exit code and message if -o is a directory
        """
        args = self.parser.parse_args(["-d", "test.com", "-o", ".", "-v"])
        with pytest.raises(SystemExit) as error:
            verify_args(args, self.parser)
        _, msg = capsys.readouterr()
        assert error.value.code != 0 and "[-] Path is directory" in msg

    def test_verify_args_throws_error_with_non_empty_file(self, capsys) -> None:
        """
        Asserts non-zero exit code and message if -o is a directory
        """
        with open("test_parser.txt", "w", encoding="utf-8") as file:
            file.write("TESTING")
        args = self.parser.parse_args(
            ["-d", "test.com", "-o", "test_parser.txt", "-v"])
        with pytest.raises(SystemExit) as error:
            verify_args(args, self.parser)
        _, msg = capsys.readouterr()
        assert error.value.code != 0 and "[-] Path exists and is not empty" in msg


class TestExecutor:
    """
    Executor module test class
    """

    @classmethod
    def setup_class(cls) -> None:
        """
        Class setup runs before any tests
        """
        cls.single = Executor(SimpleNamespace(**ARGS_SINGLE))
        cls.single_secure = Executor(SimpleNamespace(**ARGS_SINGLE_SECURE))
        cls.single_inspect = Executor(SimpleNamespace(**ARGS_SINGLE_INSPECT))
        cls.single_output = Executor(SimpleNamespace(**ARGS_SINGLE_OUTPUT))
        cls.single_verbose = Executor(SimpleNamespace(**ARGS_SINGLE_VERBOSE))
        cls.multi = Executor(SimpleNamespace(**ARGS_MULTI))
        cls.multi_secure = Executor(SimpleNamespace(**ARGS_MULTI_SECURE))
        cls.multi_inspect = Executor(SimpleNamespace(**ARGS_MULTI_INSPECT))
        cls.multi_output = Executor(SimpleNamespace(**ARGS_MULTI_OUTPUT))
        cls.multi_verbose = Executor(SimpleNamespace(**ARGS_MULTI_VERBOSE))

    @classmethod
    def teardown_class(cls) -> None:
        """
        Class teardown after all tests
        """
        cls.single = None
        cls.single_secure = None
        cls.single_inspect = None
        cls.single_output = None
        cls.single_verbose = None
        cls.multi = None
        cls.multi_secure = None
        cls.multi_inspect = None
        cls.multi_output = None
        cls.multi_verbose = None

    def teardown_method(self) -> None:
        """
        Method teardown called after each test
        """
        # clean up the output file if it was created during testing
        try:
            os.remove("test_scan.txt")
        except FileNotFoundError:
            pass

    def test_single_domain_scan_returns_missing_headers(self, capsys) -> None:
        """
        Assert test headers are not in missing headers returned
        """
        self.single.handle_single()
        out, _ = capsys.readouterr()
        assert \
            "[+] Received response from http://127.0.0.1:5000" in out and \
            "[-] Response is missing the following security headers:" in out and \
            "Cross-Origin-Resource-Policy" in out

    def test_single_domain_secure_scan_uses_https(self) -> None:
        """
        Assert request uses HTTPS - this will raise an exception on localhost
        """
        with pytest.raises(urllib.error.URLError) as error:
            self.single_secure.handle_single()
        assert \
            self.single_secure.protocol == "https://" and \
            "[SSL: WRONG_VERSION_NUMBER]" in str(error.value.reason)

    def test_single_domain_inspect_checks_for_given_header(self, capsys) -> None:
        """
        Assert correct message sent to stdout and result contains header
        """
        self.single_inspect.handle_single()
        out, _ = capsys.readouterr()
        assert \
            "[+] Results when scanning 127.0.0.1:5000 for 'Strict-Transport-Security'" in out and \
            "[+] http://127.0.0.1:5000" in out

    def test_single_domain_output_writes_out_to_files(self) -> None:
        """
        Assert output written to test_scan.txt
        """
        self.single_output.handle_single()
        with open("test_scan.txt", "r", encoding="utf-8") as file:
            output = file.read()
        assert \
            "[+] Received response from http://127.0.0.1:5000" in output and \
            "[-] Response is missing the following security headers:" in output and \
            "Cross-Origin-Resource-Policy" in output

    def test_single_domain_verbose_provides_additional_information(self, capsys) -> None:
        """
        Assert that the verbose switch provides additional data on missing headers
        """
        self.single_verbose.handle_single()
        out, _ = capsys.readouterr()
        assert \
            "[+] Verbose output" in out and \
            "Description" in out and \
            "--- POTENTIAL VULNERABILITIES ---" in out and \
            "OWASP Web Link" in out

    def test_multi_domain_scan_returns_missing_headers(self, capsys) -> None:
        """
        Assert test headers are not in missing headers returned
        """
        self.multi.handle_multiple()
        out, _ = capsys.readouterr()
        assert \
            "[+] Received response from http://127.0.0.1:5000" in out and \
            "[-] Response is missing the following security headers:" in out and \
            "Cross-Origin-Resource-Policy" in out and \
            "http://ftp.127.0.0.1:5000" in out and \
            "http://ipv4.127.0.0.1:5000" in out and \
            "http://api.127.0.0.1:5000" in out

    def test_multi_domain_secure_scan_uses_https(self, capsys) -> None:
        """
        Assert request uses HTTPS
        """
        self.multi_secure.handle_multiple()
        out, _ = capsys.readouterr()
        assert \
            self.multi_secure.protocol == "https://" and \
            "[SSL: WRONG_VERSION_NUMBER]" in out

    def test_multi_domain_inspect_checks_for_given_header(self, capsys) -> None:
        """
        Assert correct message sent to stdout and result contains header
        """
        self.multi_inspect.handle_multiple()
        out, _ = capsys.readouterr()
        assert \
            "[+] Results when scanning 127.0.0.1:5000 for 'Strict-Transport-Security'" in out and \
            "[+] http://127.0.0.1:5000" in out and \
            "http://ftp.127.0.0.1:5000" in out and \
            "http://ipv4.127.0.0.1:5000" in out and \
            "http://api.127.0.0.1:5000" in out

    def test_multi_domain_output_writes_out_to_files(self) -> None:
        """
        Assert output written to test_scan.txt
        """
        self.multi_output.handle_multiple()
        with open("test_scan.txt", "r", encoding="utf-8") as file:
            output = file.read()
        assert \
            "[+] Received response from http://127.0.0.1:5000" in output and \
            "[-] Response is missing the following security headers:" in output and \
            "Cross-Origin-Resource-Policy" in output

    def test_multi_domain_verbose_provides_additional_information(self, capsys) -> None:
        """
        Assert that the verbose switch provides additional data on missing headers
        """
        self.multi_verbose.handle_multiple()
        out, _ = capsys.readouterr()
        assert \
            "[+] Verbose output" in out and \
            "Description" in out and \
            "--- POTENTIAL VULNERABILITIES ---" in out and \
            "OWASP Web Link" in out
