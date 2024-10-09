"""
Header Spy tool test module
"""

import argparse
import os

import pytest

from main import create_parser, verify_args
# from src.executor import Executor


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
        os.remove("test.txt")

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
        self.parser = self.parser.parse_args(["-o", "test.txt"])
        assert self.parser.output == "test.txt"

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
        args = self.parser.parse_args(["-o", "scan.txt", "-v"])
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
        with open("test.txt", "w", encoding="utf-8") as file:
            file.write("TESTING")
        args = self.parser.parse_args(
            ["-d", "test.com", "-o", "test.txt", "-v"])
        with pytest.raises(SystemExit) as error:
            verify_args(args, self.parser)
        _, msg = capsys.readouterr()
        assert error.value.code != 0 and "[-] Path exists and is not empty" in msg


# class TestExecutor:
#     """
#     Executor module test class
#     """

#     @classmethod
#     def setup_class(cls) -> None:
#         """
#         Class setup runs before any tests
#         """
#         cls.executor = Executor()

#     @classmethod
#     def teardown_class(cls) -> None:
#         """
#         Class teardown after all tests
#         """
#         cls.executor = None

#     def setup_method(self) -> None:
#         """
#         Method setup called before each test
#         """
#         self.executor = Executor()

#     def teardown_method(self) -> None:
#         """
#         Method teardown called after each test
#         """
#         self.executor = None
