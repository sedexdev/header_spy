"""
Tests for output.py
"""

# pylint: disable=line-too-long, redefined-outer-name

import re
from unittest.mock import patch, mock_open, MagicMock

import pytest

from utils.output import HeaderSpyIO


@pytest.fixture
def header_spy_io() -> HeaderSpyIO:
    """
    Pytest fixture for HeaderSpyIO

    Returns:
        HeaderSpyIO: HeaderSpyIO instance
    """
    return HeaderSpyIO()


@pytest.fixture
def mock_data() -> dict:
    """
    Pytest fixture for mock data

    Returns:
        dict: mock test data
    """
    return {
        "url": "http://example.com",
        "response": "HTTP/1.1 200 OK\nContent-Type: text/html",
        "missing_headers": ["Strict-Transport-Security"],
        "inspect_header": "X-Frame-Options"
    }


def test_write_file(header_spy_io: HeaderSpyIO, mock_data: dict) -> None:
    """
    Tests the write_file method

    Args:
        header_spy_io (HeaderSpyIO): HeaderSpyIO instance 
        mock_data (dict): mock test data
    """
    m_open = mock_open()
    with patch('builtins.open', m_open):
        header_spy_io.write_file(mock_data, 'output.txt')
        handle = m_open()
        handle.write.assert_any_call(
            "[+] Received response from http://example.com\n\n")
        handle.write.assert_any_call(
            "[-] Response is missing the following security headers:\n")


def remove_ansi_codes(text: str) -> str:
    """
    Output cleansing function to remove ANSI codes from text

    Args:
        text (str): text to clean
    Returns:
        str: sanitized text
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


@patch('sys.stdout.write')
def test_write_stdout(mock_stdout_write: MagicMock, header_spy_io: HeaderSpyIO, mock_data: dict) -> None:
    """
    Tests the write_stdout method

    Args:
        mock_stdout_write (MagicMock): mock std_write
        header_spy_io (HeaderSpyIO): HeaderSpyIO instance
        mock_data (dict): mock test data
    """
    header_spy_io.write_stdout(mock_data)
    # A bit tricky to assert colours, so we check for parts of the output
    output = "".join(call[0][0] for call in mock_stdout_write.call_args_list)
    cleaned_output = remove_ansi_codes(output)
    assert "[+] Received response from http://example.com" in cleaned_output
    assert "[-] Response is missing the following security headers:" in cleaned_output


def test_write_verbose(header_spy_io: HeaderSpyIO) -> None:
    """
    Tests the write_verbose method

    Args:
        header_spy_io (HeaderSpyIO): HeaderSpyIO instance
    """
    m_open = mock_open()
    with patch('builtins.open', m_open):
        header_spy_io.write_verbose(
            ["Strict-Transport-Security"], 'output.txt')
        handle = m_open()
        handle.write.assert_any_call("Header: Strict-Transport-Security\n")


@patch('sys.stdout.write')
def test_write_verbose_stdout(mock_stdout_write: MagicMock, header_spy_io: HeaderSpyIO) -> None:
    """
    Tests the write_verbose_stdout method

    Args:
        mock_stdout_write (MagicMock): mock std_write
        header_spy_io (HeaderSpyIO): HeaderSpyIO instance
    """
    header_spy_io.write_verbose_stdout(["X-Frame-Options"])
    output = "".join(call[0][0] for call in mock_stdout_write.call_args_list)
    cleaned_output = remove_ansi_codes(output)
    assert "Header: X-Frame-Options" in cleaned_output


def test_write_inspection(header_spy_io: HeaderSpyIO, mock_data: dict) -> None:
    """
    Tests the write_inspection method

    Args:
        header_spy_io (HeaderSpyIO): HeaderSpyIO instance
        mock_data (dict): mock test data
    """
    m_open = mock_open()
    mock_data["missing_headers"].append("X-Frame-Options")
    with patch('builtins.open', m_open):
        header_spy_io.write_inspection(mock_data, 'output.txt')
        handle = m_open()
        handle.write.assert_called_with("[-] http://example.com\n")


@patch('sys.stdout.write')
def test_write_inspection_stdout_missing(mock_stdout_write: MagicMock, header_spy_io: HeaderSpyIO, mock_data: dict) -> None:
    """
    Tests the write_inspection_stdout method when a header is missing

    Args:
        mock_stdout_write (MagicMock): mock std_write
        header_spy_io (HeaderSpyIO): HeaderSpyIO instance
        mock_data (dict): mock test data
    """
    mock_data["missing_headers"].append("X-Frame-Options")
    header_spy_io.write_inspection_stdout(mock_data)
    output = "".join(call[0][0] for call in mock_stdout_write.call_args_list)
    cleaned_output = remove_ansi_codes(output)
    assert "[-] http://example.com" in cleaned_output


@patch('sys.stdout.write')
def test_write_inspection_stdout_present(mock_stdout_write: MagicMock, header_spy_io: HeaderSpyIO, mock_data: dict) -> None:
    """
    Tests the write_inspection_stdout method when a header is present

    Args:
        mock_stdout_write (MagicMock): mock std_write
        header_spy_io (HeaderSpyIO): HeaderSpyIO instance
        mock_data (dict): mock test data
    """
    header_spy_io.write_inspection_stdout(mock_data)
    output = "".join(call[0][0] for call in mock_stdout_write.call_args_list)
    cleaned_output = remove_ansi_codes(output)
    assert "[+] http://example.com" in cleaned_output
