"""Tests for executor.py"""

# pylint: disable=line-too-long, redefined-outer-name

import argparse

from argparse import Namespace

from http.client import HTTPMessage
from unittest.mock import patch, MagicMock, mock_open

import pytest

from utils.executor import Executor


@pytest.fixture
def mock_args() -> Namespace:
    """
    Pytest fixture for mock arguments
    """
    return argparse.Namespace(
        domain='example.com',
        output=None,
        secure=False,
        threads=10,
        inspect=None,
        verbose=False,
        word_list=None
    )


def test_executor_init(mock_args: Namespace) -> None:
    """
    Tests the Executor class constructor

    Args:
        mock_args (Namespace): mock Namespace object
    """
    executor = Executor(mock_args)
    assert executor.domain == 'example.com'
    assert executor.protocol == 'http://'


def test_get_urls(mock_args: Namespace) -> None:
    """
    Tests the get_urls method

    Args:
        mock_args (Namespace): mock Namespace object
    """
    mock_args.word_list = 'wordlist.txt'
    executor = Executor(mock_args)
    m_open = mock_open(read_data='sub1\nsub2')
    with patch('builtins.open', m_open):
        urls = executor.get_urls()
        assert 'http://example.com' in urls
        assert 'http://sub1.example.com' in urls
        assert 'http://sub2.example.com' in urls


@patch('urllib.request.urlopen')
def test_make_request(mock_urlopen: MagicMock, mock_args: Namespace) -> None:
    """
    Tests the make_request method

    Args:
        mock_urlopen (MagicMock): mock urlopen 
        mock_args (Namespace): mock Namespace object
    """
    mock_response = MagicMock()
    mock_response.info.return_value = HTTPMessage()
    mock_urlopen.return_value.__enter__.return_value = mock_response

    executor = Executor(mock_args)
    response = executor.make_request('http://example.com')
    assert isinstance(response, HTTPMessage)


def test_parse_headers(mock_args: Namespace) -> None:
    """
    Tests the parse_headers method

    Args: 
        mock_args (Namespace): mock Namespace object
    """
    executor = Executor(mock_args)
    mock_response = HTTPMessage()
    mock_response.add_header('Content-Type', 'text/html')
    mock_response.add_header('X-Frame-Options', 'SAMEORIGIN')

    missing = executor.parse_headers(mock_response)
    assert 'Strict-Transport-Security' in missing
    assert 'X-Frame-Options' not in missing


@patch('utils.executor.Executor.make_request')
@patch('utils.executor.Executor.handle_output')
def test_handle_single(mock_handle_output: MagicMock, mock_make_request: MagicMock, mock_args: Namespace) -> None:
    """
    Tests the handle_single method

    Args:
        mock_handle_output (MagicMock): mock handle_output
        mock_make_request (MagicMock): mock make_request
        mock_args (Namespace): mock Namespace object
    """
    mock_response = HTTPMessage()
    mock_handle_output.return_value = mock_response

    executor = Executor(mock_args)
    with patch.object(executor, 'make_request', return_value=mock_response) as mock_make_request:
        executor.handle_single()

    mock_make_request.assert_called_with('http://example.com')
    mock_handle_output.assert_called_once()


@patch('utils.executor.Executor.get_urls')
@patch('utils.executor.Executor.execute')
def test_handle_multiple(mock_execute: MagicMock, mock_get_urls: MagicMock, mock_args: Namespace) -> None:
    """
    Tests the handle_multiple method

    Args:
        mock_execute (MagicMock): mock execute
        mock_get_urls (MagicMock): mock get_urls
        mock_args (Namespace): mock Namespace object
    """
    mock_args.word_list = 'wordlist.txt'

    executor = Executor(mock_args)
    with patch.object(executor,
                      'get_urls',
                      return_value=[
                          'http://example.com',
                          'http://sub.example.com'
                      ]
                      ) as mock_get_urls:
        executor.handle_multiple()

    mock_get_urls.assert_called_once()
    mock_execute.assert_called_with(
        ['http://example.com', 'http://sub.example.com']
    )
