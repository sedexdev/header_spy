"""
Tests for main.py
"""

import argparse

from unittest.mock import patch

import pytest

from main import create_parser, verify_args, get_args, main


def test_create_parser() -> None:
    """
    Tests the create_parser function
    """
    parser = argparse.ArgumentParser()
    create_parser(parser)
    args = parser.parse_args(['-d', 'example.com'])
    assert args.domain == 'example.com'
    assert args.threads == 10


def test_verify_args_no_domain() -> None:
    """
    Tests the verify_args function when no domain is provided
    """
    parser = argparse.ArgumentParser()
    create_parser(parser)
    args = parser.parse_args([])
    with pytest.raises(SystemExit):
        verify_args(args, parser)


@patch('argparse.ArgumentParser.parse_args')
def test_get_args(mock_parse_args) -> None:
    """
    Tests the get_args function
    """
    mock_parse_args.return_value = argparse.Namespace(
        domain='example.com',
        output=None,
        secure=False,
        threads=10,
        inspect=None,
        verbose=False,
        word_list=None
    )
    args = get_args()
    assert args.domain == 'example.com'


@patch('main.get_args')
@patch('main.Executor')
def test_main_single(mock_executor, mock_get_args) -> None:
    """
    Tests the main function for a single domain scan
    """
    mock_get_args.return_value = argparse.Namespace(word_list=None, domain='example.com')
    mock_executor.return_value.word_list = None
    main()
    mock_executor.return_value.handle_single.assert_called_once()


@patch('main.get_args')
@patch('main.Executor')
def test_main_multiple(mock_executor, mock_get_args) -> None:
    """
    Tests the main function for a multiple domain scan
    """
    mock_get_args.return_value = argparse.Namespace(word_list='some_list.txt', domain='example.com')
    mock_executor.return_value.word_list = 'some_list.txt'
    main()
    mock_executor.return_value.handle_multiple.assert_called_once()
