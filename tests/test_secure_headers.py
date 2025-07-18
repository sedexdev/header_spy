"""
Tests for secure_headers.py
"""

from collections import defaultdict

from typing import Type

import pytest

from utils.secure_headers import (
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
    CacheControl,
    SecureHeaderData
)

# A list of all header classes to be tested
HEADER_CLASSES = [
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
]


@pytest.mark.parametrize("header_class", HEADER_CLASSES)
def test_header_descriptions(header_class: Type[SecureHeaderData]) -> None:
    """
    Tests that each header class returns a description

    Args:
        header_class (Type[SecureHeaderData]): header class instance
    """
    instance = header_class()
    print(instance)
    assert isinstance(instance.get_description(), str)
    assert len(instance.get_description()) > 0


@pytest.mark.parametrize("header_class", HEADER_CLASSES)
def test_header_links(header_class: Type[SecureHeaderData]) -> None:
    """
    Tests that each header class returns a link

    Args:
        header_class (Type[SecureHeaderData]): header class instance
    """
    instance = header_class()
    assert isinstance(instance.get_link(), str)
    assert instance.get_link().startswith("https://owasp.org")


@pytest.mark.parametrize("header_class", HEADER_CLASSES)
def test_header_vulnerabilities(header_class: Type[SecureHeaderData]) -> None:
    """
    Tests that each header class returns vulnerability data

    Args:
        header_class (Type[SecureHeaderData]): header class instance
    """
    instance = header_class()
    vulns = instance.get_vulnerabilities()
    assert isinstance(vulns, defaultdict)
    assert len(vulns) > 0
    for key, value in vulns.items():
        assert isinstance(key, str)
        assert isinstance(value, str)
