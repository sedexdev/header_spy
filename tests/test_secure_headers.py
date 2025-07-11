"""
Tests for secure_headers.py
"""

from collections import defaultdict

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
    CacheControl
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
def test_header_descriptions(header_class):
    """
    Tests that each header class returns a description
    """
    instance = header_class()
    assert isinstance(instance.get_description(), str)
    assert len(instance.get_description()) > 0


@pytest.mark.parametrize("header_class", HEADER_CLASSES)
def test_header_links(header_class):
    """
    Tests that each header class returns a link
    """
    instance = header_class()
    assert isinstance(instance.get_link(), str)
    assert instance.get_link().startswith("https://owasp.org")


@pytest.mark.parametrize("header_class", HEADER_CLASSES)
def test_header_vulnerabilities(header_class):
    """
    Tests that each header class returns vulnerability data
    """
    instance = header_class()
    vulns = instance.get_vulnerabilities()
    assert isinstance(vulns, defaultdict)
    assert len(vulns) > 0
    for key, value in vulns.items():
        assert isinstance(key, str)
        assert isinstance(value, str)
