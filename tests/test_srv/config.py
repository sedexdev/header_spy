"""
Testing config class
"""

# pylint: disable=too-few-public-methods


class Config:
    """
    Sets local env variables for the app
    """
    FLASK_ENV = "TESTING"
    FLASK_APP = "tests.test_srv.app"
    FLASK_DEBUG = True
    SECRET_KEY = "Just4t3sting!"
