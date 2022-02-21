from abc import ABC, abstractmethod
from collections import defaultdict


class SecureHeaderData(ABC):
    """
    Abstract Class containing stubs for additional data
    on the effects and implications of using certain security
    headers and the values that have been assigned to them.
    Concreate secure header data classes should inherit this
    class
    """

    @abstractmethod
    def get_name(self):
        pass

    @abstractmethod
    def get_description(self):
        pass

    @abstractmethod
    def get_values(self):
        pass

    def get_vulnerabilities(self):
        pass


class StrictTransportSecurity(SecureHeaderData, ABC):
    """
    Holds data bout the Strict-Transport-Security header
    """

    def __init__(self, name: str) -> None:
        """
        Constructor for StrictTransportSecurity class
        """
        self._name = name

    def get_name(self) -> str:
        """
        Return the name of this security header
        """
        return self._name

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Sending this header tells Web browsers that they can only communicate with the Web server over HTTPS"

    def get_values(self) -> defaultdict:
        """
        Return the possible values of this security and
        their meanings
        """
        values = defaultdict()
        values["max-age=SECONDS"] = "Time in seconds for the browser to remember that this site is HTTPS only"
        values["includeSubDomains"] = "Apply the HTTPS only rule to all subdomains as well"
        return values

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Downgrade attack"] = "Sending this header over HTTP makes the connection vulnerable to SSL stripping"
        vulns["Cookie hijacking"] = "Not using encrypted messages increases the chance of session data being stolen"
        return vulns


class XFrameOptions(SecureHeaderData, ABC):
    """
    Holds data bout the X-Frame-Options header
    """

    def __init__(self, name: str) -> None:
        """
        Constructor for XFrameOptions class
        """
        self._name = name

    def get_name(self) -> str:
        """
        Return the name of this security header
        """
        return self._name

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Sending this header tells Web browsers that they can only communicate with the Web server over HTTPS"

    def get_values(self) -> defaultdict:
        """
        Return the possible values of this security and
        their meanings
        """
        values = defaultdict()
        values["max-age=SECONDS"] = "Time in seconds for the browser to remember that this site is HTTPS only"
        values["includeSubDomains"] = "Apply the HTTPS only rule to all subdomains as well"
        return values

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Downgrade attack"] = "Sending this header over HTTP makes the connection vulnerable to SSL stripping"
        vulns["Cookie hijacking"] = "Not using encrypted messages increases the chance of session data being stolen"
        return vulns
