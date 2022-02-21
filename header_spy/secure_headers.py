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
    def get_description(self):
        pass

    @abstractmethod
    def get_values(self):
        pass

    @abstractmethod
    def get_vulnerabilities(self):
        pass


class StrictTransportSecurity(SecureHeaderData, ABC):
    """
    Holds data about the Strict-Transport-Security header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Sending this header tells Web browsers that they can only communicate with the Web server over HTTPS"

    def get_values(self) -> defaultdict:
        """
        Return the possible values of this security header
        and their meanings
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
    Holds data about the X-Frame-Options header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Guides the browser on whether data in the response can be displayed in a frame"

    def get_values(self) -> defaultdict:
        """
        Return the possible values of this security header
        and their meanings
        """
        values = defaultdict()
        values["deny"] = "Rendering within frames is denied"
        values["sameorigin"] = "Rendering within frames is allowed if the origin is the same as the Web server"
        values["allow-from: DOMAIN"] = "Rendering is allowed within frames if the frame came from DOMAIN"
        return values

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Clickjacking"] = "Unseen layers are used to fool a user into clicking on a button or link on an " \
                                "embedded page when they wanted to click something on the top layer of the page"
        return vulns


class XContentTypeOptions(SecureHeaderData, ABC):
    """
    Holds data about the X-Content-Type-Options header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Stops browsers from interpreting files differently to the MIME type in the Content-Type header"

    def get_values(self) -> defaultdict:
        """
        Return the possible values of this security header
        and their meanings
        """
        values = defaultdict()
        values["nosniff"] = "Stops browsers from trying to 'sniff' MIME types without reading the Content-Type header"
        return values

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["MIME sniffing"] = "Can cause browsers to interpret files incorrectly e.g text/plain as text/html"
        return vulns


class ContentSecurityPolicy(SecureHeaderData, ABC):
    """
    Holds data about the Content-Security-Policy header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Informs browsers on how content is rendered. Rules are created to fine-tune how content is displayed"

    def get_values(self) -> defaultdict:
        """
        Return the possible values of this security header
        and their meanings
        """
        values = defaultdict()
        values["base-uri"] = "Blah"
        values["default-src"] = "Blah"
        values["script-src"] = "Blah"
        values["object-src"] = "Blah"
        values["style-src"] = "Blah"
        values["img-src"] = "Blah"
        values["media-src"] = "Blah"
        values["frame-src"] = "Blah"
        values["child-src"] = "Blah"
        values["frame-ancestors"] = "Blah"
        values["font-src"] = "Blah"
        values["connect-src"] = "Blah"
        values["manifest-src"] = "Blah"
        values["form-action"] = "Blah"
        values["sandbox"] = "Blah"
        values["script-nonce"] = "Blah"
        values["plugin-types"] = "Blah"
        values["reflected-xss"] = "Blah"
        values["block-all-mixed-content"] = "Blah"
        values["upgrade-insecure-requests"] = "Blah"
        values["referrer"] = "Blah"
        values["report-uri"] = "Blah"
        values["report-to"] = "Blah"
        return values

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["XXS"] = "Blah"
        vulns["XS-Injection"] = "Blah"
        return vulns


class XPermittedCrossDomainPolicies(SecureHeaderData, ABC):
    """
    Holds data about the X-Permitted-Cross-Domain-Policies header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns


class ReferrerPolicy(SecureHeaderData, ABC):
    """
    Holds data about the Referrer-Policy header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns


class PermissionsPolicy(SecureHeaderData, ABC):
    """
    Holds data about the  Permissions-Policy header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns


class ClearSiteData(SecureHeaderData, ABC):
    """
    Holds data about the Clear-Site-Data header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns


class CrossOriginEmbedderPolicy(SecureHeaderData, ABC):
    """
    Holds data about the Cross-Origin-Embedder-Policy header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns


class CrossOriginOpenerPolicy(SecureHeaderData, ABC):
    """
    Holds data bout the Cross-Origin-Opener-Policy header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns


class CrossOriginResourcePolicy(SecureHeaderData, ABC):
    """
    Holds data about the Cross-Origin-Resource-Policy header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns


class CacheControl(SecureHeaderData, ABC):
    """
    Holds data about the Cache-Control header
    """

    def get_description(self) -> str:
        return ""

    def get_values(self) -> defaultdict:
        values = defaultdict()
        return values

    def get_vulnerabilities(self):
        vulns = defaultdict()
        return vulns
