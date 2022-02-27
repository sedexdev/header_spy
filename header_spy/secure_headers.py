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
        return "Informs browsers on how content is rendered. Rules are created to fine-tune where content comes from" \
               "so resources cannot be loaded from non-compliant locations."

    def get_values(self) -> defaultdict:
        """
        Return the possible values of this security header
        and their meanings
        """
        values = defaultdict()
        values["base-uri"] = "Base URI for relative URIs"
        values["default-src"] = "Default loading policy for any directive that isn't defined elsewhere in the policy"
        values["script-src"] = "Scripts that the resource can execute"
        values["object-src"] = "Location the resource can load plugins from"
        values["style-src"] = "Style sheets the resource can apply when rendering"
        values["img-src"] = "Location the resource can load images from"
        values["media-src"] = "Location the resource can load video and audio from"
        values["frame-src"] = "Location the resource can embed frames from (deprecated, use 'child-rsrc')"
        values["child-src"] = "Location the resource can embed frames from"
        values["frame-ancestors"] = "Location the resource can be embedded into a frame from"
        values["font-src"] = "Location the resource can load fonts from"
        values["connect-src"] = "URIs the resource can load using script interfaces"
        values["manifest-src"] = "Location the resource can load manifests from"
        values["form-action"] = "Which URIs can be used in the 'action' attribute of a HTML form element"
        values["sandbox"] = "HTML sandbox policy the user agent applies to the resource"
        values["script-nonce"] = "Only scripts containing a specific nonce on script elements can be executed"
        values["plugin-types"] = "Limits types of resources that can be embedded, invoked by a set of defined plugins"
        values["reflected-xss"] = "Instructs user agents to activate/deactivate heuristics used to filter out " \
                                  "reflected XXS attacks. Equivalent to the effects of the X-XXS-Protection header"
        values["block-all-mixed-content"] = "Prevents user agent from loading mixed content"
        values["upgrade-insecure-requests"] = "User agents download insecure HTTP resources over HTTPS"
        values["referrer"] = "Define information the user agent can send in the 'referrer' header (deprecated)"
        values["report-uri"] = "URI user agents send policy violation reports to (deprecated, use 'report-to')"
        values["report-to"] = "Group, defined in the 'Report-To' header, user agents send policy violation reports to"
        return values

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["XXS"] = "Allows scripts from outside sources to be executed on the resource"
        vulns["XS-Injection"] = "Allows malicious resources to be injected into the resource from the outside"
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
