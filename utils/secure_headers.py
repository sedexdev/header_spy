"""
Header data module    
"""

# pylint: disable=line-too-long

from abc import ABC, abstractmethod
from collections import defaultdict


class SecureHeaderData(ABC):
    """
    Abstract Class containing stubs for additional data
    on the effects and implications of using certain security
    headers and the values that have been assigned to them.
    Concrete secure header data classes should inherit this
    class
    """

    @abstractmethod
    def get_description(self) -> str:
        """
        Method stub for header description
        """

    @abstractmethod
    def get_link(self) -> str:
        """
        Method stub for header OWASP link
        """

    @abstractmethod
    def get_vulnerabilities(self) -> defaultdict:
        """
        Method stub for header vulnerability data
        """


class StrictTransportSecurity(SecureHeaderData, ABC):
    """
    Holds data about the Strict-Transport-Security header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Sending this header tells Web browsers that they can only communicate with the \nWeb server over HTTPS"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#http-strict-transport-security"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Downgrade attack"] = "Sending this header over HTTP makes the connection vulnerable to SSL \nstripping"
        vulns["Cookie hijacking"] = "Not using encrypted messages increases the chance of session data \nbeing stolen"
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

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#x-frame-options"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Clickjacking"] = "Unseen layers are used to fool a user into clicking on a button or link on an \n" \
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
        return "Stops browsers from interpreting files differently to the MIME type in the \nContent-Type header"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#x-content-type-options"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["MIME sniffing"] = "Can cause browsers to interpret files incorrectly e.g text/plain \nas text/html"
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
        return "Informs browsers on how content is rendered. Rules are created to fine-tune where \ncontent comes " \
               "from so resources cannot be loaded from non-compliant \nlocations."

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#content-security-policy"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["XXS"] = "Allows scripts from outside sources to be executed on the resource"
        vulns["XS-Injection"] = "Allows malicious resources to be injected into the resource from \nthe outside"
        return vulns


class XPermittedCrossDomainPolicies(SecureHeaderData, ABC):
    """
    Holds data about the X-Permitted-Cross-Domain-Policies header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "XML file outlining a policy that gives permissions to Web clients to handle data \nacross domains. " \
               "Remote domains (your servers) need to host a cross domain policy file \nthat authorises requesting " \
               "clients to be able to access content on the \nremote domain"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Resource Abuse"] = "Malicious policies can try to authorise access to harmful resources \nfrom " \
                                  "outside your domain"
        return vulns


class ReferrerPolicy(SecureHeaderData, ABC):
    """
    Holds data about the Referrer-Policy header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Governs referrer information to be sent back to requesting clients"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#referrer-policy"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Data Leak"] = "Session data can be leaked in Referrer headers if the correct policy \nis not applied"
        return vulns


class PermissionsPolicy(SecureHeaderData, ABC):
    """
    Holds data about the  Permissions-Policy header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Replaces the existing Feature-Policy header for controlling permissions and \npowerful features"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#permissions-policy"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Privacy abuse"] = "Potentially allows unauthorized access or usage of browser/client features \n" \
                                 "by Web resources. User privacy can be compromised by allowing browser \nfeatures " \
                                 "to be used by Web resources"
        return vulns


class ClearSiteData(SecureHeaderData, ABC):
    """
    Holds data about the Clear-Site-Data header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Clears browsing data (cookies, storage, cache) associated with the \nrequesting website"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#clear-site-data"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Privacy abuse"] = "Locally stored data can be accessed by attackers to compromise a \nusers privacy"
        vulns["Session hijacking"] = "Locally stored session data could be stolen by an attacker in \norder to " \
                                     "authenticate against Wen services as that user"
        return vulns


class CrossOriginEmbedderPolicy(SecureHeaderData, ABC):
    """
    Holds data about the Cross-Origin-Embedder-Policy header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Prevents a document from loading any cross-origin resources that don’t \nexplicitly grant the " \
               "document permission"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#cross-origin-embedder-policy"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["XXS"] = "Allows scripts from outside sources to be executed on \nthe resource"
        return vulns


class CrossOriginOpenerPolicy(SecureHeaderData, ABC):
    """
    Holds data bout the Cross-Origin-Opener-Policy header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Allows you to ensure a top-level document does not share a browsing context \ngroup with " \
               "cross-origin documents. Documents are process-isolated so potential \nattackers can’t access " \
               "global objects if they were \nopening it in a popup"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["XS-Leaks"] = "Class of vulnerabilities derived from side-channels built into \nthe web platform. " \
                            "They take advantage of the web’s core principle of \ncomposability, which allows " \
                            "websites to interact with each other, and \nabuse legitimate mechanisms 2 to infer " \
                            "information about \nthe user"
        return vulns


class CrossOriginResourcePolicy(SecureHeaderData, ABC):
    """
    Holds data about the Cross-Origin-Resource-Policy header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Allows to define a policy that lets Websites and applications opt in to \nprotection against " \
               "certain requests from other origins (such as those issued with \nelements like <script> and <img>)"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#cross-origin-resource-policy"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Side-channel Attacks"] = "An attack based on information gained from the implementation \nof a " \
                                        "computer system, rather than weaknesses in \nimplemented algorithms"
        vulns["XXSI"] = "A kind of vulnerability which exploits the fact that, when a resource \nis included using " \
                        "the script tag, the SOP doesn’t apply, because scripts have to \nbe able to be included " \
                        "cross-domain. An attacker can thus read everything that \nwas included using the script tag"
        return vulns


class CacheControl(SecureHeaderData, ABC):
    """
    Holds data about the Cache-Control header
    """

    def get_description(self) -> str:
        """
        Returns a string describing the purpose of this
        security header
        """
        return "Holds directives (instructions) for caching in both requests and responses"

    def get_link(self) -> str:
        """
        Return the OWASP Website info link for this header
        """
        return "https://owasp.org/www-project-secure-headers/#cache-control"

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Privacy abuse"] = "Browsers often store information in a client-side cache, which can \nleave behind " \
                                 "sensitive information for other users to find and exploit, \nsuch as passwords or " \
                                 "credit card numbers"
        return vulns
