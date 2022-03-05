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
    def get_info(self):
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

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#http-strict-transport-security"}

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

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#x-frame-options"}

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

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#x-content-type-options"}

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

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#content-security-policy"}

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
        """
        Returns a string describing the purpose of this
        security header
        """
        return "XML file outlining a policy that gives permissions to Web clients to handle data across domains. " \
               "Remote domains (your servers) need to host a cross domain policy file that authorises requesting" \
               "clients to be able to access content on the remote domain"

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Resource Abuse"] = "Malicious policies can try to authorise access to harmful resources from outside " \
                                  "your domain"
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

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#referrer-policy"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Data Leak"] = "Session data can be leaked in Referrer headers if the correct policy is not applied"
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
        return "Replaces the existing Feature-Policy header for controlling permissions and powerful features"

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#permissions-policy"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Privacy abuse"] = "Potentially allows unauthorized access or usage of browser/client features by Web " \
                                 "resources. User privacy can be compromised by allowing browser features to be used " \
                                 "by Web resources"
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
        return "Clears browsing data (cookies, storage, cache) associated with the requesting website"

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#clear-site-data"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Privacy abuse"] = "Locally stored data can be accessed by attackers to compromise a users privacy"
        vulns["Session hijacking"] = "Locally stored session data could be stolen by an attacker in order to " \
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
        return "Prevents a document from loading any cross-origin resources that don’t explicitly grant the " \
               "document permission"

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#cross-origin-embedder-policy"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["XXS"] = "Allows scripts from outside sources to be executed on the resource"
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
        return "Allows you to ensure a top-level document does not share a browsing context group with cross-origin " \
               "documents. Documents are process-isolated so potential attackers can’t access global objects if they" \
               "were opening it in a popup"

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["XS-Leaks"] = "Class of vulnerabilities derived from side-channels built into the web platform. " \
                            "They take advantage of the web’s core principle of composability, which allows " \
                            "websites to interact with each other, and abuse legitimate mechanisms 2 to infer " \
                            "information about the user"
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
        return "Allows to define a policy that lets web sites and applications opt in to protection against certain " \
               "requests from other origins (such as those issued with elements like <script> and <img>)"

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#cross-origin-resource-policy"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Side-channel Attacks"] = "An attack based on information gained from the implementation of a " \
                                        "computer system, rather than weaknesses in implemented algorithms"
        vulns["XXSI"] = "A kind of vulnerability which exploits the fact that, when a resource is included using " \
                        "the script tag, the SOP doesn’t apply, because scripts have to be able to be included " \
                        "cross-domain. An attacker can thus read everything that was included using the script tag"
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

    def get_info(self) -> dict:
        """
        Return the OWASP Website info link for this header
        """
        return {"Information": "https://owasp.org/www-project-secure-headers/#cache-control"}

    def get_vulnerabilities(self) -> defaultdict:
        """
        Return a dictionary of possible vulnerabilities
        due to this header being missing
        """
        vulns = defaultdict()
        vulns["Privacy abuse"] = "Browsers often store information in a client-side cache, which can leave behind " \
                                 "sensitive information for other users to find and exploit, such as passwords or " \
                                 "credit card numbers"
        return vulns
