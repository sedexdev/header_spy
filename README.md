# HeaderSpy: A tool for checking secure HTTP headers

[![Test](https://github.com/sedexdev/header_spy/actions/workflows/test.yml/badge.svg)](https://github.com/sedexdev/header_spy/actions/workflows/test.yml)

Makes an HTTP GET request to a domain supplied by the user and then inspects the headers in the HTTP response. The tool
lists out the headers that are present, and flags up missing headers that improve the security of communication over HTTP.

The tool is based on the <a href="https://owasp.org/www-project-secure-headers/">OWASP Secure Headers Project</a>. This
project **"describes HTTP response headers that your application can use to increase the security of your application"**.
The tool can inspect a single domain, or it can enumerate a large amount of possible subdomains of a given domain.

# Usage

<code>python main.py [-h] -d [domain.name] [-s] [-i] [header_name] [-w] [word_list_path] [-t] [num_threads] [-o] [file_path] [-v]</code>

Output is sent to <code>stdout</code> by default.

If output is sent to a file, the path can be passed in as an absolute or relative value.

**NOTE:** The timeout for an HTTP request is set to 10 seconds. The program may appear to hang while it tries to
resend requests to non-responsive domains. This behaviour is normal, all requests will complete after either receiving
a response, the request has timed out, or the requested network is unreachable.

**CREDIT**: Thanks to <a href="https://github.com/rbsec/" target="_blank" rel="noopener noreferrer">rbsec</a> for
sharing comprehensive word lists for subdomain enumeration. The repo the <code>subdomain-x.txt</code> files came
from can be found <a href="https://github.com/rbsec/dnscan" target="_blank" rel="noopener noreferrer">here</a>

# Options

<code>-d, --domain</code>: The domain to send a HTTP GET request to in order to inspect the response headers (**required**)
<br>
<code>-h, --help</code>: Show the options
<br>
<code>-o, --output</code>: File path to save the response data to
<br>
<code>-s, --secure</code>: Use HTTPS for requests, default behaviour uses HTTP
<br>
<code>-t, --threads</code>: The number of threads used to enumerate subdomains. Default is 10
<br>
<code>-i, --inspect-header</code>: Pass in a single header name to show URLs that contain that header
<br>
<code>-v, --verbose</code>: Outputs more data about HTTP headers with a description, a link to the OWASP Website, and
the vulnerabilities that can result from the header not being present
<br>
<code>-w, --wordlist</code>: Absolute or relative path to a word list to use for subdomain enumeration
<br>

Sending results to <code>stdout</code> will show failures as well as successes in terms of Web server responses.
Sending the results to a file will only show successful requests that received responses.

Similarly, sending the result of a single header search to <code>stdout</code> will show both domains that **do**
contain the header ([+]) and those that **don't** contain the header ([-]). When sending the results of a single
header search to a file, only those domains that **don't have the given header are written**.

No verbose content is displayed when searching for the presence of a single HTTP header using the <code>-i</code> switch

# License

<a href="https://github.com/sedexdev/header_spy/blob/main/LICENSE">M.I.T</a>
