# HeaderSpy: A tool for checking secure HTTP headers

Makes a HTTP GET request to a domain supplied by the user and then inspects the headers in the HTTP response. The tool 
lists out the headers that are present, and flags up missing headers that improve the security of communication over HTTP.

The tool is based on the <a href="https://owasp.org/www-project-secure-headers/">OWASP Secure Headers Project</a>. This
project **"describes HTTP response headers that your application can use to increase the security of your application"**.
The tool can inspect a single domain, or it can enumerate a large amount of possible subdomains of a given domain.

# Usage

<code>python main.py [-h] -d [domain.name] [-s] [-u] [header_name] [-e] [-n] [num_subdomains] [-t] [num_threads] [-o]</code>

Output is sent to <code>stdout</code> by default.

If output is sent to a file, itis saved in the current working directory as <code>output.txt</code>

**NOTE:** The timeout for an HTTP request is set to 30 seconds. The program may appear to hang while it tries to 
resend requests to non-responsive domains. This behaviour is normal, all requests will complete after either receiving 
a response, the request has timed out, or the requested network is unreachable. 

**CREDIT**: Thanks to <a href="https://github.com/rbsec/" target="_blank" rel="noopener noreferrer">rbsec</a> for 
sharing comprehensive word lists for subdomain enumeration. The repo the <code>subdomain-x.txt</code> files came 
from can be found <a href="https://github.com/rbsec/dnscan" target="_blank" rel="noopener noreferrer">here</a>

# Options

<code>-d, --domain</code>: The domain to send a HTTP GET request to in order to inspect the response headers (**required**)
</br>
<code>-e, --enum_sub</code>: Enumerate subdomains for the domain passed in using <code>-d</code> 
</br>
<code>-h, --help</code>: Show the options
</br>
<code>-n, --num_sub</code>: Number of subdomains to look for when opting to use subdomain enumeration. Options are 
chosen using integers 100, 1000, or 10000
</br>
<code>-o, --output</code>: Send output to a file rather than stdout
</br>
<code>-s, --secure</code>: Use HTTPS for requests, default behaviour uses HTTP 
</br>
<code>-t, --threads</code>: The number of threads used to enumerate subdomains. Default is 10
</br>
<code>-u, --uni_header</code>: Pass in a single header name to show response URLs that contain that header
</br>

# License

<a href="https://github.com/sedexdev/header_spy/blob/main/LICENSE">M.I.T</a>
