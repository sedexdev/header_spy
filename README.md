# HeaderSpy: A tool for checking secure HTTP headers

Makes a request to a domain supplied by the user and then inspects the headers
in the HTTP response. The tool lists out the headers that are present, and 
flags up missing headers that improve the security of communication over HTTP.

# Usage

<code>python main.py [-h] -d [domain.name] [-s] [-e] [-n] [num_subdomains] [-t] [num_threads] [-o]</code>

Output is sent to <code>stdout</code> by default.

**NOTE:** The timeout for an HTTP request is set to 30 seconds. The program may appear to hang while it tries to 
resend requests to non-responsive domains. This behaviour is normal, all requests will complete after either receiving 
a response, the request has timed out, or the requested network is unreachable. 

**CREDIT**: Thanks to <a href="https://github.com/rbsec/">rbsec</a> for sharing comprehensive word lists for subdomain
enumeration. The repo the <code>subdomain-x.txt</code> files came from can be found <a href="https://github.com/rbsec/dnscan">here</a>

# Options

<code>-h, --help</code>: Show the options
</br>
<code>-d, --domain</code>: The domain to send a HTTP request to in order to inspect the response headers (**required**)
</br>
<code>-t, --threads</code>: The number of threads used to enumerate subdomains</code>
</br>
<code>-e, --enum_sub</code>: Enumerate subdomains for the domain passed in using <code>-d</code> 
</br>
<code>-n, --num_sub</code>: Number of subdomains to use for when opting to use subdomain enumeration. Options are 
chosen using integers 100, 1000, or 10000
</br>
<code>-s, --secure</code>: Use HTTPS for requests, default behaviour uses HTTP 
</br>
<code>-o, --output</code>: Send output to a file rather than stdout
</br>

# License

<a href="https://github.com/sedexdev/header_spy/blob/main/LICENSE">M.I.T</a>