# HeaderSpy: A tool for checking secure HTTP headers

Makes a request to a domain supplied by the user and then inspects the headers
in the HTTP response. The tool lists out the headers that are present, and 
flags up missing headers that improve the security of communication over HTTP.

# Usage

<code>python main.py [-h] -d [domain.name] [-s] [-e] [-t] [num_threads] [-o]</code>

Output is sent to <code>stdout</code> by default.

# Options

<code>-h, --help</code>: Show the options
</br>
<code>-d, --domain</code>: The domain to send a HTTP request to in order to inspect the response headers (**required**)
</br>
<code>-t, --threads</code>: The number of threads used to enumerate subdomains</code>
</br>
<code>-e, --enum_sub</code>: Enumerate subdomains for the domain passed in using <code>-d</code> 
</br>
<code>-s, --secure</code>: Use HTTPS for requests, default behaviour uses HTTP 
</br>
<code>-o, --output</code>: Send output to a file rather than stdout
</br>

# License

<a href="https://github.com/sedexdev/header_spy/blob/main/LICENSE">M.I.T</a>