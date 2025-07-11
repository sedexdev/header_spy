# HeaderSpy: A tool for checking secure HTTP headers

[![Test](https://github.com/sedexdev/header_spy/actions/workflows/test.yml/badge.svg)](https://github.com/sedexdev/header_spy/actions/workflows/test.yml)

Makes an HTTP GET request to a domain supplied by the user and then inspects the headers in the HTTP response. The tool
lists out the headers that are present, and flags up missing headers that improve the security of communication over HTTP.

The tool is based on the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/). This
project **"describes HTTP response headers that your application can use to increase the security of your application"**.
The tool can inspect a single domain, or it can enumerate a large amount of possible subdomains of a given domain.

# 📦 Installation

## Prerequisites

```bash
Python >= 3.12
```

## Get the code

```bash
git clone https://github.com/sedexdev/header_spy.git
cd header_spy
python3 main.py [OPTIONS]
```

# ⚙️ Usage

```bash
python main.py [-h] -d [domain.name] [-s] [-i] [header_name] [-w] [word_list_path] [-t] [num_threads] [-o] [file_path] [-v]
```

`-d, --domain`: Domain to inspect - sends HTTP GET request (**required**) \
`-h, --help`: Show the options \
`-o, --output`: Output file path to save the response data to \
`-s, --secure`: Use HTTPS for requests, default behaviour uses HTTP \
`-t, --threads`: The number of threads used to enumerate subdomains. Default is 10 \
`-i, --inspect-header`: Pass in a single header name to show URLs that contain that header \
`-v, --verbose`: Outputs detailed data with a description, a link to the OWASP Website, and potential vulnerabilities resulting from the header not being present \
`-w, --wordlist`: Path to a word list used for subdomain enumeration

## Notes

-   Output is sent to `stdout` by default.
-   File output paths can be absolute or relative values.
-   The timeout for an HTTP request is set to 10 seconds.
    -   The program may appear to hang while it tries to
        resend requests to non-responsive domains.
    -   This behaviour is normal, all requests will complete after either receiving a response, the request has timed out, or the requested network is unreachable.
-   Sending results to `stdout` will show failures as well as successes.
-   Sending the results to a file will only show successful requests.
-   Sending the result of a single header search to `stdout` will show domains that **do** contain the header (`[+]`) and those that **don't** contain the header (`[-]`).
-   Sending the results of a single header search to a file writes only those domains that **don't have the given header**.
-   No verbose content is displayed when searching for a single header using the `-i` switch

# 📂 Project Structure

```
header_spy/
│
├── .github/          # GitHub workflows and issue templates
├── tests/            # Unit and integration tests
├── utils/            # Utility classes & functions
├── .gitignore        # Ignore file for Git
├── LICENSE           # MIT OSS license
├── README.md         # This file :>
├── main.py           # Entry point
└── requirements.py   # Dependencies
```

# 🧪 Running Tests

```bash
# create a virtual environment with your preferred tool
cd header_spy/
virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
pytest tests/
```

# 🐛 Reporting Issues

Found a bug or need a feature? Open an issue [here](https://github.com/sedexdev/header_spy/issues).

# 🧑‍💻 Authors

**Andrew Macmillan** – [@sedexdev](https://github.com/sedexdev)

# 📜 License

This project is licensed under the MIT License - see the [M.I.T](https://github.com/sedexdev/header_spy/blob/main/LICENSE) file for details.

# 📣 Acknowledgements

Thanks to [rbsec](https://github.com/rbsec/) for
sharing comprehensive word lists for subdomain enumeration. \
The repo the `subdomain-x.txt` files came from can be found [here](https://github.com/rbsec/dnscan).
