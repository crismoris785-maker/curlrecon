# CurlRecon

![CI](https://github.com/USERNAME/curlrecon/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/curlrecon.svg)

Advanced CLI reconnaissance tool and HTML report generator.

## Features

- **HTTP Engine**: Asynchronous, HTTP/2 and proxy support via `httpx`.
- **CLI Interface**: `curl`-compatible switches built with `click`.
- **Terminal UI**: Beautiful terminal output powered by `rich`.
- **Fingerprinting**: Tech stack detection (CMS, Infrastructure, WAF).
- **Security Baseline**: Essential security headers checking.
- **Reporting**: Standalone interactive HTML dashboard generation.
- **Strict Data Validation**: Powered by `pydantic`.

## Installation

The recommended way to install CurlRecon on modern systems (like Kali Linux, Ubuntu, or macOS) is using `pipx`. This installs the tool in a secure, isolated environment without conflicting with your OS packages:

```bash
pipx install curlrecon
```

*Alternatively, you can install it directly via pip if you are inside a virtual environment or on a system that allows it:*

```bash
pip install curlrecon
```

## Usage

### Interactive Mode

If you run the tool without any arguments, it will launch a fully-featured interactive menu system where you can specify targets, configure scans, and generate reports without needing to memorize flags.

```bash
# If installed via pip:
curlrecon

# If running locally from the source folder:
python -m curlrecon.cli
```

### CLI Execution

```bash
curlrecon https://example.com --html-out report.html
```

### CLI Flags

| Flag | Description |
|---|---|
| `-X, --request` | HTTP Method (GET, POST, HEAD, etc.) |
| `-H, --header` | Custom HTTP headers |
| `-A, --user-agent` | User-Agent string |
| `-x, --proxy` | HTTP/SOCKS5 proxy |
| `-k, --insecure` | Disable TLS/SSL verification |
| `-d, --data` | String payload for POST/PUT |
| `-L, --location` | Toggle following redirects (default: True) |
| `--timeout` | Network timeout in seconds (default: 10.0) |
| `-l, --file` | Path to target URLs file |
| `-t, --threads` | Concurrent workers (default: 10) |
| `--json-out` | Output raw JSON to stdout |
| `--html-out` | Path to export HTML report |
| `-o, --output` | Path to write JSON output directly |

### Examples

**1. Basic Scan with HTML Report**
```bash
curlrecon https://example.com --html-out report.html
```

**2. Custom HTTP Method and Headers (`-X`, `-H`, `-A`)**
```bash
curlrecon https://example.com -X POST -H "Authorization: Bearer token123" -H "X-Custom: MyValue" -A "CustomAgent/1.0"
```

**3. Sending Data Payload (`-d`)**
```bash
curlrecon https://example.com/api/login -X POST -d '{"username":"admin", "password":"password"}' -H "Content-Type: application/json"
```

**4. Scanning Multiple Targets from a File with Concurrency (`-l`, `-t`)**
```bash
curlrecon -l targets.txt -t 20 --html-out bulk_report.html
```

**5. Proxy and Insecure (Bypass SSL) (`-x`, `-k`)**
```bash
curlrecon https://example.com -x socks5://127.0.0.1:9050 -k
```

**6. JSON Output and Redirection (`--json-out`, `-o`, `-L`)**
```bash
# Don't follow redirects (-L is True by default, use --no-location to disable)
curlrecon https://example.com --no-location --json-out

# Save JSON directly to a file quietly
curlrecon https://example.com -o results.json
```

## Dedication

*This tool is dedicated to **The Constant**, my mentor in cyber security.*
