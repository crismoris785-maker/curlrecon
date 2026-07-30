# CurlRecon

![CI](https://github.com/USERNAME/curlrecon/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/curlrecon.svg)

Advanced CLI reconnaissance tool and HTML report generator. 

CurlRecon is designed to perform lightning-fast passive fingerprinting, active security scanning, vulnerability mapping, and WAF evasion, all presented in a sleek terminal UI or exportable HTML dashboard.

## Features

- **Passive Fingerprinting**: Detects CMS, Infrastructure, WAFs, and Tech Stacks.
- **Security Baseline**: Checks for missing HTTP security headers and maps them to potential threats.
- **Vulnerability Detection**: Automatically maps detected software versions against an offline JSON database (`cve_database.json`) to highlight critical CVEs.
- **Active Scanning**:
  - **Directory Fuzzing**: Brute-forces hidden endpoints.
  - **Port Scanning**: Rapid socket connection tests for common ports (22, 80, 443, 8080, 8443, etc.).
  - **Subdomain Enumeration**: Queries `crt.sh` to find associated subdomains.
- **Secrets Extraction**: Uses Regex to find exposed API keys, tokens, and secrets in response bodies.
- **WAF Evasion**: Spoofs internal IP headers (e.g. `X-Forwarded-For: 127.0.0.1`) and randomizes the `User-Agent` to bypass basic rate-limiting.
- **Reporting**: Standalone interactive HTML dashboard generation containing all recon data.
- **HTTP Engine**: Asynchronous, HTTP/2, and proxy support via `httpx`.

## Installation

The recommended way to install CurlRecon on modern systems (like Kali Linux, Ubuntu, or macOS) is using `pipx`. This installs the tool in a secure, isolated environment:

```bash
pipx install curlrecon
```

*Alternatively, you can install it directly via pip:*

```bash
pip install curlrecon
```

## Usage

### Interactive Mode

If you run the tool without any arguments, it will launch a fully-featured interactive menu system where you can specify targets, toggle active scanning modules, and generate reports without needing to memorize flags.

```bash
# Launch interactive menu
python -m curlrecon.cli
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
| `--fuzz` | Enable active directory fuzzing |
| `--ports` | Enable active fast port scanning |
| `--subdomains` | Enable subdomain enumeration via crt.sh |
| `--vuln` | Enable vulnerability checking via local `cve_database.json` |
| `--evade` | Enable WAF Evasion (Spoofed internal IP, Random User-Agent) |
| `--json-out` | Output raw JSON to stdout |
| `--html-out` | Path to export HTML report |
| `-o, --output` | Path to write JSON output directly |

### Offline CVE Database

To use the `--vuln` flag effectively, simply drop a file named `cve_database.json` in the same directory you run the tool from. The tool will parse this file dynamically to map detected software versions to CVEs.

Example `cve_database.json` format:
```json
{
  "Nginx": {
    "1.24.0": "CVE-XXXX-XXXX (Simulated Vulnerability)"
  }
}
```

## Examples

**1. Comprehensive Scan with HTML Report (All Features Enabled)**
```bash
python -m curlrecon.cli https://example.com --fuzz --ports --subdomains --vuln --evade --html-out report.html
```

**2. Basic Scan**
```bash
python -m curlrecon.cli https://example.com 
```

**3. Custom HTTP Method and Headers (`-X`, `-H`, `-A`)**
```bash
python -m curlrecon.cli https://example.com -X POST -H "Authorization: Bearer token123" -H "X-Custom: MyValue" -A "CustomAgent/1.0"
```

**4. Scanning Multiple Targets from a File with Concurrency (`-l`, `-t`)**
```bash
python -m curlrecon.cli -l targets.txt -t 20 --html-out bulk_report.html
```

**5. Proxy and Insecure (Bypass SSL) (`-x`, `-k`)**
```bash
python -m curlrecon.cli https://example.com -x socks5://127.0.0.1:9050 -k
```

**6. JSON Output and Redirection (`--json-out`, `-o`, `-L`)**
```bash
# Save JSON directly to a file quietly
python -m curlrecon.cli https://example.com -o results.json
```

## Dedication

*This tool is dedicated to **The Constant**, my mentor in cyber security.*
