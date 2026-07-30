# CurlRecon Roadmap

This document outlines planned features and future implementations for `CurlRecon` to transform it into a comprehensive reconnaissance and vulnerability scanning tool.

## Active Scanning Features

- [ ] **Directory & File Fuzzing**
  - Implement a `--fuzz` flag to check for common hidden paths (e.g., `/.git/`, `/.env`, `/server-status`, `/admin`, `/backup.zip`).
  - Support custom wordlists.

- [ ] **Secrets & API Key Extraction**
  - Parse HTML and JavaScript responses against a regex database to detect exposed credentials (AWS Keys, Google Maps tokens, Stripe keys, etc.).

- [ ] **Subdomain Enumeration**
  - Integrate with public APIs (like crt.sh) to find subdomains.
  - Implement concurrent brute-forcing with a subdomain wordlist.

- [ ] **Port Scanning**
  - Add basic, fast TCP connect scanning for common web ports (e.g., 80, 443, 8080, 8443) before attempting HTTP requests.

## Vulnerability Detection

- [ ] **CORS Misconfiguration Detection**
  - Automatically inject custom `Origin` headers (e.g., `Origin: https://evil.com`) into background requests.
  - Analyze responses for blindly reflected `Access-Control-Allow-Origin` headers.

- [ ] **Subdomain Takeover Checking**
  - Detect 404 response signatures unique to major cloud providers (GitHub Pages, AWS S3, Heroku) indicating a vulnerable dangling DNS record.

- [ ] **Automated CVE Mapping**
  - Compare detected CMS, server, and framework versions against an offline database of critical, high-severity CVEs.
  - Alert the user if the target is running a demonstrably vulnerable version.

- [ ] **WAF Evasion Techniques**
  - Attempt standard WAF bypass tricks automatically when a block is detected (e.g., adding `X-Forwarded-For: 127.0.0.1`).

## Tool Enhancements

- [ ] **Advanced Reporting**
  - Export reports to PDF or Markdown formats in addition to HTML and JSON.
  - Provide a summary of most critical findings at the top of the report.

- [ ] **Plugin System**
  - Create a modular architecture allowing users to drop in custom python scripts as "recon modules" to easily expand functionality.
