# Web Application Vulnerability Scanner

A comprehensive web application vulnerability scanner with endpoint discovery and flexible testing options.

## Features

- **Endpoint Discovery**: Automatically discover and enumerate website endpoints
- **Vulnerability Testing**: Test for common web vulnerabilities including:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - CSRF vulnerabilities
  - Insecure Direct Object References (IDOR)
  - Exposed debug tools
  - File disclosure vulnerabilities
  - Weak admin credentials
  - Missing HTTPS/TLS issues
  - Broken access control
  - Session/token management issues

## Installation

1. Install Python dependencies:

```bash

pip install -r requirements.txt

```

2.  Clone the repository:

`git clone https://github.com/Skyrxin/VulnScan.git`
## Usage

### Basic Endpoint Discovery

```bash

python scanner.py --target https://example.com --discover-only

```

### Full Vulnerability Scan

```bash

python scanner.py --target https://example.com --scan-all

```

### Discover Endpoints and Save for Later

```bash

python scanner.py --target https://example.com --discover --save-endpoints endpoints.json

```

### Load and Test Saved Endpoints

```bash

python scanner.py --load-endpoints endpoints.json --scan-vulnerabilities

```

## Project Structure

- `scanner.py` - Main scanner application

- `modules/` - Core scanning modules

  - `endpoint_discovery.py` - Endpoint discovery and enumeration

  - `vulnerability_scanner.py` - Vulnerability testing modules

  - `status_checker.py` - Status code checking and visualization

  - `payloads.py` - Attack payloads and test cases

- `results/` - Scan results and reports

- `wordlists/` - Common endpoint wordlists

## Output  

The scanner provides color-coded terminal output and can save results in JSON format for further analysis.