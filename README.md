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

1.  Clone the repository:

```bash 

git clone https://github.com/Skyrxin/VulnScan.git

```

2. Install Python dependencies:

```bash

pip install -r requirements.txt

```


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

### Discord Notifier Option

Create a Discord webhook in your server (Server Settings → Integrations → Webhooks).
Run the scanner and pass the webhook URL:

```bash

python scanner.py --target https://example.com --scan-all --discord-webhook https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN

```
If the webhook is configured correctly you'll see a console message:

<div align="center"><img width="553" height="239" alt="image" src="https://github.com/user-attachments/assets/c6a75af8-5bd6-4855-8081-f976c7d9953d" /></div>

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
