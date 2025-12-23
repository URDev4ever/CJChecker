<h1 ALIGN="center">CJChecker</h1>
<p align="center"> 🇺🇸 <a href="README.md"><b>English</b></a> | 🇪🇸 <a href="README_ES.md">Español</a> </p>
<p align="center">
 <img width="423" height="87" alt="image" src="https://github.com/user-attachments/assets/5b2b398f-1bc2-4b25-9212-4e7e2c4708c0" />
</p>

<h3 align="center">
  CJChecker is a lightweight command-line tool that checks web applications for basic Clickjacking protection by analyzing HTTP response headers.

  It focuses on identifying the presence of common anti-clickjacking mechanisms such as `X-Frame-Options` and `Content-Security-Policy` without attempting exploit confirmation.
</h3>

---

## Features

- Detects **X-Frame-Options** header and evaluates its value
- Detects **Content-Security-Policy** and checks for `frame-ancestors`
- Supports single URL and bulk scanning from a file
- Concurrent scanning with configurable workers
- Colored, readable terminal output
- Summary report for bulk scans
- Optional output to file
- Proper exit codes for scripting usage

---

## Requirements

- Python **3.8+**
- Internet access to the target URLs

### Python dependencies
- `requests`

Install dependencies with:
```bash
pip install requests
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/urdev4ever/cjchecker.git
cd cjchecker
```

(Optional) Make the script executable:

```bash
chmod +x cjchecker.py
```

---

## Usage

### Scan a single URL

```bash
python3 cjchecker.py -u https://example.com
```
<img width="574" height="384" alt="image" src="https://github.com/user-attachments/assets/9d6c7752-62bc-4f25-b084-884efd624b88" />


### Scan multiple URLs from a file

```bash
python3 cjchecker.py -l urls.txt
```
<img width="431" height="480" alt="image" src="https://github.com/user-attachments/assets/c6bc1d77-2e48-4d73-9c5b-2dd92b2ead32" />


### Set request timeout

```bash
python3 cjchecker.py -u https://example.com -t 5
```

### Set number of concurrent workers

```bash
python3 cjchecker.py -l urls.txt -w 10
```

### Save results to a file

```bash
python3 cjchecker.py -l urls.txt -o results.txt
```

---

## Input File Format

When using list mode (`-l`), the file must contain one URL per line:

```txt
https://example.com
https://test.example
example.org
# lines starting with # are ignored
```

URLs without a scheme will default to `https://`.

---

## Output

For each scanned target, CJChecker displays:

* Target URL
* HTTP status code
* Response time
* Detected clickjacking-related headers
* Overall security status
* Recommendations when protections are missing or weak

### Security Status

* **PROTECTED** → At least one clickjacking defense detected
* **VULNERABLE** → No clickjacking protection found

### Summary Report (list mode)

* Total URLs scanned
* Successful checks
* Protected vs vulnerable targets
* Protection rate
* List of vulnerable URLs

---

## Detection Logic

A target is considered **protected** if at least one of the following is present:

* `X-Frame-Options: DENY`
* `X-Frame-Options: SAMEORIGIN`
* `Content-Security-Policy` containing the `frame-ancestors` directive

CJChecker intentionally avoids deep CSP parsing to reduce false positives.

---

## Limitations

* Header-based detection only
* No exploit attempts or iframe proof-of-concepts
* No JavaScript execution or DOM analysis
* Redirects are followed automatically
* Results indicate presence of defenses, not exploitability

---

## Exit Codes

* `0` → All checked URLs are protected
* `1` → One or more vulnerable URLs found
* `130` → Scan interrupted by user (Ctrl+C)

---

## Disclaimer

This tool is intended for educational and defensive security purposes only.
Results should be treated as indicators, not confirmed vulnerabilities.

---

Made with <3 by URDev
