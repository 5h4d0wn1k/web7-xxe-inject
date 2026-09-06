# WEB7 — XXE Injection Tool

XXE payload generation, blind XXE detection, file read via SSRF, and error-based exfiltration.

## Overview

This project provides a comprehensive XXE (XML External Entity) injection toolkit:
- **Payload generation** — Classic, parameter entity, OOB, XInclude, SVG payloads
- **Blind XXE detection** — Error-based and OOB detection techniques
- **File read exploitation** — Read arbitrary files from the target server
- **SSRF via XXE** — Access internal services through the vulnerable parser
- **Brute-force** — Fuzz common files and internal endpoints

## Features

- Multiple XXE payload formats (classic, parameter entity, XInclude, SVG)
- Blind XXE detection with error-based analysis
- File read and SSRF exploitation
- OOB (out-of-band) exfiltration support
- Common-file brute-force scanner
- Internal network endpoint discovery
- Full CLI with mode selection

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

## Usage

```bash
# Generate payloads
python3 xxe_tool.py --mode generate --file /etc/passwd

# Detect blind XXE
python3 xxe_tool.py --mode detect --url http://target/xml-endpoint

# Exploit file read
python3 xxe_tool.py --mode exploit --url http://target/xml-endpoint --file /etc/passwd

# Brute-force common files
python3 xxe_tool.py --mode brute --url http://target/xml-endpoint

# Offline demo (vulnerable + clean control simulators, no network)
python3 xxe_tool.py --demo        # or run with no arguments

# Run the offline test suite
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

Run against a local lab target only (loopback or a VM you own):

1. `python3 xxe_tool.py --demo` — verify the engine detects file-read, entity
   expansion and error-based XXE on the vulnerable simulator and reports zero
   findings on the clean control (both exit 0).
2. Start a knowingly-vulnerable parser endpoint (e.g. a local app that
   processes XML with external entity loading enabled) and run
   `python3 xxe_tool.py --mode detect --url http://127.0.0.1:<port>/parse`.
3. Confirm a positive on the vulnerable endpoint and a negative on a hardened
   endpoint that strips DOCTYPE (`docs/payloads` never touch real systems).
4. `python3 -m unittest discover -s tests` — full offline suite must pass.

## Metrics

- Demo wall time: < 20 s (two loopback simulators, ~6 HTTP requests each)
- Offline detection: file read, entity expansion, and error-based exfil all
  fire on the planted vulnerable simulator and never on the clean control.
- Test suite: 9 deterministic offline tests (`python3 -m unittest`), no network
  access required.
- Code paths exercised: urllib request/receive, payload generation,
  `BlindXXEDetector.detect_xml_parsing`, `.test_file_read`, `.error_based_exfil`,
  `is_vulnerable`, and both simulator handlers.

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
