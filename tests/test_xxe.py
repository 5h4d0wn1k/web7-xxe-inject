#!/usr/bin/env python3
"""Tests for WEB7 — XXE Injection Tool.

Hosts the built-in vulnerable/clean XML simulators on loopback and runs the
real detection engine through urllib against them.
"""

import os
import sys
import threading
import unittest
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xxe_tool import (
    BlindXXEDetector,
    VulnXMLHandler,
    CleanXMLHandler,
    _resolve_xxe_entities,
)


class XXEHelpersTest(unittest.TestCase):
    def test_entity_resolver_expands_internal_and_external(self):
        resolved, missing_name, missing_uri = _resolve_xxe_entities(
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE data [\n'
            '<!ENTITY internal "HELLO">\n'
            '<!ENTITY fin SYSTEM "file:///etc/passwd">\n'
            ']>\n'
            "<root>&internal;|&fin;</root>",
        )
        self.assertIsNone(missing_name)
        self.assertIn("HELLO", resolved)
        self.assertIn("root:x:0:0:", resolved)

    def test_entity_resolver_reports_missing_file(self):
        resolved, missing_name, missing_uri = _resolve_xxe_entities(
            '<!DOCTYPE data [<!ENTITY e SYSTEM "file:///NOPE">]>'
            "<root>&e;</root>",
        )
        self.assertIsNone(resolved)
        self.assertEqual(missing_name, "e")
        self.assertEqual(missing_uri, "file:///NOPE")


def _start(handler_cls, fixtures=None):
    if fixtures is not None:
        handler_cls.fixtures = fixtures
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class XXEDetectionTest(unittest.TestCase):
    def setUp(self):
        self.vuln = _start(VulnXMLHandler)
        self.clean = _start(CleanXMLHandler)
        self.addCleanup(self._close, self.vuln)
        self.addCleanup(self._close, self.clean)

    @staticmethod
    def _close(server):
        server.shutdown()
        server.server_close()

    def _scan(self, server):
        url = f"http://127.0.0.1:{server.server_port}/parse"
        detector = BlindXXEDetector(url, method="POST", param="xml", timeout=5)
        return detector.full_scan("/etc/passwd")

    def test_detects_fixture_leak_on_vulnerable(self):
        results = self._scan(self.vuln)
        file_read = results["file_read"]
        self.assertTrue(file_read["file_read_possible"])
        self.assertIn("root:x:0:0:", file_read["leaked_content"])

    def test_error_based_fires_on_vulnerable(self):
        results = self._scan(self.vuln)
        self.assertTrue(results["error_based"]["error_based_detected"])

    def test_entity_expansion_detected_on_vulnerable(self):
        results = self._scan(self.vuln)
        self.assertTrue(results["xml_parsing"]["entity_expansion"])
        self.assertTrue(BlindXXEDetector.is_vulnerable(results))

    def test_no_false_positive_on_clean(self):
        results = self._scan(self.clean)
        self.assertFalse(results["file_read"]["file_read_possible"])
        self.assertFalse(results["error_based"]["error_based_detected"])
        self.assertFalse(BlindXXEDetector.is_vulnerable(results))

    def test_vulnerable_clean_contrast(self):
        vuln = self._scan(self.vuln)
        clean = self._scan(self.clean)
        self.assertFalse(clean["xml_parsing"]["entity_expansion"])
        self.assertGreater(
            len(vuln["file_read"]["leaked_content"]),
            len(clean["file_read"]["leaked_content"]),
        )


class XXEDemoTest(unittest.TestCase):
    def test_demo_vulnerable_returns_0(self):
        import xxe_tool
        rc = xxe_tool.run_demo(vulnerable=True, clean=False)
        self.assertEqual(rc, 0)

    def test_demo_clean_returns_0(self):
        import xxe_tool
        rc = xxe_tool.run_demo(vulnerable=True, clean=True)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()