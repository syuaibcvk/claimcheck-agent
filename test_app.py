#!/usr/bin/env python3
"""Unit tests for ClaimCheck. Run: python3 -m unittest -v"""

import hashlib
import unittest

import app

SEED_PHRASE_PAGE = """<!DOCTYPE html>
<html><body>
<h1>Wallet verification required</h1>
<p>To claim your airdrop, enter your seed phrase and private key below.</p>
</body></html>"""

SEND_TO_RECEIVE_PAGE = """<!DOCTYPE html>
<html><body>
<h1>Bonus claim event</h1>
<p>Send 0.05 ETH to the verification address and receive 0.5 ETH back.</p>
</body></html>"""

CLEAN_PAGE = """<!DOCTYPE html>
<html><head><title>Example Protocol — Official Claim</title></head>
<body>
<h1>Official token claim</h1>
<p>The claim window opens on November 30, 2026 and closes on December 15, 2026.</p>
<p>Connect your wallet on this official site to check eligibility.
We will never ask for your seed phrase or private key.</p>
<p>Contract: 0x4Fe7E22267bFc3fB5113C42Ea9E93265Dc8F1C03</p>
<p><a href="https://example.com/docs">Read the documentation</a></p>
</body></html>"""

EVM_PAGE = """<html><body>
<p>Treasury wallet: 0x1da704b275869Ff834F3cF143Ea0d07491e97C20</p>
<p>Bitcoin donations: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq</p>
</body></html>"""


class TestRiskLevels(unittest.TestCase):
    def test_seed_phrase_request_is_critical(self):
        report = app.analyze(SEED_PHRASE_PAGE.encode(), "text", None)
        self.assertEqual(report["risk_level"], "CRITICAL")
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("secret_request", rules)

    def test_send_to_receive_is_high_or_critical(self):
        report = app.analyze(SEND_TO_RECEIVE_PAGE.encode(), "text", None)
        self.assertIn(report["risk_level"], ("HIGH", "CRITICAL"))
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("send_to_receive", rules)

    def test_clean_page_is_low(self):
        report = app.analyze(CLEAN_PAGE.encode(), "text", None)
        self.assertEqual(report["risk_level"], "LOW")
        self.assertEqual(report["findings"], [])

    def test_safety_warning_is_not_flagged(self):
        # "We will never ask for your seed phrase" is safety copy, and the
        # clean page above relies on the negation guard; assert directly too.
        text = "Remember: we never ask for your seed phrase. Ever."
        report = app.analyze_text(text)
        self.assertEqual(report["risk_level"], "LOW")


class TestExtraction(unittest.TestCase):
    def test_evm_address_extracted(self):
        report = app.analyze(EVM_PAGE.encode(), "text", None)
        self.assertIn(
            "0x1da704b275869Ff834F3cF143Ea0d07491e97C20",
            report["extracted"]["evm_addresses"],
        )

    def test_btc_address_extracted(self):
        report = app.analyze(EVM_PAGE.encode(), "text", None)
        self.assertIn(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            report["extracted"]["btc_addresses"],
        )

    def test_dates_and_links_extracted(self):
        report = app.analyze(CLEAN_PAGE.encode(), "text", None)
        self.assertIn("November 30, 2026", report["extracted"]["dates"])
        self.assertIn(
            "https://example.com/docs", report["extracted"]["links"])

    def test_evidence_hash_matches_content(self):
        content = CLEAN_PAGE.encode()
        report = app.analyze(content, "text", None)
        self.assertEqual(
            report["evidence_sha256"], hashlib.sha256(content).hexdigest())
        self.assertTrue(report["id"])
        self.assertIn("T", report["timestamp"])


class TestDemoFixture(unittest.TestCase):
    def test_demo_fixture_is_critical(self):
        report = app.analyze(app.DEMO_HTML.encode(), "demo", "built-in fixture")
        self.assertEqual(report["risk_level"], "CRITICAL")
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("secret_request", rules)
        self.assertIn("lookalike_domain", rules)


class TestUrlValidation(unittest.TestCase):
    def test_credentials_rejected(self):
        with self.assertRaises(app.FetchError):
            app.validate_url("https://user:pass@example.com/claim")

    def test_non_http_scheme_rejected(self):
        with self.assertRaises(app.FetchError):
            app.validate_url("ftp://example.com/claim")
        with self.assertRaises(app.FetchError):
            app.validate_url("file:///etc/passwd")

    def test_good_url_accepted(self):
        parsed = app.validate_url("https://example.com/claim")
        self.assertEqual(parsed.hostname, "example.com")


if __name__ == "__main__":
    unittest.main()
