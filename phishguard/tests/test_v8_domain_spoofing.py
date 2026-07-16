"""Smoke tests for v8 trusted-domain and confusable-character defenses."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
import app  # noqa: E402


class DomainSpoofingTests(unittest.TestCase):
    def assert_danger(self, url: str) -> None:
        domain = app.get_domain(url)
        official = app.detect_official_domain(domain)
        homograph = app.detect_homograph_attack(domain)
        self.assertGreaterEqual(max(official["score"], homograph["score"]), 90, url)

    def assert_official(self, url: str) -> None:
        domain = app.get_domain(url)
        self.assertTrue(app.domain_is_official(domain)[0], url)

    def test_real_domains(self):
        for url in (
            "https://www.binance.com/en/blog/markets/6320153512014434443",
            "https://word.cloud.microsoft/zh-hans/",
            "https://m.okooo.com/jczq/",
            "https://dashboard.render.com/web/example",
        ):
            self.assert_official(url)

    def test_numeric_and_letter_confusables(self):
        for url in (
            "https://www.b1nance.com/en/blog/markets/6320153512014434443",
            "https://g00gle.com/login",
            "https://paypa1-secure.com/login",
            "https://m.ok000.com/jczq/",
            "https://d0cs.google.com/account",
            "https://w0rd.cloud.microsoft/zh-hans/",
        ):
            self.assert_danger(url)

    def test_shared_platform_is_not_trusted(self):
        domain = app.get_domain("https://docs.google.com/document/d/example")
        result = app.detect_official_domain(domain)
        self.assertEqual(result["status"], "warning")
        self.assertGreaterEqual(result["score"], 20)


if __name__ == "__main__":
    unittest.main()
