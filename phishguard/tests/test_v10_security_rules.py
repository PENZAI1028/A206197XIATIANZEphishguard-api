import unittest

from backend.app import (
    detect_homograph_attack,
    detect_official_domain,
    detect_brand_impersonation,
    domain_is_official,
    get_domain,
    get_shared_hosting_provider,
)


class V10RulesTests(unittest.TestCase):
    def assert_danger(self, url):
        domain = get_domain(url)
        official = detect_official_domain(domain)
        homograph = detect_homograph_attack(domain)
        self.assertGreaterEqual(max(official["score"], homograph["score"]), 90, url)

    def test_common_official_domains(self):
        for url in (
            "https://www.binance.com/en",
            "https://dashboard.render.com/",
            "https://www.google.com/",
            "https://www.maybank2u.com.my/",
            "https://chatgpt.com/",
        ):
            self.assertTrue(domain_is_official(get_domain(url))[0], url)

    def test_confusables_and_brand_suffixes(self):
        for url in (
            "https://www.b1nance.com/en/login",
            "https://paypa1-secure.com/login",
            "https://g00gle-support.net/verify",
            "https://m1cr0soft-login.com/",
            "https://d0cs.google.com/document/",
            "https://w0rd.cloud.microsoft/login",
            "https://m.ok000.com/",
            "https://xn--pple-43d.com/",
        ):
            self.assert_danger(url)

    def test_canonical_runtime_brand_features(self):
        brand = detect_brand_impersonation("b1nance-login.com")
        self.assertGreaterEqual(brand["score"], 70)
        self.assertFalse(domain_is_official("b1nance-login.com")[0])
        self.assertTrue(domain_is_official("binance.com")[0])

    def test_shared_platforms_not_blanket_trusted(self):
        for url in ("https://someone.github.io/page", "https://example.onrender.com", "https://pages.dev/"):
            domain = get_domain(url)
            self.assertFalse(domain_is_official(domain)[0], url)
            self.assertIsNotNone(get_shared_hosting_provider(domain), url)


if __name__ == "__main__":
    unittest.main()
