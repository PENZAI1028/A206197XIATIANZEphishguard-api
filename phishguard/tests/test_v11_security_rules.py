import unittest

from backend.app import detect_homograph_attack, detect_official_domain, domain_is_official, get_domain
from backend.phishguard_v11_model import brand_signals, has_risk_confusable_marker


class V11RulesTests(unittest.TestCase):
    def assert_danger(self, url):
        domain = get_domain(url)
        official = detect_official_domain(domain)
        homograph = detect_homograph_attack(domain)
        self.assertGreaterEqual(max(official["score"], homograph["score"]), 90, url)

    def test_common_official_domains(self):
        for url in ("https://www.binance.com/en", "https://dashboard.render.com/", "https://www.google.com/", "https://www.maybank2u.com.my/", "https://chatgpt.com/"):
            self.assertTrue(domain_is_official(get_domain(url))[0], url)

    def test_brand_substitutions_are_high_risk(self):
        for url in ("https://www.b1nance.com/en/login", "https://paypa1-secure.com/login", "https://g00gle-support.net/verify", "https://m1cr0soft-login.com/", "https://d0cs.google.com/document/", "https://w0rd.cloud.microsoft/login", "https://m.ok000.com/", "https://xn--pple-43d.com/"):
            self.assert_danger(url)

    def test_plain_i_and_l_are_not_markers(self):
        self.assertFalse(has_risk_confusable_marker("chdpublication"))
        self.assertFalse(has_risk_confusable_marker("microwaves"))
        self.assertTrue(has_risk_confusable_marker("b1nance"))
        self.assertTrue(has_risk_confusable_marker("g00gle"))

    def test_model_brand_features(self):
        _, marked, _, unofficial, official = brand_signals("b1nance-login.com")
        self.assertEqual(marked, 1.0)
        self.assertEqual(unofficial, 1.0)
        self.assertEqual(official, 0.0)
        _, marked_real, _, unofficial_real, official_real = brand_signals("binance.com")
        self.assertEqual(marked_real, 0.0)
        self.assertEqual(unofficial_real, 0.0)
        self.assertEqual(official_real, 1.0)


if __name__ == "__main__":
    unittest.main()
