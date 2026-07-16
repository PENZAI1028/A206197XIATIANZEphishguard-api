import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import reputation_store as reputation


class ReputationRuntimeTests(unittest.TestCase):
    def sample_store(self, generated_at="2026-06-29T00:00:00Z"):
        exact = reputation.fingerprint_hash("known.bad/login?x=1")
        return {
            "format_version": 1,
            "generated_at_utc": generated_at,
            "counts": {"url_fingerprints": 1, "hosts": 2, "roots": 2},
            "url_fingerprints": {
                exact: {"sources": ["openphish", "phishtank"], "url_count": 2}
            },
            "hosts": {
                "known.bad": {"sources": ["phishtank"], "url_count": 1},
                "sub.knownroot.test": {"sources": ["urlhaus"], "url_count": 1},
            },
            "roots": {
                "known.bad": {"sources": ["phishtank"], "url_count": 1},
                "knownroot.test": {"sources": ["urlhaus"], "url_count": 1},
            },
            "load_error": None,
        }

    def test_exact_url_ignores_scheme_and_www(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("http://www.known.bad/login?x=1")
        self.assertTrue(result["match"])
        self.assertEqual(result["match_type"], "exact_url")
        self.assertGreaterEqual(result["score"], 99)
        self.assertIn("openphish", result["sources"])

    def test_single_source_root_hostname_is_non_blocking(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("https://known.bad/another-path")
        self.assertTrue(result["match"])
        self.assertEqual(result["match_type"], "host")
        self.assertEqual(result["score"], 35)
        self.assertEqual(result["evidence_class"], "root_host_single_source")

    def test_root_only_match_is_context_not_blocking(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("https://other.knownroot.test/path")
        self.assertFalse(result["match"])
        self.assertTrue(result["context_match"])
        self.assertEqual(result["evidence_class"], "root_context_only")

    def test_non_match_does_not_mean_safe(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("https://example.com")
        self.assertFalse(result["match"])
        self.assertEqual(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
