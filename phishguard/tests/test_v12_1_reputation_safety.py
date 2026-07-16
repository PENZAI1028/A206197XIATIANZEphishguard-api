import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import reputation_store as reputation


class ReputationSafetyTests(unittest.TestCase):
    def sample_store(self):
        exact = reputation.fingerprint_hash("known.bad/login?x=1")
        return {
            "format_version": 1,
            "generated_at_utc": "2026-06-29T00:00:00Z",
            "counts": {"url_fingerprints": 1, "hosts": 3, "roots": 2},
            "url_fingerprints": {exact: {"sources": ["openphish"], "url_count": 1}},
            "hosts": {
                "known.bad": {"sources": ["phishtank"], "url_count": 2},
                "sub.knownroot.test": {"sources": ["urlhaus"], "url_count": 2},
                "gravatar.com": {"sources": ["phishtank"], "url_count": 16},
            },
            "roots": {
                "known.bad": {"sources": ["phishtank"], "url_count": 2},
                "knownroot.test": {"sources": ["urlhaus"], "url_count": 2},
            },
            "load_error": None,
        }

    def test_exact_url_is_strong(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("https://known.bad/login?x=1")
        self.assertTrue(result["match"])
        self.assertEqual(result["match_type"], "exact_url")
        self.assertEqual(result["score"], 100)

    def test_dedicated_subdomain_is_strong(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("https://sub.knownroot.test/other")
        self.assertTrue(result["match"])
        self.assertEqual(result["score"], 98)
        self.assertEqual(result["evidence_class"], "dedicated_host")

    def test_single_source_root_host_is_non_blocking_warning(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("https://gravatar.com/")
        self.assertTrue(result["match"])
        self.assertEqual(result["score"], 35)
        self.assertEqual(result["evidence_class"], "root_host_single_source")

    def test_root_only_does_not_flag_unseen_sibling(self):
        with patch.object(reputation, "_STORE", self.sample_store()):
            result = reputation.lookup_reputation("https://other.knownroot.test/path")
        self.assertFalse(result["match"])
        self.assertTrue(result["context_match"])
        self.assertEqual(result["evidence_class"], "root_context_only")


if __name__ == "__main__":
    unittest.main()
