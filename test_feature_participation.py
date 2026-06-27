import unittest

import app as backend


class FeatureParticipationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = backend.app.test_client()

    def predict(self, url):
        response = self.client.post("/predict", json={"url": url})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_all_model_features_are_used_by_loaded_model(self):
        self.assertIsNotNone(backend.model, backend.MODEL_LOAD_ERROR)
        self.assertEqual(len(backend.MODEL_FEATURE_NAMES), 22)
        self.assertEqual(
            int(backend.model.n_features_in_),
            len(backend.MODEL_FEATURE_NAMES)
        )
        self.assertTrue(all(float(value) > 0 for value in backend.model.feature_importances_))

        payload = self.predict("https://goo.su/i.whatAapp")
        self.assertEqual(len(payload["model_features"]), len(backend.MODEL_FEATURE_NAMES))
        self.assertTrue(all(item["used_by_model"] for item in payload["model_features"]))

    def test_all_displayed_indicators_have_real_weighted_contributions(self):
        self.assertAlmostEqual(sum(backend.INDICATOR_WEIGHTS.values()), 1.0)

        for url in [
            "https://www.google.com",
            "http://example.com/login",
            "https://goo.su/i.whatAapp",
            "https://goog1e.com/login",
            "http://192.168.1.10/login",
            "https://example.xyz/account/verify"
        ]:
            with self.subTest(url=url):
                payload = self.predict(url)
                indicators = payload["indicators"]
                self.assertEqual(
                    {item["name"] for item in indicators},
                    set(backend.INDICATOR_WEIGHTS)
                )

                for item in indicators:
                    expected = round(
                        item["score"] * backend.INDICATOR_WEIGHTS[item["name"]],
                        2
                    )
                    self.assertTrue(item["used_in_final_score"])
                    self.assertGreater(item["weight_percent"], 0)
                    self.assertEqual(item["weighted_contribution_points"], expected)

                weighted_total = round(
                    sum(item["weighted_contribution_points"] for item in indicators),
                    2
                )
                self.assertEqual(
                    payload["score_audit"]["weighted_score_before_overrides"],
                    weighted_total
                )
                self.assertEqual(
                    payload["score_audit"]["indicator_weight_total_percent"],
                    100.0
                )
                self.assertEqual(
                    payload["score_audit"]["final_risk_score"],
                    payload["risk_score"]
                )

    def test_local_reputation_is_not_display_only(self):
        payload = self.predict("https://goo.su/i.whatAapp")
        reputation = next(
            item
            for item in payload["indicators"]
            if item["name"] == "domainReputation"
        )

        self.assertEqual(reputation["score"], 70)
        self.assertEqual(reputation["weight_percent"], 6.0)
        self.assertEqual(reputation["weighted_contribution_points"], 4.2)
        self.assertTrue(reputation["used_in_final_score"])


if __name__ == "__main__":
    unittest.main()
