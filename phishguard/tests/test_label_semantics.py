"""Regression tests for the PhiUSIIL source-label contract."""

from training.train_url_model import make_lookalike_rows, to_binary_label


def test_phiusiil_numeric_labels_are_inverted_into_project_semantics():
    # UCI source: 0=phishing, 1=legitimate.
    # Project invariant used by predict_proba: 1=phishing, 0=safe.
    assert to_binary_label(0, "0") == 1
    assert to_binary_label(1, "0") == 0
    assert to_binary_label(0.0, "0") == 1
    assert to_binary_label(1.0, "0") == 0


def test_synthetic_lookalikes_use_project_phishing_class():
    rows = make_lookalike_rows(100, 42)
    assert not rows.empty
    assert set(rows["label"]) == {1}


def test_numeric_classes_can_never_both_map_to_phishing():
    assert {to_binary_label(0, "0"), to_binary_label(1, "0")} == {0, 1}
    assert {to_binary_label(0, "1"), to_binary_label(1, "1")} == {0, 1}
