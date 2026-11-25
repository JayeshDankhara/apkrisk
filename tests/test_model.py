import math

import pytest

from apkrisk.model import _load, feature_names, predict, unknown_features, vectorize


def test_feature_schema():
    names = feature_names()
    assert len(names) == 808
    assert sum(n.startswith("meta_") for n in names) == 8
    assert sum(n.startswith("perm_") for n in names) == 300
    assert sum(n.startswith("api_") for n in names) == 500


def test_vectorize_order_and_defaults():
    names = feature_names()
    x = vectorize({names[3]: 5, "not_a_feature": 1})
    assert len(x) == len(names)
    assert x[3] == 5.0
    assert sum(x) == 5.0


@pytest.mark.parametrize("model", ["svm", "lr"])
def test_empty_app_scores_intercept(model):
    _, intercept = _load(model)
    v = predict({}, model=model)
    assert v.score == pytest.approx(intercept)
    assert v.top_contributions == []


def test_probability_only_for_lr():
    assert predict({}, model="svm").probability is None
    p = predict({}, model="lr").probability
    assert 0.0 < p < 1.0
    assert p == pytest.approx(1 / (1 + math.exp(-predict({}, model="lr").score)))


def test_typical_app_benign_and_risky_app_malware():
    typical = {
        "meta_min_sdk": 24, "meta_target_sdk": 34, "meta_services_count": 5,
        "meta_receivers_count": 4, "meta_providers_count": 2,
        "meta_activities_count": 10, "meta_declared_perms": 0,
    }
    assert predict(typical).label == "benign"

    coef, _ = _load("svm")
    names = feature_names()
    risky_perms = sorted(
        (n for n in names if n.startswith("perm_")),
        key=lambda n: coef[names.index(n)],
        reverse=True,
    )[:12]
    risky = dict(typical, **{p: 1 for p in risky_perms})
    assert predict(risky).label == "malware"


def test_contributions_sorted_and_explain_score():
    names = feature_names()
    feats = {n: 1 for n in names if n.startswith("perm_")}
    v = predict(feats, top=808)
    impacts = [abs(c.impact) for c in v.top_contributions]
    assert impacts == sorted(impacts, reverse=True)
    _, intercept = _load("svm")
    assert intercept + sum(c.impact for c in v.top_contributions) == pytest.approx(v.score)


def test_unknown_model_rejected():
    with pytest.raises(ValueError):
        predict({}, model="random_forest")


def test_unknown_features():
    assert unknown_features({"perm_android.permission.INTERNET": 1, "perm_x.MADE_UP": 1}) == ["perm_x.MADE_UP"]
