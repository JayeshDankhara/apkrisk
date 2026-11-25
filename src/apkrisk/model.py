"""Bundled linear malware classifiers and explanations."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Dict, List, Mapping, Sequence

MODELS = {
    "svm": "Linear_SVM.json",
    "lr": "Logistic_Regression.json",
}


@dataclass
class Contribution:
    feature: str
    value: float
    weight: float

    @property
    def impact(self) -> float:
        return self.value * self.weight


@dataclass
class Verdict:
    model: str
    label: str  # "malware" or "benign"
    score: float  # decision value; > 0 means malware
    probability: float | None  # only for logistic regression
    matched_features: int
    total_features: int
    top_contributions: List[Contribution] = field(default_factory=list)

    @property
    def is_malware(self) -> bool:
        return self.label == "malware"


@lru_cache(maxsize=None)
def feature_names() -> List[str]:
    data = json.loads(resources.files("apkrisk.data").joinpath("feature_list.json").read_text())
    return list(data["features"])


@lru_cache(maxsize=None)
def _load(model: str):
    if model not in MODELS:
        raise ValueError(f"unknown model {model!r}; choose from {sorted(MODELS)}")
    data = json.loads(resources.files("apkrisk.data").joinpath(MODELS[model]).read_text())
    coef = data["coefficients"][0]
    if len(coef) != len(feature_names()):
        raise RuntimeError(f"{MODELS[model]} does not match feature_list.json")
    return coef, float(data["intercept"][0])


def vectorize(features: Mapping[str, float]) -> List[float]:
    """Map a raw feature dict onto the model's fixed 808-feature order."""
    return [float(features.get(name, 0.0)) for name in feature_names()]


def predict(features: Mapping[str, float], model: str = "svm", top: int = 10) -> Verdict:
    """Classify raw features with a bundled model.

    The exported coefficients already include the training-time MaxAbsScaler,
    so raw feature values are used directly.
    """
    coef, intercept = _load(model)
    names = feature_names()
    x = vectorize(features)

    score = intercept + sum(w * v for w, v in zip(coef, x))
    probability = 1.0 / (1.0 + math.exp(-score)) if model == "lr" else None

    contributions = [
        Contribution(feature=n, value=v, weight=w)
        for n, v, w in zip(names, x, coef)
        if v != 0.0 and w != 0.0
    ]
    contributions.sort(key=lambda c: abs(c.impact), reverse=True)

    return Verdict(
        model=model,
        label="malware" if score > 0 else "benign",
        score=score,
        probability=probability,
        matched_features=sum(1 for n, v in zip(names, x) if v != 0.0 and not n.startswith("meta_")),
        total_features=len(names),
        top_contributions=contributions[:top],
    )


def unknown_features(features: Mapping[str, float]) -> Sequence[str]:
    """Features present in the APK that the model has never seen."""
    known = set(feature_names())
    return sorted(k for k in features if k not in known)


def as_dict(verdict: Verdict) -> Dict:
    return {
        "model": verdict.model,
        "label": verdict.label,
        "score": round(verdict.score, 4),
        "probability": None if verdict.probability is None else round(verdict.probability, 4),
        "matched_features": verdict.matched_features,
        "total_features": verdict.total_features,
        "top_contributions": [
            {"feature": c.feature, "value": c.value, "impact": round(c.impact, 4)}
            for c in verdict.top_contributions
        ],
    }
