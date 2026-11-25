"""apkrisk: explainable static malware risk scoring for Android APKs."""

from .features import ApkFeatures, extract
from .model import Verdict, predict

__all__ = ["ApkFeatures", "Verdict", "extract", "predict", "scan"]
__version__ = "0.1.0"


def scan(apk_path, model: str = "svm", top: int = 10) -> Verdict:
    """Extract features from an APK and classify it."""
    return predict(extract(apk_path).features, model=model, top=top)
