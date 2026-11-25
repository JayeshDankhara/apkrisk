"""Static feature extraction from APK files.

The extraction mirrors the pipeline used to build the training dataset, so the
bundled models see the same kind of features they were trained on:

* metadata: component counts, SDK levels, declared permissions
* permissions requested in AndroidManifest.xml (``perm_<name>``)
* methods of DEX classes whose names match security-relevant keywords
  (``api_<class>-><method>``)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

TARGET_API_KEYWORDS = [
    # Crypto
    "crypto", "cipher", "javax/crypto", "java/security",
    # Network
    "net/", "http", "url", "socket", "connection",
    # SMS / telephony
    "sms", "telephony", "tel/",
    # Process / runtime
    "runtime", "process", "exec",
    # File system
    "file", "io/",
    # Reflection (obfuscation indicator)
    "reflect",
    # Device info
    "deviceid", "imei", "location",
    # WebView
    "webkit", "webview",
    # Content (contacts, calendar)
    "content/resolver", "contacts",
    # Camera / microphone
    "camera", "media/recorder",
]


@dataclass
class ApkFeatures:
    """Raw features extracted from one APK."""

    path: str
    package: str
    sha256: str
    features: Dict[str, float] = field(default_factory=dict)
    permissions: List[str] = field(default_factory=list)


def _quiet_androguard() -> None:
    """Androguard logs every parsing step through loguru; silence it."""
    try:
        from loguru import logger

        logger.remove()
    except Exception:  # pragma: no cover - loguru missing or already removed
        pass
    logging.getLogger("androguard").setLevel(logging.ERROR)


def api_feature_name(class_name: str, method_name: str) -> str:
    """Build the feature name used in the training data for a DEX method."""
    name = f"api_{class_name.lower()}->{method_name}"
    return name.replace("/", "_").replace(";", "")


def extract(apk_path: str | Path, include_api: bool = True) -> ApkFeatures:
    """Extract static features from an APK.

    Args:
        apk_path: Path to the ``.apk`` file.
        include_api: Parse DEX code for API features. Turning this off is much
            faster but leaves 500 of the 808 model features empty.
    """
    _quiet_androguard()
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk_path = Path(apk_path)
    app = APK(str(apk_path))

    feats: Dict[str, float] = {
        "meta_services_count": len(app.get_services()),
        "meta_receivers_count": len(app.get_receivers()),
        "meta_providers_count": len(app.get_providers()),
        "meta_activities_count": len(app.get_activities()),
        "meta_min_sdk": _to_int(app.get_min_sdk_version()),
        "meta_target_sdk": _to_int(app.get_target_sdk_version()),
        "meta_declared_perms": len(app.get_declared_permissions()),
    }

    permissions = sorted(set(app.get_permissions()))
    for perm in permissions:
        feats[f"perm_{perm.strip().replace(' ', '_')}"] = 1

    api_count = 0
    if include_api:
        for dex_bytes in app.get_all_dex():
            try:
                dex = DEX(dex_bytes)
            except Exception:
                continue  # skip malformed DEX files, as the training pipeline did
            for method in dex.get_methods():
                class_name = method.get_class_name().lower()
                if any(kw in class_name for kw in TARGET_API_KEYWORDS):
                    feats[api_feature_name(class_name, method.get_name())] = 1
                    api_count += 1
    feats["meta_api_calls_found"] = api_count

    import hashlib

    sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    return ApkFeatures(
        path=str(apk_path),
        package=app.get_package() or "",
        sha256=sha256,
        features=feats,
        permissions=permissions,
    )


def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
