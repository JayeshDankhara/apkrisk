"""Command-line interface: ``apkrisk scan`` and ``apkrisk features``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Iterable, List

from . import __version__
from .features import extract
from .model import as_dict, feature_names, predict, unknown_features


def _collect(paths: Iterable[str]) -> List[Path]:
    """Expand files and folders into a sorted list of APK paths."""
    found: List[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            found.extend(sorted(q for q in p.rglob("*.apk") if q.is_file()))
        elif p.is_file():
            found.append(p)
        else:
            print(f"apkrisk: not found: {p}", file=sys.stderr)
    return found


def _print_verdict(path: Path, package: str, verdict, explain: bool) -> None:
    mark = "MALWARE" if verdict.is_malware else "benign "
    prob = f"  p={verdict.probability:.3f}" if verdict.probability is not None else ""
    print(f"[{mark}] {path.name}  ({package})  score={verdict.score:+.3f}{prob}")
    if explain:
        for c in verdict.top_contributions:
            direction = "→ malware" if c.impact > 0 else "→ benign "
            print(f"           {c.impact:+8.3f} {direction}  {c.feature}")


def cmd_scan(args) -> int:
    apks = _collect(args.paths)
    if not apks:
        print("apkrisk: no APK files to scan", file=sys.stderr)
        return 2

    results, flagged, errors = [], 0, 0
    for path in apks:
        try:
            feats = extract(path, include_api=not args.no_api)
            verdict = predict(feats.features, model=args.model, top=args.top)
        except Exception as exc:  # corrupt or unsupported APK
            errors += 1
            if args.json:
                results.append({"path": str(path), "error": str(exc)})
            else:
                print(f"[ ERROR ] {path.name}: {exc}", file=sys.stderr)
            continue

        flagged += verdict.is_malware
        if args.json:
            results.append({
                "path": str(path),
                "package": feats.package,
                "sha256": feats.sha256,
                **as_dict(verdict),
                "unseen_features": len(unknown_features(feats.features)),
            })
        else:
            _print_verdict(path, feats.package, verdict, explain=args.explain)

    if args.json:
        json.dump(results if len(results) != 1 else results[0], sys.stdout, indent=2)
        print()
    else:
        print(f"\n{len(apks)} scanned, {flagged} flagged as malware, {errors} failed")

    if errors and errors == len(apks):
        return 2
    return 1 if (args.fail_on_malware and flagged) else 0


def cmd_features(args) -> int:
    apks = _collect(args.paths)
    if not apks:
        print("apkrisk: no APK files found", file=sys.stderr)
        return 2

    names = feature_names()
    out = open(args.output, "w", newline="") if args.output else sys.stdout
    try:
        writer = csv.writer(out)
        writer.writerow(["sha256", "package_name", *names])
        for path in apks:
            try:
                feats = extract(path, include_api=not args.no_api)
            except Exception as exc:
                print(f"apkrisk: skipped {path}: {exc}", file=sys.stderr)
                continue
            writer.writerow([feats.sha256, feats.package, *(feats.features.get(n, 0) for n in names)])
    finally:
        if out is not sys.stdout:
            out.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apkrisk",
        description="Explainable static malware risk scoring for Android APKs.",
    )
    parser.add_argument("--version", action="version", version=f"apkrisk {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="classify APK files or folders of APKs")
    scan.add_argument("paths", nargs="+", help="APK files or folders (searched recursively)")
    scan.add_argument("-m", "--model", choices=["svm", "lr"], default="svm",
                      help="svm: Linear SVM (default); lr: Logistic Regression with probability")
    scan.add_argument("-e", "--explain", action="store_true", help="show the features that drove each verdict")
    scan.add_argument("-n", "--top", type=int, default=10, help="number of features to explain (default 10)")
    scan.add_argument("--json", action="store_true", help="print machine-readable JSON")
    scan.add_argument("--no-api", action="store_true", help="skip DEX parsing (faster, less accurate)")
    scan.add_argument("--fail-on-malware", action="store_true",
                      help="exit with status 1 if any APK is flagged (useful in CI)")
    scan.set_defaults(func=cmd_scan)

    feats = sub.add_parser("features", help="export the 808-feature vector of each APK as CSV")
    feats.add_argument("paths", nargs="+", help="APK files or folders")
    feats.add_argument("-o", "--output", help="CSV file to write (default: stdout)")
    feats.add_argument("--no-api", action="store_true", help="skip DEX parsing")
    feats.set_defaults(func=cmd_features)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # output piped into e.g. `head`
        sys.stderr.close()
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
