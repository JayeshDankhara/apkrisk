# apkrisk

**Explainable static malware risk scoring for Android APKs.**

`apkrisk` reads an APK, extracts 808 static features (permissions, security-relevant API methods and manifest metadata), and classifies it with a 17 KB linear model. It also tells you *which* features drove the verdict, so the result can be checked instead of trusted blindly.

```console
$ pip install git+https://github.com/JayeshDankhara/apkrisk
$ apkrisk scan AndroidMalwareDetector_v4.2.apk --explain -n 5
[benign ] AndroidMalwareDetector_v4.2.apk  (com.jayesh.android_malware_detector)  score=-5.671
             -2.208 → benign   meta_min_sdk
             +0.960 → malware  api_ljava_io_file->length
             -0.905 → benign   api_ljava_nio_channels_filechannel->size
             -0.845 → benign   api_ljava_lang_reflect_array->newInstance
             -0.800 → benign   api_ljava_nio_charset_charset->forName

1 scanned, 0 flagged as malware, 0 failed
```

## Why use it

- **Fast:** no emulator, no network and no upload to a third-party service. A typical app is scanned in under a second.
- **Explainable:** every verdict lists the features that pushed it towards malware or benign.
- **Research-grade features:** produces the exact feature vectors used in the accompanying paper, so you can build your own datasets in the same format.
- **CI-friendly:** JSON output and `--fail-on-malware` exit codes for build pipelines and app-store review tooling.

## Install

```bash
pip install git+https://github.com/JayeshDankhara/apkrisk   # from GitHub
pip install apkrisk                                         # from PyPI, once released
```

Requires Python 3.9+. The only dependency is [Androguard](https://github.com/androguard/androguard).

## Usage

### Scan APKs

```bash
apkrisk scan app.apk                    # one file
apkrisk scan ./apks/                    # every .apk in a folder, recursively
apkrisk scan app.apk --explain -n 20    # show the 20 most influential features
apkrisk scan app.apk -m lr              # Logistic Regression, adds a probability
apkrisk scan ./apks/ --json > report.json
apkrisk scan build/app-release.apk --fail-on-malware   # exit 1 if flagged
```

| Exit code | Meaning |
|---|---|
| 0 | Scan finished (and nothing flagged, if `--fail-on-malware` is set) |
| 1 | At least one APK was flagged and `--fail-on-malware` was set |
| 2 | No APKs found, or none could be parsed |

### Export features for research

```bash
apkrisk features ./dataset/ -o features.csv
```

This writes one row per APK: `sha256`, `package_name`, then the 808 features in model order.

### Python API

```python
import apkrisk

verdict = apkrisk.scan("app.apk", model="lr")
print(verdict.label, verdict.probability)
for c in verdict.top_contributions:
    print(f"{c.impact:+.3f}  {c.feature}")

# Or work with features directly
feats = apkrisk.extract("app.apk")
verdict = apkrisk.predict(feats.features, model="svm")
```

### In GitHub Actions

```yaml
- run: pip install git+https://github.com/JayeshDankhara/apkrisk
- run: apkrisk scan app/build/outputs/apk/release/app-release.apk --explain --fail-on-malware
```

## How it works

| Feature group | Count | Source |
|---|---|---|
| Permissions | 300 | `AndroidManifest.xml` requested permissions |
| API methods | 500 | DEX methods in classes matching security-relevant keywords (crypto, networking, SMS, reflection, runtime, file system and others) |
| Metadata | 8 | Component counts, min/target SDK, declared permissions, API method count |

Two models are bundled, both trained on 16,453 APKs (12,656 malware from CICMalDroid 2020 and 3,797 benign apps from AndroZoo, 2023–2026):

| Model | CV F1 (macro) | Size | Notes |
|---|---|---|---|
| Linear SVM (`svm`, default) | 0.9951 | 17 KB JSON | Fastest; decision score only |
| Logistic Regression (`lr`) | 0.9949 | 17 KB JSON | Adds a probability |

The training-time `MaxAbsScaler` is folded into the coefficients, so raw feature values are used directly. Model selection and the Pareto analysis behind these choices are described in the paper and in [AndroidMalwareDetector](https://github.com/JayeshDankhara/AndroidMalwareDetector).

## Limitations

Please read these before relying on a verdict:

- **Not an antivirus.** This is a research tool for triage. It does not replace dynamic analysis or a commercial scanner.
- **Dataset age and coverage:** The malware comes from 2020 and covers four families (adware, banking, riskware and SMS). Newer families and techniques may be missed.
- **Optimistic scores:** The reported CV scores are likely optimistic. The two classes come from different periods, and SMOTE oversampling was applied before the cross-validation split.
- **Static only:** Packed, obfuscated or dynamically loaded code can evade static features.
- **False positives:** Legitimate apps with SMS, accessibility or device-admin features (for example backup tools, parental controls and accessibility apps) can score high. Use `--explain` to check why an app was flagged.

## Development

```bash
git clone https://github.com/JayeshDankhara/apkrisk && cd apkrisk
pip install -e ".[dev]"
pytest                                        # unit tests
APKRISK_TEST_APK=/path/to/any.apk pytest      # also run the end-to-end tests
```

Bug reports, false-positive reports and pull requests are welcome. If you report a false positive or a miss, please include the APK's SHA-256 and the `--explain` output.

## Citation

If you use `apkrisk` in research, please cite:

```bibtex
@unpublished{dankhara2026pareto,
  author = {Dankhara, Jayesh and Jacobi, Mark},
  title  = {AI-Powered Android Malware Detection System Using Machine Learning:
            A Multi-Objective Pareto-Optimality Approach for On-Device Deployment},
  note   = {Manuscript under review, Journal of Information Security and Applications},
  year   = {2026}
}
```

## License

[MIT](LICENSE) © 2026 Jayesh Dankhara
