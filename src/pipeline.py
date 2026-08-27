from pathlib import Path
import hashlib
import json
import re
import zipfile
import numpy as np

try:
    import joblib
except Exception:
    joblib = None

try:
    from androguard.misc import AnalyzeAPK
except Exception:
    AnalyzeAPK = None

try:
    from androguard.core.apk import APK
except Exception:
    APK = None


SENSITIVE = {
    "android.permission.CAMERA": 10,
    "android.permission.RECORD_AUDIO": 10,
    "android.permission.RECORD_VIDEO": 8,
    "android.permission.READ_SMS": 9,
    "android.permission.SEND_SMS": 8,
    "android.permission.RECEIVE_SMS": 8,
    "android.permission.READ_CALL_LOG": 8,
    "android.permission.READ_CONTACTS": 7,
    "android.permission.ACCESS_FINE_LOCATION": 8,
    "android.permission.ACCESS_COARSE_LOCATION": 5,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 12,
    "android.permission.RECEIVE_BOOT_COMPLETED": 8,
    "android.permission.INTERNET": 4,
    "android.permission.READ_PHONE_STATE": 5,
}


# 25 configurable Dalvik opcode categories
OPCODES = [
    "move", "return", "const", "invoke", "new", "goto", "if", "cmp",
    "array", "field", "monitor", "throw", "check", "instance", "switch",
    "add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr"
]


def _safe_call(obj, method_name, default=None):
    """Safely call an androguard method."""
    try:
        method = getattr(obj, method_name, None)
        if callable(method):
            value = method()
            return value if value is not None else default
    except Exception:
        pass
    return default


def _normalise_dex(dex):
    """Convert androguard DEX output to a list."""
    if dex is None:
        return []

    if isinstance(dex, (list, tuple)):
        return list(dex)

    return [dex]


def _opcode_features(dex_objects):
    """
    Extract simplified opcode 2-gram features.

    Invalid/corrupted DEX files are skipped instead of crashing
    the complete application.
    """
    counts = {
        f"{a}_{b}": 0
        for a in OPCODES
        for b in OPCODES
    }

    total = 0

    for d in dex_objects:
        try:
            classes = d.get_classes()

            for c in classes:
                try:
                    methods = c.get_methods()
                except Exception:
                    continue

                for m in methods:
                    try:
                        code = m.get_code()

                        if not code:
                            continue

                        instructions = list(
                            code.get_bc().get_instructions()
                        )

                        prev = None

                        for insn in instructions:
                            try:
                                op = insn.get_name().lower()
                            except Exception:
                                continue

                            cat = next(
                                (
                                    x for x in OPCODES
                                    if op.startswith(x)
                                ),
                                "other"
                            )

                            if prev is not None:
                                key = f"{prev}_{cat}"

                                if key in counts:
                                    counts[key] += 1

                            prev = cat
                            total += 1

                    except Exception:
                        # Skip problematic methods
                        continue

        except Exception:
            # Skip problematic DEX objects
            continue

    top = sorted(
        counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:25]

    return dict(top), total


def _basic_zip_check(apk_path):
    """Check whether the uploaded file is a readable ZIP/APK."""
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()

            return {
                "is_zip": True,
                "has_manifest": "AndroidManifest.xml" in names,
                "has_dex": any(
                    name.startswith("classes")
                    and name.endswith(".dex")
                    for name in names
                ),
                "file_count": len(names),
            }

    except Exception:
        return {
            "is_zip": False,
            "has_manifest": False,
            "has_dex": False,
            "file_count": 0,
        }


def _extract_manifest_only(apk_path):
    """
    Fallback analysis.

    If AnalyzeAPK fails because of a bad DEX checksum,
    try to read only the APK/manifest information.
    """

    if APK is None:
        return None

    try:
        a = APK(apk_path)

        perms = _safe_call(
            a,
            "get_permissions",
            []
        ) or []

        activities = _safe_call(
            a,
            "get_activities",
            []
        ) or []

        services = _safe_call(
            a,
            "get_services",
            []
        ) or []

        receivers = _safe_call(
            a,
            "get_receivers",
            []
        ) or []

        providers = _safe_call(
            a,
            "get_providers",
            []
        ) or []

        custom = []

        try:
            custom = a.get_declared_permissions() or []
        except Exception:
            pass

        return {
            "package": _safe_call(a, "get_package", "Unknown"),
            "version_name": _safe_call(
                a,
                "get_androidversion_name",
                "Unknown"
            ),
            "min_sdk": _safe_call(
                a,
                "get_min_sdk_version",
                "Unknown"
            ),
            "target_sdk": _safe_call(
                a,
                "get_target_sdk_version",
                "Unknown"
            ),
            "permissions": perms,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "custom_permissions": custom,
        }

    except Exception:
        return None


def _build_evidence(
    apk_path,
    manifest_data,
    dex_count=0,
    opcode_instructions=0,
    analysis_mode="full"
):
    """Create a common evidence structure."""

    file_hash = hashlib.sha256(
        Path(apk_path).read_bytes()
    ).hexdigest()

    zip_info = _basic_zip_check(apk_path)

    return {
        "package": manifest_data.get("package", "Unknown"),
        "version_name": manifest_data.get(
            "version_name",
            "Unknown"
        ),
        "min_sdk": manifest_data.get(
            "min_sdk",
            "Unknown"
        ),
        "target_sdk": manifest_data.get(
            "target_sdk",
            "Unknown"
        ),
        "sha256": file_hash,
        "permissions": manifest_data.get(
            "permissions",
            []
        ),
        "activities": manifest_data.get(
            "activities",
            []
        ),
        "services": manifest_data.get(
            "services",
            []
        ),
        "receivers": manifest_data.get(
            "receivers",
            []
        ),
        "providers": manifest_data.get(
            "providers",
            []
        ),
        "custom_permissions": manifest_data.get(
            "custom_permissions",
            []
        ),
        "dex_files": dex_count,
        "opcode_instructions": opcode_instructions,
        "analysis_mode": analysis_mode,
        "zip_valid": zip_info["is_zip"],
        "has_manifest": zip_info["has_manifest"],
        "has_dex": zip_info["has_dex"],
        "apk_file_count": zip_info["file_count"],
    }


def extract_features(apk_path):
    """
    Main feature extraction.

    First attempts complete Manifest + DEX analysis.

    If DEX parsing fails, especially because of:
        Wrong Adler32 checksum for DEX file

    the application falls back to Manifest-only analysis
    instead of crashing.
    """

    if AnalyzeAPK is None and APK is None:
        raise RuntimeError(
            "Androguard is not installed. "
            "Run: pip install -r requirements.txt"
        )

    # ---------------------------------------------------------
    # STEP 1: Try complete Manifest + DEX analysis
    # ---------------------------------------------------------

    if AnalyzeAPK is not None:

        try:
            a, dex, dx = AnalyzeAPK(apk_path)

            perms = _safe_call(
                a,
                "get_permissions",
                []
            ) or []

            acts = _safe_call(
                a,
                "get_activities",
                []
            ) or []

            svcs = _safe_call(
                a,
                "get_services",
                []
            ) or []

            recs = _safe_call(
                a,
                "get_receivers",
                []
            ) or []

            provs = _safe_call(
                a,
                "get_providers",
                []
            ) or []

            custom = []

            try:
                custom = a.get_declared_permissions() or []
            except Exception:
                pass

            dex_objects = _normalise_dex(dex)

            op_counts, total_ops = _opcode_features(
                dex_objects
            )

            manifest_data = {
                "package": _safe_call(
                    a,
                    "get_package",
                    "Unknown"
                ),
                "version_name": _safe_call(
                    a,
                    "get_androidversion_name",
                    "Unknown"
                ),
                "min_sdk": _safe_call(
                    a,
                    "get_min_sdk_version",
                    "Unknown"
                ),
                "target_sdk": _safe_call(
                    a,
                    "get_target_sdk_version",
                    "Unknown"
                ),
                "permissions": perms,
                "activities": acts,
                "services": svcs,
                "receivers": recs,
                "providers": provs,
                "custom_permissions": custom,
            }

            evidence = _build_evidence(
                apk_path,
                manifest_data,
                dex_count=len(dex_objects),
                opcode_instructions=total_ops,
                analysis_mode="full"
            )

            return evidence, op_counts

        except Exception as dex_error:

            error_text = str(dex_error)

            # -------------------------------------------------
            # STEP 2: DEX failed -> Manifest-only fallback
            # -------------------------------------------------

            manifest_data = _extract_manifest_only(
                apk_path
            )

            if manifest_data is not None:

                evidence = _build_evidence(
                    apk_path,
                    manifest_data,
                    dex_count=0,
                    opcode_instructions=0,
                    analysis_mode="manifest_only"
                )

                evidence["dex_error"] = error_text

                return evidence, {}

            # -------------------------------------------------
            # STEP 3: APK itself is unreadable
            # -------------------------------------------------

            zip_info = _basic_zip_check(apk_path)

            if not zip_info["is_zip"]:
                raise RuntimeError(
                    "The uploaded file is not a valid APK/ZIP "
                    "or is corrupted."
                )

            raise RuntimeError(
                "APK manifest could not be read. "
                f"DEX analysis error: {error_text}"
            )

    # ---------------------------------------------------------
    # AnalyzeAPK unavailable -> direct APK fallback
    # ---------------------------------------------------------

    manifest_data = _extract_manifest_only(
        apk_path
    )

    if manifest_data is not None:

        evidence = _build_evidence(
            apk_path,
            manifest_data,
            dex_count=0,
            opcode_instructions=0,
            analysis_mode="manifest_only"
        )

        return evidence, {}

    raise RuntimeError(
        "Unable to analyze this APK."
    )


def _load_model():

    if joblib is None:
        return None

    p = Path("models/model.joblib")

    if not p.exists():
        return None

    try:
        return joblib.load(p)

    except Exception:
        # Never crash the dashboard because of a model issue
        return None


def _calculate_scores(evidence, op_counts):

    perms = evidence.get(
        "permissions",
        []
    )

    hits = [
        (p, SENSITIVE[p])
        for p in perms
        if p in SENSITIVE
    ]

    # -------------------------------------------
    # Permission risk
    # -------------------------------------------

    perm_risk = min(
        100,
        sum(w for _, w in hits) * 4
    )

    # -------------------------------------------
    # Android component risk
    # -------------------------------------------

    comp_counts = [
        (
            "Activities",
            len(evidence.get("activities", []))
        ),
        (
            "Services",
            len(evidence.get("services", []))
        ),
        (
            "Receivers",
            len(evidence.get("receivers", []))
        ),
        (
            "Providers",
            len(evidence.get("providers", []))
        ),
    ]

    comp_risk = min(
        100,
        sum(n for _, n in comp_counts) * 5
    )

    # -------------------------------------------
    # DEX risk
    # -------------------------------------------

    dex_present = evidence.get(
        "dex_files",
        0
    ) > 0

    opcode_count = evidence.get(
        "opcode_instructions",
        0
    )

    dex_risk = min(
        100,
        int(bool(op_counts)) * 35
        + int(opcode_count > 10000) * 25
    )

    # -------------------------------------------
    # Base threat score
    # -------------------------------------------

    base_score = min(
        99,
        5
        + perm_risk * 0.45
        + comp_risk * 0.20
        + dex_risk * 0.35
    )

    return (
        hits,
        comp_counts,
        perm_risk,
        comp_risk,
        dex_risk,
        base_score
    )


def analyze_apk(apk_path):

    try:
        evidence, op_counts = extract_features(
            apk_path
        )

    except Exception as error:

        # Return structured result instead of crashing Streamlit
        return {
            "verdict": "UNKNOWN",
            "confidence": None,
            "threat_score": 0,
            "permission_risk": 0,
            "component_risk": 0,
            "dex_risk": 0,
            "indicator_count": 0,
            "permissions": [],
            "components": [],
            "dex_files": 0,
            "opcode_ngrams": 0,
            "dex_details": [
                {
                    "dex_files": 0,
                    "opcode_instructions": 0,
                    "nonzero_opcode_2grams": 0
                }
            ],
            "evidence": {
                "sha256": hashlib.sha256(
                    Path(apk_path).read_bytes()
                ).hexdigest(),
                "analysis_mode": "failed",
                "error": str(error)
            },
            "explanation": (
                "The APK could not be completely analyzed. "
                "The application did not execute the APK. "
                f"Analysis error: {error}"
            ),
        }

    (
        hits,
        comp_counts,
        perm_risk,
        comp_risk,
        dex_risk,
        base_score
    ) = _calculate_scores(
        evidence,
        op_counts
    )

    # ---------------------------------------------------------
    # ML MODEL
    # ---------------------------------------------------------

    model = _load_model()

    confidence = None
    ml_prediction = None

    if model is not None:

        try:

            feature_names = getattr(
                model,
                "feature_names_in_",
                None
            )

            if feature_names is not None:

                perms = evidence.get(
                    "permissions",
                    []
                )

                vec = {
                    f"perm::{p}": int(
                        p in perms
                    )
                    for p in SENSITIVE
                }

                vec.update({
                    f"op2::{k}": v
                    for k, v in op_counts.items()
                })

                vec.update({
                    "num_activities": len(
                        evidence.get(
                            "activities",
                            []
                        )
                    ),
                    "num_services": len(
                        evidence.get(
                            "services",
                            []
                        )
                    ),
                    "num_receivers": len(
                        evidence.get(
                            "receivers",
                            []
                        )
                    ),
                    "num_providers": len(
                        evidence.get(
                            "providers",
                            []
                        )
                    ),
                    "num_permissions": len(
                        perms
                    ),
                })

                X = np.array(
                    [
                        [
                            vec.get(
                                str(feature),
                                0
                            )
                            for feature in feature_names
                        ]
                    ],
                    dtype=float
                )

                ml_prediction = int(
                    model.predict(X)[0]
                )

                if hasattr(
                    model,
                    "predict_proba"
                ):
                    confidence = float(
                        np.max(
                            model.predict_proba(X)[0]
                        )
                    )

        except Exception as model_error:

            ml_prediction = None
            confidence = None

    # ---------------------------------------------------------
    # VERDICT
    # ---------------------------------------------------------

    if ml_prediction is not None:

        verdict = (
            "MALWARE"
            if ml_prediction == 1
            else "BENIGN"
        )

        explanation = (
            "Prediction generated using the trained "
            "machine-learning model."
        )

    else:

        verdict = (
            "MALWARE"
            if base_score >= 60
            else "BENIGN"
        )

        if evidence.get(
            "analysis_mode"
        ) == "manifest_only":

            explanation = (
                "Manifest-level analysis completed. "
                "DEX analysis was skipped because the APK "
                "contained an invalid or unreadable DEX file. "
                "The displayed threat score is therefore "
                "based on available static manifest indicators "
                "and should not be presented as a full DEX+ML "
                "classification."
            )

        else:

            explanation = (
                "Prototype heuristic because "
                "models/model.joblib is not present. "
                "Do not report this heuristic as the "
                "paper's trained classifier."
            )

    # ---------------------------------------------------------
    # FINAL RESULT
    # ---------------------------------------------------------

    return {
        "verdict": verdict,
        "confidence": confidence,
        "threat_score": round(
            base_score,
            2
        ),
        "permission_risk": round(
            perm_risk,
            2
        ),
        "component_risk": round(
            comp_risk,
            2
        ),
        "dex_risk": round(
            dex_risk,
            2
        ),
        "indicator_count": len(
            hits
        ),
        "permissions": [
            (
                p,
                "HIGH" if w >= 9 else "MEDIUM",
                w
            )
            for p, w in hits
        ],
        "components": comp_counts,
        "dex_files": evidence.get(
            "dex_files",
            0
        ),
        "opcode_ngrams": len(
            op_counts
        ),
        "dex_details": [
            {
                "dex_files": evidence.get(
                    "dex_files",
                    0
                ),
                "opcode_instructions": evidence.get(
                    "opcode_instructions",
                    0
                ),
                "nonzero_opcode_2grams": len(
                    op_counts
                ),
            }
        ],
        "evidence": evidence,
        "explanation": explanation,
    }
