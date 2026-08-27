from pathlib import Path
import hashlib
import re
import zipfile

import numpy as np

try:
    import joblib
except Exception:
    joblib = None

try:
    from androguard.core.apk import APK
except Exception:
    APK = None

try:
    from androguard.core.dex import DEX
except Exception:
    DEX = None


# ============================================================
# FIXED 75 ANDROID STATIC FEATURES
# 20 permissions
# 15 manifest/component
# 25 opcode 2-grams
# 10 suspicious API/code indicators
# 5 APK/file indicators
# ============================================================

PERMISSIONS = [
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.RECORD_VIDEO",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.INTERNET",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
]

# 5 categories × 5 categories = 25 fixed opcode 2-grams
OPCODE_CATEGORIES = [
    "move",
    "const",
    "invoke",
    "control",
    "data",
]

OPCODE_FEATURES = [
    f"op2::{a}_{b}"
    for a in OPCODE_CATEGORIES
    for b in OPCODE_CATEGORIES
]

MANIFEST_FEATURES = [
    "num_activities",
    "num_services",
    "num_receivers",
    "num_providers",
    "num_custom_permissions",
    "num_components",
    "num_permissions",
    "min_sdk",
    "target_sdk",
    "sdk_gap",
    "num_exported_components",
    "num_intent_filters",
    "is_debuggable",
    "allow_backup",
    "uses_cleartext_traffic",
]

API_PATTERNS = {
    "api_sms": [
        "smsmanager",
        "sendtextmessage",
        "sendsmsto",
    ],
    "api_telephony": [
        "telephonymanager",
        "getdeviceid",
        "getsubscriberid",
        "simoperator",
    ],
    "api_location": [
        "locationmanager",
        "fusedlocation",
        "getlastknownlocation",
        "requestlocationupdates",
    ],
    "api_camera": [
        "android.hardware.camera",
        "cameramanager",
        "camera2",
    ],
    "api_audio": [
        "mediarecorder",
        "audiorecord",
        "microphone",
    ],
    "api_accessibility": [
        "accessibilityservice",
        "accessibilityevent",
        "accessibilitynodeinfo",
    ],
    "api_dynamic_loading": [
        "dexclassloader",
        "pathclassloader",
        "inmemorydexclassloader",
    ],
    "api_reflection": [
        "java.lang.reflect",
        "method.invoke",
        "class.forname",
        "getdeclaredmethod",
    ],
    "api_process_exec": [
        "runtime.exec",
        "processbuilder",
        "exec(",
        "su",
    ],
    "api_crypto_encoding": [
        "javax.crypto",
        "cipher.getinstance",
        "base64",
        "messagedigest",
    ],
}

API_FEATURES = list(API_PATTERNS.keys())

APK_FEATURES = [
    "num_dex_files",
    "num_dex_instructions",
    "has_native_libs",
    "num_executable_archives",
    "apk_size_mb",
]

FEATURE_NAMES = (
    [f"perm::{p}" for p in PERMISSIONS]
    + MANIFEST_FEATURES
    + OPCODE_FEATURES
    + API_FEATURES
    + APK_FEATURES
)

assert len(FEATURE_NAMES) == 75


# ============================================================
# HELPERS
# ============================================================

def _safe_call(obj, name, default=None):
    try:
        fn = getattr(obj, name, None)

        if callable(fn):
            value = fn()

            if value is None:
                return default

            return value

    except Exception:
        pass

    return default


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _text(value):
    if value is None:
        return ""

    try:
        return str(value).lower()
    except Exception:
        return ""


# ============================================================
# APK ZIP INFORMATION
# ============================================================

def _apk_zip_info(apk_path):

    result = {
        "is_zip": False,
        "has_manifest": False,
        "has_dex": False,
        "dex_files": [],
        "native_libs": 0,
        "executable_archives": 0,
        "file_count": 0,
    }

    try:

        with zipfile.ZipFile(apk_path, "r") as z:

            names = z.namelist()

            result["is_zip"] = True

            result["has_manifest"] = (
                "AndroidManifest.xml" in names
            )

            result["dex_files"] = [
                name
                for name in names
                if re.fullmatch(
                    r"classes(?:\d+)?\.dex",
                    Path(name).name
                )
            ]

            result["has_dex"] = bool(
                result["dex_files"]
            )

            result["native_libs"] = sum(
                1
                for name in names
                if name.startswith("lib/")
                and name.endswith(".so")
            )

            result["executable_archives"] = sum(
                1
                for name in names
                if name.lower().endswith(
                    (
                        ".jar",
                        ".zip",
                        ".bin",
                        ".dat",
                    )
                )
            )

            result["file_count"] = len(names)

    except Exception:
        pass

    return result


# ============================================================
# OPCODE CATEGORY
# ============================================================

def _opcode_category(opcode):

    op = _text(opcode)

    if op.startswith("move"):
        return "move"

    if op.startswith("const"):
        return "const"

    if op.startswith("invoke"):
        return "invoke"

    control_prefixes = (
        "goto",
        "if-",
        "if",
        "switch",
        "return",
        "throw",
        "cmp",
    )

    if op.startswith(control_prefixes):
        return "control"

    return "data"


# ============================================================
# OPCODE FEATURES
# ============================================================

def _opcode_features(dex_objects):

    counts = {
        name: 0
        for name in OPCODE_FEATURES
    }

    total_instructions = 0

    for dex in dex_objects:

        try:

            for cls in dex.get_classes():

                try:
                    methods = cls.get_methods()
                except Exception:
                    continue

                for method in methods:

                    try:

                        code = method.get_code()

                        if not code:
                            continue

                        instructions = (
                            code.get_bc()
                            .get_instructions()
                        )

                        previous = None

                        for instruction in instructions:

                            try:
                                opcode = instruction.get_name()
                            except Exception:
                                continue

                            current = _opcode_category(
                                opcode
                            )

                            if previous is not None:

                                key = (
                                    f"op2::{previous}_{current}"
                                )

                                counts[key] += 1

                            previous = current

                            total_instructions += 1

                    except Exception:
                        continue

        except Exception:
            continue

    return counts, total_instructions


# ============================================================
# DEX TEXT FOR API INDICATORS
# ============================================================

def _dex_text(dex_objects):

    chunks = []

    # Limit keeps very large APKs manageable.
    MAX_ITEMS = 150000

    for dex in dex_objects:

        try:

            for cls in dex.get_classes():

                try:
                    methods = cls.get_methods()
                except Exception:
                    continue

                for method in methods:

                    try:

                        code = method.get_code()

                        if not code:
                            continue

                        for instruction in (
                            code.get_bc()
                            .get_instructions()
                        ):

                            try:
                                chunks.append(
                                    instruction.get_name()
                                )
                            except Exception:
                                pass

                            try:
                                chunks.append(
                                    instruction.get_output()
                                )
                            except Exception:
                                pass

                            if len(chunks) >= MAX_ITEMS:
                                return " ".join(
                                    chunks
                                ).lower()

                    except Exception:
                        continue

        except Exception:
            continue

    return " ".join(chunks).lower()


# ============================================================
# API INDICATORS
# ============================================================

def _api_indicators(dex_text):

    result = {}

    for feature, patterns in API_PATTERNS.items():

        result[feature] = int(
            any(
                pattern.lower() in dex_text
                for pattern in patterns
            )
        )

    return result


# ============================================================
# MANIFEST ATTRIBUTES
# ============================================================

def _manifest_stats(apk):

    result = {
        "num_exported_components": 0,
        "num_intent_filters": 0,
        "is_debuggable": 0,
        "allow_backup": 0,
        "uses_cleartext_traffic": 0,
    }

    try:

        xml = apk.get_android_manifest_xml()

        if xml is None:
            return result

        root = (
            xml.getroot()
            if hasattr(xml, "getroot")
            else xml
        )

        namespace = (
            "{http://schemas.android.com/apk/res/android}"
        )

        def get_attr(element, name):

            try:
                return element.get(
                    namespace + name
                )
            except Exception:
                return None

        applications = list(
            root.iter("application")
        )

        if applications:

            application = applications[0]

            result["is_debuggable"] = int(
                _text(
                    get_attr(
                        application,
                        "debuggable"
                    )
                ) == "true"
            )

            result["allow_backup"] = int(
                _text(
                    get_attr(
                        application,
                        "allowBackup"
                    )
                ) == "true"
            )

            result["uses_cleartext_traffic"] = int(
                _text(
                    get_attr(
                        application,
                        "usesCleartextTraffic"
                    )
                ) == "true"
            )

        exported = 0
        intent_filters = 0

        for tag in [
            "activity",
            "activity-alias",
            "service",
            "receiver",
            "provider",
        ]:

            for node in root.iter(tag):

                if (
                    _text(
                        get_attr(
                            node,
                            "exported"
                        )
                    )
                    == "true"
                ):
                    exported += 1

                intent_filters += sum(
                    1
                    for child in list(node)
                    if getattr(
                        child,
                        "tag",
                        ""
                    ) == "intent-filter"
                )

        result["num_exported_components"] = exported

        result["num_intent_filters"] = (
            intent_filters
        )

    except Exception:
        pass

    return result


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(apk_path):

    if APK is None:

        raise RuntimeError(
            "Androguard is not installed. "
            "Add androguard to requirements.txt."
        )

    apk_path = str(apk_path)

    zip_info = _apk_zip_info(
        apk_path
    )

    if not zip_info["is_zip"]:

        raise RuntimeError(
            "The uploaded file is not a valid APK."
        )

    try:

        apk = APK(apk_path)

        permissions = list(
            _safe_call(
                apk,
                "get_permissions",
                []
            )
            or []
        )

        activities = list(
            _safe_call(
                apk,
                "get_activities",
                []
            )
            or []
        )

        services = list(
            _safe_call(
                apk,
                "get_services",
                []
            )
            or []
        )

        receivers = list(
            _safe_call(
                apk,
                "get_receivers",
                []
            )
            or []
        )

        providers = list(
            _safe_call(
                apk,
                "get_providers",
                []
            )
            or []
        )

        custom_permissions = list(
            _safe_call(
                apk,
                "get_declared_permissions",
                []
            )
            or []
        )

        min_sdk = _safe_int(
            _safe_call(
                apk,
                "get_min_sdk_version",
                0
            )
        )

        target_sdk = _safe_int(
            _safe_call(
                apk,
                "get_target_sdk_version",
                0
            )
        )

        # ----------------------------------------------------
        # Direct DEX loading.
        # IMPORTANT: AnalyzeAPK() is NOT used.
        # ----------------------------------------------------

        dex_objects = []

        try:

            raw_dex = _safe_call(
                apk,
                "get_all_dex",
                []
            )

            raw_dex = raw_dex or []

            if not isinstance(
                raw_dex,
                (list, tuple)
            ):
                raw_dex = [raw_dex]

            for item in raw_dex:

                try:

                    if hasattr(
                        item,
                        "get_classes"
                    ):
                        dex_objects.append(item)

                    elif isinstance(
                        item,
                        (bytes, bytearray)
                    ) and DEX is not None:

                        dex_objects.append(
                            DEX(bytes(item))
                        )

                except Exception:
                    continue

        except Exception:
            dex_objects = []

        # ----------------------------------------------------
        # DEX features
        # ----------------------------------------------------

        opcode_counts, total_instructions = (
            _opcode_features(
                dex_objects
            )
        )

        dex_text = _dex_text(
            dex_objects
        )

        api_flags = _api_indicators(
            dex_text
        )

        manifest_stats = _manifest_stats(
            apk
        )

        component_count = (
            len(activities)
            + len(services)
            + len(receivers)
            + len(providers)
        )

        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        evidence = {

            "package": _safe_call(
                apk,
                "get_package",
                "Unknown"
            ),

            "version_name": _safe_call(
                apk,
                "get_androidversion_name",
                "Unknown"
            ),

            "min_sdk": min_sdk,

            "target_sdk": target_sdk,

            "sha256": hashlib.sha256(
                Path(
                    apk_path
                ).read_bytes()
            ).hexdigest(),

            "permissions": permissions,

            "activities": activities,

            "services": services,

            "receivers": receivers,

            "providers": providers,

            "custom_permissions":
                custom_permissions,

            "dex_files":
                len(
                    zip_info["dex_files"]
                ),

            "opcode_instructions":
                total_instructions,

            "analysis_mode":
                "static_75_features",

            "zip_valid":
                zip_info["is_zip"],

            "has_manifest":
                zip_info["has_manifest"],

            "has_dex":
                zip_info["has_dex"],

            "apk_file_count":
                zip_info["file_count"],

            "native_lib_count":
                zip_info["native_libs"],

            "executable_archive_count":
                zip_info[
                    "executable_archives"
                ],
        }

        # ====================================================
        # BUILD EXACT 75 FEATURES
        # ====================================================

        vector = {}

        # -------------------------------
        # 20 PERMISSION FEATURES
        # -------------------------------

        for permission in PERMISSIONS:

            vector[
                f"perm::{permission}"
            ] = int(
                permission in permissions
            )

        # -------------------------------
        # 15 MANIFEST FEATURES
        # -------------------------------

        vector.update({

            "num_activities":
                len(activities),

            "num_services":
                len(services),

            "num_receivers":
                len(receivers),

            "num_providers":
                len(providers),

            "num_custom_permissions":
                len(custom_permissions),

            "num_components":
                component_count,

            "num_permissions":
                len(permissions),

            "min_sdk":
                min_sdk,

            "target_sdk":
                target_sdk,

            "sdk_gap":
                max(
                    0,
                    target_sdk - min_sdk
                ),

            "num_exported_components":
                manifest_stats[
                    "num_exported_components"
                ],

            "num_intent_filters":
                manifest_stats[
                    "num_intent_filters"
                ],

            "is_debuggable":
                manifest_stats[
                    "is_debuggable"
                ],

            "allow_backup":
                manifest_stats[
                    "allow_backup"
                ],

            "uses_cleartext_traffic":
                manifest_stats[
                    "uses_cleartext_traffic"
                ],
        })

        # -------------------------------
        # 25 OPCODE FEATURES
        # -------------------------------

        vector.update(
            opcode_counts
        )

        # -------------------------------
        # 10 API FEATURES
        # -------------------------------

        vector.update(
            api_flags
        )

        # -------------------------------
        # 5 APK FEATURES
        # -------------------------------

        apk_size_mb = (
            Path(apk_path).stat().st_size
            / (1024 * 1024)
        )

        vector.update({

            "num_dex_files":
                len(
                    zip_info["dex_files"]
                ),

            "num_dex_instructions":
                total_instructions,

            "has_native_libs":
                int(
                    zip_info["native_libs"]
                    > 0
                ),

            "num_executable_archives":
                zip_info[
                    "executable_archives"
                ],

            "apk_size_mb":
                round(
                    apk_size_mb,
                    4
                ),
        })

        # ====================================================
        # FORCE EXACT ORDER / EXACTLY 75 FEATURES
        # ====================================================

        vector = {
            name: vector.get(
                name,
                0
            )
            for name in FEATURE_NAMES
        }

        assert len(vector) == 75

        return (
            evidence,
            vector,
            opcode_counts
        )

    except Exception as error:

        raise RuntimeError(
            f"Static APK extraction failed: {error}"
        ) from error


# ============================================================
# EXPLAINABLE BACKUP RISK SCORE
# NOT A TRAINED MODEL
# ============================================================

PERMISSION_WEIGHTS = {

    "android.permission.CAMERA": 10,

    "android.permission.RECORD_AUDIO": 10,

    "android.permission.RECORD_VIDEO": 8,

    "android.permission.READ_SMS": 9,

    "android.permission.SEND_SMS": 8,

    "android.permission.RECEIVE_SMS": 8,

    "android.permission.READ_CALL_LOG": 8,

    "android.permission.WRITE_CALL_LOG": 8,

    "android.permission.READ_CONTACTS": 7,

    "android.permission.WRITE_CONTACTS": 7,

    "android.permission.ACCESS_FINE_LOCATION": 8,

    "android.permission.ACCESS_COARSE_LOCATION": 5,

    "android.permission.BIND_ACCESSIBILITY_SERVICE": 12,

    "android.permission.RECEIVE_BOOT_COMPLETED": 8,

    "android.permission.INTERNET": 4,

    "android.permission.READ_PHONE_STATE": 5,

    "android.permission.READ_EXTERNAL_STORAGE": 3,

    "android.permission.WRITE_EXTERNAL_STORAGE": 4,

    "android.permission.REQUEST_INSTALL_PACKAGES": 10,

    "android.permission.SYSTEM_ALERT_WINDOW": 9,
}


def _calculate_scores(
    evidence,
    vector
):

    permissions = evidence.get(
        "permissions",
        []
    )

    hits = [
        (
            permission,
            PERMISSION_WEIGHTS[
                permission
            ]
        )
        for permission in permissions
        if permission in PERMISSION_WEIGHTS
    ]

    permission_risk = min(
        100,
        sum(
            weight
            for _, weight in hits
        ) * 3.5
    )

    component_risk = min(
        100,
        vector.get(
            "num_components",
            0
        ) * 2.5
        +
        vector.get(
            "num_exported_components",
            0
        ) * 3.5
    )

    api_risk = min(
        100,
        sum(
            vector.get(
                name,
                0
            )
            for name in API_FEATURES
        ) * 8
    )

    dex_risk = min(
        100,
        (
            35
            if vector.get(
                "num_dex_files",
                0
            ) > 0
            else 0
        )
        +
        (
            20
            if vector.get(
                "num_dex_instructions",
                0
            ) > 10000
            else 0
        )
        +
        (
            10
            if vector.get(
                "has_native_libs",
                0
            )
            else 0
        )
    )

    manifest_risk = min(
        100,
        vector.get(
            "is_debuggable",
            0
        ) * 15
        +
        vector.get(
            "uses_cleartext_traffic",
            0
        ) * 10
        +
        vector.get(
            "num_intent_filters",
            0
        ) * 1.5
    )

    score = min(
        99,
        5
        + permission_risk * 0.40
        + component_risk * 0.15
        + api_risk * 0.20
        + dex_risk * 0.15
        + manifest_risk * 0.10
    )

    return (
        hits,
        permission_risk,
        component_risk,
        api_risk,
        dex_risk,
        manifest_risk,
        score,
    )


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

def _load_model():

    if joblib is None:
        return None

    model_path = Path(
        "models/model.joblib"
    )

    if not model_path.exists():
        return None

    try:
        return joblib.load(
            model_path
        )
    except Exception:
        return None


# ============================================================
# FINAL APK ANALYSIS
# ============================================================

def analyze_apk(apk_path):

    try:

        (
            evidence,
            vector,
            opcode_counts
        ) = extract_features(
            apk_path
        )

    except Exception as error:

        return {

            "verdict": "UNKNOWN",

            "confidence": None,

            "threat_score": 0,

            "permission_risk": 0,

            "component_risk": 0,

            "api_risk": 0,

            "dex_risk": 0,

            "manifest_risk": 0,

            "indicator_count": 0,

            "permissions": [],

            "components": [],

            "dex_files": 0,

            "opcode_ngrams": 0,

            "feature_count": 75,

            "feature_vector": {},

            "dex_details": [{

                "dex_files": 0,

                "opcode_instructions": 0,

                "nonzero_opcode_2grams": 0,
            }],

            "evidence": {

                "sha256":
                    hashlib.sha256(
                        Path(
                            apk_path
                        ).read_bytes()
                    ).hexdigest(),

                "analysis_mode":
                    "failed",

                "error":
                    str(error),
            },

            "explanation":
                "The APK could not be analyzed. "
                "The APK was not executed. "
                f"Static-analysis error: {error}",
        }

    (
        hits,
        permission_risk,
        component_risk,
        api_risk,
        dex_risk,
        manifest_risk,
        base_score,
    ) = _calculate_scores(
        evidence,
        vector
    )

    # ========================================================
    # TRAINED ML MODEL
    # ========================================================

    model = _load_model()

    confidence = None
    ml_prediction = None
    model_error = None

    if model is not None:

        try:

            feature_names = getattr(
                model,
                "feature_names_in_",
                None
            )

            if feature_names is None:

                expected = getattr(
                    model,
                    "n_features_in_",
                    None
                )

                if expected not in (
                    None,
                    75
                ):
                    raise ValueError(
                        f"Model expects "
                        f"{expected} features; "
                        f"this pipeline provides 75."
                    )

                X = np.array(
                    [[
                        vector[name]
                        for name in FEATURE_NAMES
                    ]],
                    dtype=float
                )

            else:

                X = np.array(
                    [[
                        vector.get(
                            str(name),
                            0
                        )
                        for name in feature_names
                    ]],
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

        except Exception as error:

            model_error = str(error)

            ml_prediction = None

            confidence = None

    # ========================================================
    # VERDICT
    # ========================================================

    if ml_prediction is not None:

        verdict = (
            "MALWARE"
            if ml_prediction == 1
            else "BENIGN"
        )

        explanation = (
            "Prediction generated using "
            "the trained machine-learning "
            "model with the fixed 75-feature "
            "static representation."
        )

    else:

        verdict = (
            "MALWARE"
            if base_score >= 60
            else "BENIGN"
        )

        if model is None:

            explanation = (
                "75 static features were "
                "extracted successfully. "
                "models/model.joblib was not "
                "found, so this is an "
                "explainable backup heuristic "
                "and not a trained ML prediction."
            )

        else:

            explanation = (
                "75 static features were "
                "extracted successfully, but "
                "the trained model could not "
                f"be used: {model_error}. "
                "The displayed verdict is "
                "therefore the backup heuristic."
            )

    component_counts = [

        (
            "Activities",
            len(
                evidence.get(
                    "activities",
                    []
                )
            )
        ),

        (
            "Services",
            len(
                evidence.get(
                    "services",
                    []
                )
            )
        ),

        (
            "Receivers",
            len(
                evidence.get(
                    "receivers",
                    []
                )
            )
        ),

        (
            "Providers",
            len(
                evidence.get(
                    "providers",
                    []
                )
            )
        ),
    ]

    return {

        "verdict":
            verdict,

        "confidence":
            confidence,

        "threat_score":
            round(
                base_score,
                2
            ),

        "permission_risk":
            round(
                permission_risk,
                2
            ),

        "component_risk":
            round(
                component_risk,
                2
            ),

        "api_risk":
            round(
                api_risk,
                2
            ),

        "dex_risk":
            round(
                dex_risk,
                2
            ),

        "manifest_risk":
            round(
                manifest_risk,
                2
            ),

        "indicator_count":
            len(hits),

        "permissions": [

            (
                permission,
                (
                    "HIGH"
                    if weight >= 9
                    else "MEDIUM"
                ),
                weight,
            )

            for permission, weight
            in hits
        ],

        "components":
            component_counts,

        "dex_files":
            evidence.get(
                "dex_files",
                0
            ),

        "opcode_ngrams":
            sum(
                1
                for value
                in opcode_counts.values()
                if value > 0
            ),

        "feature_count":
            75,

        "feature_vector":
            vector,

        "dex_details": [{

            "dex_files":
                evidence.get(
                    "dex_files",
                    0
                ),

            "opcode_instructions":
                evidence.get(
                    "opcode_instructions",
                    0
                ),

            "nonzero_opcode_2grams":
                sum(
                    1
                    for value
                    in opcode_counts.values()
                    if value > 0
                ),
        }],

        "evidence":
            evidence,

        "explanation":
            explanation,
    }
