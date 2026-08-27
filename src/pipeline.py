from pathlib import Path
import hashlib, json, re
import numpy as np

try:
    import joblib
except Exception:
    joblib=None

try:
    from androguard.misc import AnalyzeAPK
except Exception:
    AnalyzeAPK=None

SENSITIVE={
"android.permission.CAMERA":10,
"android.permission.RECORD_AUDIO":10,
"android.permission.RECORD_VIDEO":8,
"android.permission.READ_SMS":9,
"android.permission.SEND_SMS":8,
"android.permission.RECEIVE_SMS":8,
"android.permission.READ_CALL_LOG":8,
"android.permission.READ_CONTACTS":7,
"android.permission.ACCESS_FINE_LOCATION":8,
"android.permission.ACCESS_COARSE_LOCATION":5,
"android.permission.BIND_ACCESSIBILITY_SERVICE":12,
"android.permission.RECEIVE_BOOT_COMPLETED":8,
"android.permission.INTERNET":4,
"android.permission.READ_PHONE_STATE":5,
}

# 25 simplified Dalvik opcode categories used as a reproducible implementation
# of the paper's "DEX-level 2-gram opcode features". The paper does not publish
# the exact 25 retained n-grams, so these names are deliberately configurable.
OPCODES=["move","return","const","invoke","new","goto","if","cmp","array","field",
         "monitor","throw","check","instance","switch","add","sub","mul","div",
         "rem","and","or","xor","shl","shr"]

def _opcode_features(dex_objects):
    counts={f"{a}_{b}":0 for a in OPCODES for b in OPCODES}
    total=0
    for d in dex_objects:
        try:
            for c in d.get_classes():
                for m in c.get_methods():
                    code=m.get_code()
                    if not code: continue
                    ins=list(code.get_bc().get_instructions())
                    prev=None
                    for insn in ins:
                        op=insn.get_name().lower()
                        cat=next((x for x in OPCODES if op.startswith(x)), "other")
                        if prev is not None:
                            key=f"{prev}_{cat}"
                            if key in counts: counts[key]+=1
                        prev=cat; total+=1
        except Exception:
            continue
    # top 25 by frequency, represented over the fixed 625-space and then
    # selected downstream by the training CSV.
    top=sorted(counts.items(),key=lambda x:x[1],reverse=True)[:25]
    return dict(top), total

def extract_features(apk_path):
    if AnalyzeAPK is None:
        raise RuntimeError("androguard is not installed. Run: pip install -r requirements.txt")
    a, dex, dx = AnalyzeAPK(apk_path)
    perms=[p for p in (a.get_permissions() or [])]
    acts=a.get_activities() or []
    svcs=a.get_services() or []
    recs=a.get_receivers() or []
    provs=a.get_providers() or []
    custom=[]
    try:
        custom=a.get_declared_permissions() or []
    except Exception:
        pass
    op_counts,total_ops=_opcode_features(dex)
    evidence={
        "package": a.get_package(),
        "version_name": a.get_androidversion_name(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "sha256": hashlib.sha256(Path(apk_path).read_bytes()).hexdigest(),
        "permissions": perms,
        "activities": acts,
        "services": svcs,
        "receivers": recs,
        "providers": provs,
        "custom_permissions": custom,
        "dex_files": len(dex),
        "opcode_instructions": total_ops,
    }
    return evidence,op_counts

def _load_model():
    if joblib is None: return None
    p=Path("models/model.joblib")
    return joblib.load(p) if p.exists() else None

def analyze_apk(apk_path):
    evidence, op_counts=extract_features(apk_path)
    perms=evidence["permissions"]
    hits=[(p,SENSITIVE[p]) for p in perms if p in SENSITIVE]
    perm_risk=min(100,sum(w for _,w in hits)*4)
    comp_counts=[("Activities",len(evidence["activities"])),("Services",len(evidence["services"])),
                 ("Receivers",len(evidence["receivers"])),("Providers",len(evidence["providers"]))]
    comp_risk=min(100,sum(n for _,n in comp_counts)*5)
    dex_risk=min(100,(len(op_counts)>0)*35+(evidence["opcode_instructions"]>10000)*25)
    base_score=min(99,5+perm_risk*.45+comp_risk*.2+dex_risk*.35)

    model=_load_model()
    confidence=None
    if model is not None:
        feature_names=getattr(model,"feature_names_in_",None)
        if feature_names is not None:
            # Manifest features + configurable opcode features.
            vec={f"perm::{p}":int(p in perms) for p in SENSITIVE}
            vec.update({f"op2::{k}":v for k,v in op_counts.items()})
            vec.update({"num_activities":len(evidence["activities"]),
                        "num_services":len(evidence["services"]),
                        "num_receivers":len(evidence["receivers"]),
                        "num_providers":len(evidence["providers"]),
                        "num_permissions":len(perms)})
            X=np.array([[vec.get(f,0) for f in feature_names]],dtype=float)
            pred=int(model.predict(X)[0])
            if hasattr(model,"predict_proba"):
                confidence=float(np.max(model.predict_proba(X)[0]))
            verdict="MALWARE" if pred==1 else "BENIGN"
        else:
            verdict="MALWARE" if base_score>=60 else "BENIGN"
    else:
        verdict="MALWARE" if base_score>=60 else "BENIGN"

    explanation=("Model-backed prediction." if model is not None else
                 "Prototype heuristic because models/model.joblib is not present. "
                 "Do not report this heuristic as the paper's trained classifier.")
    return {
        "verdict":verdict,"confidence":confidence,"threat_score":round(base_score,2),
        "permission_risk":round(perm_risk,2),"component_risk":round(comp_risk,2),
        "dex_risk":round(dex_risk,2),"indicator_count":len(hits),
        "permissions":[(p,"HIGH" if w>=9 else "MEDIUM",w) for p,w in hits],
        "components":comp_counts,"dex_files":evidence["dex_files"],
        "opcode_ngrams":len(op_counts),"dex_details":[
            {"dex_files":evidence["dex_files"],"opcode_instructions":evidence["opcode_instructions"],
             "nonzero_opcode_2grams":len(op_counts)}],
        "evidence":evidence,"explanation":explanation,
    }
