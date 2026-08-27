import io, json, tempfile
from pathlib import Path
import streamlit as st
import pandas as pd
from src.pipeline import analyze_apk

st.set_page_config(page_title="AI Cyber Defense", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.stApp{background:#050b14;color:#eaf7ff}.block-container{max-width:1450px}
h1,h2,h3{letter-spacing:.03em}.metric{background:#091a29;border:1px solid #19425a;padding:16px;border-radius:10px}
</style>""", unsafe_allow_html=True)

st.title("🛡️ AI-Enabled Android Cyber Defense")
st.caption("Research implementation • Manifest + DEX static features • ML classification • Explainable threat scoring")

with st.sidebar:
    st.header("Analysis")
    uploaded=st.file_uploader("Upload Android APK", type=["apk"])
    st.info("The APK is analyzed statically. It is never executed by this application.")
    st.markdown("**Pipeline**")
    st.write("APK → Manifest/DEX → 75-feature vector → ML classifier → threat score → alert")

if not uploaded:
    st.markdown("## Command Center")
    c1,c2,c3,c4=st.columns(4)
    c1.metric("Model", "Research-ready")
    c2.metric("Feature design", "75")
    c3.metric("Analysis", "Static")
    c4.metric("Output", "Malware / Benign")
    st.warning("Upload an APK to begin. A trained model artifact must be placed at `models/model.joblib` before ML predictions are enabled.")
    st.stop()

with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
    f.write(uploaded.getbuffer()); apk_path=f.name

with st.spinner("Performing static APK analysis…"):
    result=analyze_apk(apk_path)

score=result["threat_score"]
verdict=result["verdict"]
st.markdown(f"### {'🔴' if verdict=='MALWARE' else '🟢'} {verdict}")
c1,c2,c3,c4=st.columns(4)
c1.metric("Threat score", f"{score:.1f}/100")
c2.metric("ML confidence", f"{result['confidence']*100:.1f}%" if result["confidence"] is not None else "N/A")
c3.metric("DEX files", result["dex_files"])
c4.metric("Sensitive indicators", result["indicator_count"])

tab1,tab2,tab3,tab4,tab5=st.tabs(["Overview","Permissions","Components","DEX / Opcodes","Evidence"])
with tab1:
    st.progress(min(max(score/100,0),1))
    st.subheader("Threat composition")
    st.bar_chart(pd.DataFrame({"risk":[result["permission_risk"],result["component_risk"],result["dex_risk"]]},
                              index=["Permissions","Components","DEX"]))
    st.info(result["explanation"])
with tab2:
    st.dataframe(pd.DataFrame(result["permissions"], columns=["Permission","Risk","Weight"]), use_container_width=True)
with tab3:
    st.dataframe(pd.DataFrame(result["components"], columns=["Component","Count"]), use_container_width=True)
with tab4:
    st.metric("Opcode 2-gram features observed", result["opcode_ngrams"])
    st.dataframe(pd.DataFrame(result["dex_details"]), use_container_width=True)
with tab5:
    st.json(result["evidence"])

report=json.dumps(result,indent=2,default=str)
st.download_button("Download JSON analysis report",report,
                   file_name=f"{Path(uploaded.name).stem}_cyber_report.json",
                   mime="application/json")
