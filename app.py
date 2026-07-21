import streamlit as st
import zipfile
import json
import os
import hashlib
import tempfile
import numpy as np

st.set_page_config(page_title="BeamNG Mod Anti-Theft Checker", layout="wide")

st.title("🚗 BeamNG.drive Mod Theft Inspector")
st.write("Upload an original mod ZIP and a suspect mod ZIP to check for copied JBeam nodes or duplicate asset files.")

col1, col2 = st.columns(2)
with col1:
    orig_file = st.file_uploader("Upload Original Mod (.zip)", type=["zip"])
with col2:
    susp_file = st.file_uploader("Upload Suspect Mod (.zip)", type=["zip"])

def get_file_hashes(extract_path):
    hashes = {}
    for root, _, files in os.walk(extract_path):
        for f in files:
            if not f.endswith(('.jbeam', '.json', '.txt')):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, extract_path)
                with open(full_path, 'rb') as fp:
                    hashes[rel_path] = hashlib.md5(fp.read()).hexdigest()
    return hashes

def extract_jbeam_nodes(jbeam_path):
    nodes = []
    try:
        with open(jbeam_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.split('//')[0] for line in f.readlines()]
            content = "".join(lines)
            data = json.loads(content)
            for part_key, part_val in data.items():
                if isinstance(part_val, dict) and "nodes" in part_val:
                    for node in part_val["nodes"]:
                        if isinstance(node, list) and len(node) >= 4 and isinstance(node[1], (int, float)):
                            nodes.append([node[1], node[2], node[3]])
    except Exception:
        pass
    return nodes

if orig_file and susp_file:
    if st.button("Run Theft Inspection"):
        with st.spinner("Extracting and analyzing mod structures..."):
            with tempfile.TemporaryDirectory() as tmpdir:
                orig_dir = os.path.join(tmpdir, "original")
                susp_dir = os.path.join(tmpdir, "suspect")
                
                with zipfile.ZipFile(orig_file, 'r') as z: z.extractall(orig_dir)
                with zipfile.ZipFile(susp_file, 'r') as z: z.extractall(susp_dir)

                orig_hashes = get_file_hashes(orig_dir)
                susp_hashes = get_file_hashes(susp_dir)
                matching_hashes = set(orig_hashes.values()) & set(susp_hashes.values())
                
                orig_nodes = []
                for root, _, files in os.walk(orig_dir):
                    for f in files:
                        if f.endswith('.jbeam'):
                            orig_nodes.extend(extract_jbeam_nodes(os.path.join(root, f)))
                            
                susp_nodes = []
                for root, _, files in os.walk(susp_dir):
                    for f in files:
                        if f.endswith('.jbeam'):
                            susp_nodes.extend(extract_jbeam_nodes(os.path.join(root, f)))

                node_match_pct = 0.0
                if orig_nodes and susp_nodes:
                    orig_arr = np.array(orig_nodes)
                    susp_arr = np.array(susp_nodes)
                    matches = sum(1 for pt in orig_arr if np.min(np.linalg.norm(susp_arr - pt, axis=1)) < 0.001)
                    node_match_pct = (matches / len(orig_arr)) * 100

                st.subheader("Inspection Results")
                res_col1, res_col2 = st.columns(2)
                with res_col1:
                    st.metric("JBeam Physics Overlap", f"{node_match_pct:.1f}%")
                    if node_match_pct > 80:
                        st.error("🚨 Critical: High probability of stolen/cloned JBeam structure!")
                    elif node_match_pct > 40:
                        st.warning("⚠️ Warning: Significant node overlap detected.")
                    else:
                        st.success("✅ Clean: JBeam structure appears distinct.")

                with res_col2:
                    st.metric("Identical Raw Asset Files", f"{len(matching_hashes)}")
                    if len(matching_hashes) > 0:
                        st.error(f"🚨 Found {len(matching_hashes)} exact-match asset/texture files!")
                    else:
                        st.success("✅ Clean: No exact asset hash matches found.")
