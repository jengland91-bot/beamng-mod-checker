import streamlit as st
import zipfile
import json
import os
import hashlib
import tempfile
import numpy as np
import trimesh
from PIL import Image
import imagehash

st.set_page_config(page_title="BeamNG Detailed Mod Inspector", layout="wide")

st.title("🚗 BeamNG.drive Detailed Theft Inspector")
st.write("Upload ONE suspect mod ZIP and check it against MULTIPLE original mod ZIPs for an itemized breakdown of copied assets.")

col1, col2 = st.columns(2)
with col1:
    susp_file = st.file_uploader("Upload Suspect Mod (.zip)", type=["zip"])
with col2:
    orig_files = st.file_uploader("Upload Original Mods (.zip)", type=["zip"], accept_multiple_files=True)

def get_file_hashes(extract_path):
    hashes = {}
    for root, _, files in os.walk(extract_path):
        for f in files:
            if not f.endswith(('.jbeam', '.json', '.txt', '.dae', '.dds', '.png', '.jpg')):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, extract_path)
                try:
                    with open(full_path, 'rb') as fp:
                        hashes[rel_path] = hashlib.md5(fp.read()).hexdigest()
                except Exception:
                    pass
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

def analyze_meshes(extract_path):
    mesh_stats = []
    for root, _, files in os.walk(extract_path):
        for f in files:
            if f.endswith('.dae'):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, extract_path)
                try:
                    scene = trimesh.load(full_path, force='mesh')
                    if isinstance(scene, trimesh.Trimesh):
                        meshes = [scene]
                    elif isinstance(scene, trimesh.Scene):
                        meshes = scene.geometry.values()
                    else:
                        meshes = []
                    
                    for m in meshes:
                        if hasattr(m, 'vertices') and len(m.vertices) > 0:
                            v_count = len(m.vertices)
                            f_count = len(m.faces)
                            extents = tuple(np.round(m.extents, 3)) if hasattr(m, 'extents') else (0,0,0)
                            mesh_stats.append((rel_path, v_count, f_count, extents))
                except Exception:
                    pass
    return mesh_stats

def analyze_textures(extract_path):
    hashes = {}
    for root, _, files in os.walk(extract_path):
        for f in files:
            if f.lower().endswith(('.png', '.jpg', '.jpeg')):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, extract_path)
                try:
                    with Image.open(full_path) as img:
                        hashes[rel_path] = imagehash.phash(img)
                except Exception:
                    pass
    return hashes

if susp_file and orig_files:
    if st.button("Run Detailed Inspection"):
        with st.spinner("Extracting and running deep item analysis..."):
            with tempfile.TemporaryDirectory() as tmpdir:
                # Extract Suspect Mod
                susp_dir = os.path.join(tmpdir, "suspect")
                with zipfile.ZipFile(susp_file, 'r') as z: z.extractall(susp_dir)

                susp_hashes = get_file_hashes(susp_dir)
                
                susp_nodes = []
                for root, _, files in os.walk(susp_dir):
                    for f in files:
                        if f.endswith('.jbeam'):
                            susp_nodes.extend(extract_jbeam_nodes(os.path.join(root, f)))
                
                susp_meshes = analyze_meshes(susp_dir)
                susp_tex = analyze_textures(susp_dir)

                st.subheader("📊 Detailed Inspection Breakdown")
                
                for idx, orig_file in enumerate(orig_files):
                    orig_dir = os.path.join(tmpdir, f"original_{idx}")
                    with zipfile.ZipFile(orig_file, 'r') as z: z.extractall(orig_dir)

                    # 1. Hashes
                    orig_hashes = get_file_hashes(orig_dir)
                    matching_hash_files = []
                    for o_path, o_hash in orig_hashes.items():
                        for s_path, s_hash in susp_hashes.items():
                            if o_hash == s_hash:
                                matching_hash_files.append((o_path, s_path))

                    # 2. JBeam Nodes
                    orig_nodes = []
                    for root, _, files in os.walk(orig_dir):
                        for f in files:
                            if f.endswith('.jbeam'):
                                orig_nodes.extend(extract_jbeam_nodes(os.path.join(root, f)))

                    node_match_pct = 0.0
                    if orig_nodes and susp_nodes:
                        orig_arr = np.array(orig_nodes)
                        susp_arr = np.array(susp_nodes)
                        matches = sum(1 for pt in orig_arr if np.min(np.linalg.norm(susp_arr - pt, axis=1)) < 0.001)
                        node_match_pct = (matches / len(orig_arr)) * 100

                    # 3. 3D Meshes
                    orig_meshes = analyze_meshes(orig_dir)
                    flagged_meshes = []
                    for o_path, o_v, o_f, o_ext in orig_meshes:
                        for s_path, s_v, s_f, s_ext in susp_meshes:
                            if o_v == s_v and o_f == s_f and o_ext == s_ext:
                                flagged_meshes.append((o_path, s_path, o_v, o_f))
                                break

                    # 4. Textures
                    orig_tex = analyze_textures(orig_dir)
                    stolen_textures = []
                    for o_path, o_hash in orig_tex.items():
                        for s_path, s_hash in susp_tex.items():
                            if o_hash - s_hash < 5:
                                stolen_textures.append((o_path, s_path))

                    # Card Output
                    with st.expander(f"📁 Analysis for: {orig_file.name}", expanded=True):
                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("JBeam Overlap", f"{node_match_pct:.1f}%")
                        c2.metric("Flagged 3D Meshes", f"{len(flagged_meshes)}")
                        c3.metric("Copied Textures", f"{len(stolen_textures)}")
                        c4.metric("Exact File Hashes", f"{len(matching_hash_files)}")

                        # Detailed Itemized Lists
                        if len(stolen_textures) > 0:
                            st.markdown("### 🎨 Copied Texture Files")
                            for orig_t, susp_t in stolen_textures:
                                st.write(f"• **Original:** `{orig_t}` ↔ **Suspect:** `{susp_t}`")

                        if len(flagged_meshes) > 0:
                            st.markdown("### 📐 Flagged 3D Mesh Geometry (.dae)")
                            for orig_m, susp_m, verts, faces in flagged_meshes:
                                st.write(f"• **Original:** `{orig_m}` ↔ **Suspect:** `{susp_m}` (*Vertices: {verts}, Faces: {faces}*)")

                        if len(matching_hash_files) > 0:
                            st.markdown("### 📄 Identical Raw Asset Files")
                            for orig_h, susp_h in matching_hash_files:
                                st.write(f"• **Original:** `{orig_h}` ↔ **Suspect:** `{susp_h}`")

                        if node_match_pct <= 30 and len(flagged_meshes) == 0 and len(stolen_textures) == 0 and len(matching_hash_files) == 0:
                            st.success(f"✅ Clean: No notable asset overlap found with `{orig_file.name}`.")
