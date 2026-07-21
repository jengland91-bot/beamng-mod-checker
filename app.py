import streamlit as st
import zipfile
import json
import os
import hashlib
import tempfile
import difflib
import re
import numpy as np
import trimesh
from PIL import Image
import imagehash

st.set_page_config(page_title="BeamNG Comprehensive Mod Inspector", layout="wide")

st.title("🛡️ BeamNG.drive Ultra Mod Theft Inspector")
st.write("Upload ONE suspect mod ZIP and check it against MULTIPLE original mod ZIPs for a complete forensic audit.")

col1, col2 = st.columns(2)
with col1:
    susp_file = st.file_uploader("Upload Suspect Mod (.zip)", type=["zip"])
with col2:
    orig_files = st.file_uploader("Upload Original Mods (.zip)", type=["zip"], accept_multiple_files=True)

def sanitize_jbeam_text(text):
    """Strips comments and trailing commas so BeamNG's custom JSON format parses cleanly."""
    # Remove block comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # Remove line comments
    lines = [line.split('//')[0] for line in text.splitlines()]
    clean_text = "\n".join(lines)
    # Remove trailing commas before closing braces/brackets
    clean_text = re.sub(r',\s*([\]}])', r'\1', clean_text)
    return clean_text

def get_all_file_hashes(extract_path):
    hashes = {}
    for root, _, files in os.walk(extract_path):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, extract_path)
            try:
                with open(full_path, 'rb') as fp:
                    hashes[rel_path] = hashlib.md5(fp.read()).hexdigest()
            except Exception:
                pass
    return hashes

def extract_jbeam_nodes_and_subsystems(jbeam_path):
    nodes = []
    torque_curves = []
    part_names = []
    try:
        with open(jbeam_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_content = f.read()
            clean_content = sanitize_jbeam_text(raw_content)
            data = json.loads(clean_content)
            
            for part_key, part_val in data.items():
                if isinstance(part_val, dict):
                    # Part Name
                    if "information" in part_val and isinstance(part_val["information"], dict):
                        if "name" in part_val["information"]:
                            part_names.append(str(part_val["information"]["name"]))
                    
                    # Nodes (Extract 3D coordinates safely)
                    if "nodes" in part_val and isinstance(part_val["nodes"], list):
                        for node in part_val["nodes"]:
                            if isinstance(node, list) and len(node) >= 4:
                                # Check if coordinates are numbers
                                if all(isinstance(node[i], (int, float)) for i in (1, 2, 3)):
                                    nodes.append([float(node[1]), float(node[2]), float(node[3])])
                    
                    # Engine Torque Curves
                    if "mainEngine" in part_val and isinstance(part_val["mainEngine"], dict):
                        if "torque" in part_val["mainEngine"]:
                            t_data = part_val["mainEngine"]["torque"]
                            if isinstance(t_data, list):
                                curve = [pt for pt in t_data if isinstance(pt, list) and len(pt) >= 2]
                                if len(curve) > 3:
                                    torque_curves.append(curve)
    except Exception:
        # Fallback: Regex extraction for nodes if JSON parsing fails completely
        try:
            with open(jbeam_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Matches node array pattern: ["node_id", x, y, z]
                matches = re.findall(r'\[\s*"[^"]+"\s*,\s*(-?\d+\.?\d*)\s*,\s*(-?\d+\.?\d*)\s*,\s*(-?\d+\.?\d*)', content)
                for m in matches:
                    nodes.append([float(m[0]), float(m[1]), float(m[2])])
        except Exception:
            pass

    return nodes, torque_curves, part_names

def analyze_meshes(extract_path):
    mesh_stats = []
    for root, _, files in os.walk(extract_path):
        for f in files:
            if f.endswith('.dae'):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, extract_path)
                try:
                    scene = trimesh.load(full_path, force='mesh')
                    meshes = [scene] if isinstance(scene, trimesh.Trimesh) else (scene.geometry.values() if isinstance(scene, trimesh.Scene) else [])
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

def check_code_similarity(orig_dir, susp_dir):
    code_matches = []
    orig_text_files = {}
    
    for root, _, files in os.walk(orig_dir):
        for f in files:
            if f.endswith(('.lua', '.json', '.jbeam', '.cs', '.html', '.js')):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, orig_dir)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as fp:
                        orig_text_files[rel_path] = fp.read()
                except Exception:
                    pass

    for root, _, files in os.walk(susp_dir):
        for f in files:
            if f.endswith(('.lua', '.json', '.jbeam', '.cs', '.html', '.js')):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, susp_dir)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as fp:
                        susp_text = fp.read()
                        if len(susp_text) > 50:
                            for o_path, o_text in orig_text_files.items():
                                if len(o_text) > 50:
                                    ratio = difflib.SequenceMatcher(None, o_text, susp_text).ratio()
                                    if ratio > 0.80:
                                        code_matches.append((o_path, rel_path, ratio * 100))
                except Exception:
                    pass
    return code_matches

def check_material_paths(orig_dir, susp_dir):
    path_matches = []
    orig_folder_names = set()
    
    v_path = os.path.join(orig_dir, "vehicles")
    if os.path.exists(v_path):
        orig_folder_names = {f.lower() for f in os.listdir(v_path) if os.path.isdir(os.path.join(v_path, f))}

    for root, _, files in os.walk(susp_dir):
        for f in files:
            if f in ('materials.json', 'materials.cs') or f.endswith('.jbeam'):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, susp_dir)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as fp:
                        content = fp.read().lower()
                        for folder in orig_folder_names:
                            if f"vehicles/{folder}" in content:
                                path_matches.append((rel_path, folder))
                except Exception:
                    pass
    return path_matches

if susp_file and orig_files:
    if st.button("Run Full Forensic Audit"):
        with st.spinner("Scanning 3D Meshes, JBeams, Subsystems, Textures, Code, and Material Paths..."):
            with tempfile.TemporaryDirectory() as tmpdir:
                susp_dir = os.path.join(tmpdir, "suspect")
                with zipfile.ZipFile(susp_file, 'r') as z: z.extractall(susp_dir)

                susp_hashes = get_all_file_hashes(susp_dir)
                
                susp_nodes, susp_torque, susp_parts = [], [], []
                for root, _, files in os.walk(susp_dir):
                    for f in files:
                        if f.endswith('.jbeam'):
                            n, t, p = extract_jbeam_nodes_and_subsystems(os.path.join(root, f))
                            susp_nodes.extend(n)
                            susp_torque.extend(t)
                            susp_parts.extend(p)
                
                susp_meshes = analyze_meshes(susp_dir)
                susp_tex = analyze_textures(susp_dir)

                st.subheader("📊 Complete Subsystem Audit Report")
                
                for idx, orig_file in enumerate(orig_files):
                    orig_dir = os.path.join(tmpdir, f"original_{idx}")
                    with zipfile.ZipFile(orig_file, 'r') as z: z.extractall(orig_dir)

                    # 1. Exact Binary File Matches
                    orig_hashes = get_all_file_hashes(orig_dir)
                    matching_hash_files = [(o, s) for o, oh in orig_hashes.items() for s, sh in susp_hashes.items() if oh == sh]

                    # 2. JBeam Nodes & Curves
                    orig_nodes, orig_torque, orig_parts = [], [], []
                    for root, _, files in os.walk(orig_dir):
                        for f in files:
                            if f.endswith('.jbeam'):
                                n, t, p = extract_jbeam_nodes_and_subsystems(os.path.join(root, f))
                                orig_nodes.extend(n)
                                orig_torque.extend(t)
                                orig_parts.extend(p)

                    node_match_pct = 0.0
                    if orig_nodes and susp_nodes:
                        orig_arr = np.array(orig_nodes)
                        susp_arr = np.array(susp_nodes)
                        # Normalize coordinate origins (center of mass) to ignore position shifts
                        orig_arr_norm = orig_arr - np.mean(orig_arr, axis=0)
                        susp_arr_norm = susp_arr - np.mean(susp_arr, axis=0)
                        
                        matches = sum(1 for pt in orig_arr_norm if np.min(np.linalg.norm(susp_arr_norm - pt, axis=1)) < 0.005)
                        node_match_pct = (matches / len(orig_arr_norm)) * 100

                    # Check Torque Curves & Part Names
                    torque_matches = [ot for ot in orig_torque if ot in susp_torque]
                    part_matches = set(orig_parts) & set(susp_parts)

                    # 3. 3D Meshes (.dae topology)
                    orig_meshes = analyze_meshes(orig_dir)
                    flagged_meshes = [(om[0], sm[0], om[1], om[2]) for om in orig_meshes for sm in susp_meshes if om[1] == sm[1] and om[2] == sm[2]]

                    # 4. Textures (Perceptual Hashing)
                    orig_tex = analyze_textures(orig_dir)
                    stolen_skins, stolen_general_tex = [], []
                    skin_keywords = ['skin', 'livery', 'wrap', 'decal', 'color', 'paint']
                    for o_path, o_hash in orig_tex.items():
                        for s_path, s_hash in susp_tex.items():
                            if o_hash - s_hash < 5:
                                if any(k in o_path.lower() or k in s_path.lower() for k in skin_keywords):
                                    stolen_skins.append((o_path, s_path))
                                else:
                                    stolen_general_tex.append((o_path, s_path))

                    # 5. Code & Material Paths
                    code_matches = check_code_similarity(orig_dir, susp_dir)
                    material_path_matches = check_material_paths(orig_dir, susp_dir)

                    # Display Card
                    with st.expander(f"📁 Comparison against: {orig_file.name}", expanded=True):
                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("JBeam Physics Overlap", f"{node_match_pct:.1f}%")
                        c2.metric("Flagged 3D Parts (.dae)", f"{len(flagged_meshes)}")
                        c3.metric("Flagged Skins/Colors", f"{len(stolen_skins)}")
                        c4.metric("Engine & Material Flags", f"{len(torque_matches) + len(material_path_matches)}")

                        if node_match_pct > 25:
                            st.markdown("### 🔧 JBeam Physics Skeleton")
                            st.warning(f"⚠️ **Spatial Node Coordinate Overlap:** {node_match_pct:.1f}% node coordinate match detected.")

                        if len(torque_matches) > 0:
                            st.markdown("### 🏎️ Copied Engine Curves")
                            st.error(f"🚨 **Engine Torque Curve Match:** Found {len(torque_matches)} identical torque/power curve arrays.")

                        if len(material_path_matches) > 0:
                            st.markdown("### 📁 Legacy Material Path References")
                            for file_path, folder in material_path_matches:
                                st.error(f"🚨 Suspect file `{file_path}` explicitly references original folder path: `vehicles/{folder}/`.")

                        if len(part_matches) > 0:
                            st.markdown("### ⚙️ Identical Sub-Part Names")
                            for p_name in part_matches:
                                st.warning(f"• Component Slot Name Match: `{p_name}`")

                        if len(code_matches) > 0:
                            st.markdown("### 📜 Code & UI Similarity (.lua, .json, .html)")
                            for orig_c, susp_c, pct in code_matches:
                                st.write(f"• `{susp_c}` is **{pct:.1f}% identical** to `{orig_c}`")

                        if len(flagged_meshes) > 0:
                            st.markdown("### 🧩 Stolen 3D Mesh Geometry (.dae)")
                            for orig_m, susp_m, verts, faces in flagged_meshes:
                                st.write(f"• Part `{susp_m}` ↔ Original `{orig_m}` (*Vertices: {verts}, Faces: {faces}*)")

                        if len(stolen_skins) > 0:
                            st.markdown("### 🎨 Stolen Skins & Colors")
                            for orig_s, susp_s in stolen_skins:
                                st.write(f"• `{susp_s}` ↔ Original `{orig_s}`")

                        if len(stolen_general_tex) > 0:
                            st.markdown("### 🖼️ Stolen General Textures")
                            for orig_t, susp_t in stolen_general_tex:
                                st.write(f"• `{susp_t}` ↔ Original `{orig_t}`")

                        if len(matching_hash_files) > 0:
                            st.markdown("### 📄 Identical Binary / Audio / Asset Files")
                            for orig_h, susp_h in matching_hash_files:
                                st.write(f"• `{susp_h}` ↔ Original `{orig_h}`")

                        if node_match_pct <= 25 and len(flagged_meshes) == 0 and len(stolen_skins) == 0 and len(code_matches) == 0 and len(torque_matches) == 0 and len(material_path_matches) == 0 and len(matching_hash_files) == 0:
                            st.success(f"✅ Clean: No notable asset overlap found with `{orig_file.name}`.")
