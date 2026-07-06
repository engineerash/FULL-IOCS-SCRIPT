import streamlit as st
from collections import defaultdict
import os
import io
import pandas as pd
from ioc_fanger import fang

# 1. Page Configuration
st.set_page_config(page_title="SOC Unified IOC Tool", layout="wide", page_icon="🛡️")
st.title("🛡️ SOC Hunting: Multi-Client AQL Generator & Parser")

# 2. Sidebar / Top level Configuration
# Added "SHL" to the client list
client = st.selectbox("Select Client", ["Tarshid", "Alraedah", "SHL"])
uploaded_file = st.file_uploader("Upload your IOC file", type=['csv', 'txt', 'xlsx'])

# Checkbox to let you choose if you want to defang and normalize types first
apply_defang = st.checkbox("Apply Defanging & Type Standardization", value=True)

# Define target types mapping for QRadar AQL schema compatibility
def get_standard_label(raw_label):
    label = str(raw_label).lower().replace("_", " ").strip()
    if any(x in label for x in ["md5"]): return "md5"
    if any(x in label for x in ["sha1"]): return "sha1"
    if any(x in label for x in ["sha256"]): return "sha256"
    if any(x in label for x in ["sender", "from"]): return "mailsender"
    if any(x in label for x in ["subject", "title"]): return "subject"
    if any(x in label for x in ["file path", "path"]): return "filepath"
    if any(x in label for x in ["file"]): return "file"
    if any(x in label for x in ["ip", "address"]): return "ip address"
    if any(x in label for x in ["fqdn", "domain"]): return "fqdn"
    if any(x in label for x in ["url", "link"]): return "url"
    return "other"

# AQL Mapping Config
CONFIG = {
    'domain': {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True, 'can_ref_set': False},
    'fqdn':   {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True, 'can_ref_set': False},
    'url':    {'col': 'URL', 'cat': 'URL', 'is_ilike': True, 'can_ref_set': False},
    'mailsender': {'col': 'sender', 'cat': 'MailSender', 'is_ilike': True, 'can_ref_set': False},
    'subject':    {'col': 'subject', 'cat': 'MailSubject', 'is_ilike': True, 'can_ref_set': False},
    'md5':        {'col': 'MD5 Hash', 'cat': 'MD5', 'is_ilike': False, 'can_ref_set': True},
    'sha256':     {'col': 'SHA256 Hash', 'cat': 'SHA256', 'is_ilike': False, 'can_ref_set': True},
    'sha1':       {'col': 'SHA1 Hash', 'cat': 'SHA1', 'is_ilike': False, 'can_ref_set': True},
    'ip':         {'col': 'sourceIP', 'cat': 'IP', 'is_ilike': False, 'can_ref_set': True},
    'ip address': {'col': 'sourceIP', 'cat': 'IP', 'is_ilike': False, 'can_ref_set': True},
    'file':       {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False, 'can_ref_set': False},
    'filename':   {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False, 'can_ref_set': False},
    'filepath':   {'col': 'FilePath', 'cat': 'FileArtifacts', 'is_ilike': True, 'can_ref_set': False}
}

def get_chunks(vals, conf, base_query, limit=2023):
    if conf['is_ilike']:
        full_cond = " OR ".join([f'"{conf["col"]}" ILIKE \'%{v}%\'' for v in vals])
    else:
        full_cond = f'("{conf["col"]}" IN ({",".join([f"\'{v}\'" for v in vals])}))'
    if len(base_query) + len(full_cond) <= limit: return [vals]
    if conf['can_ref_set']: return "REF_SET"
    
    chunks, current_chunk, current_length = [], [], len(base_query)
    for v in vals:
        cond = f' OR "{conf["col"]}" ILIKE \'%{v}%\'' if conf['is_ilike'] else f"'{v}',"
        if current_length + len(cond) > limit and current_chunk:
            chunks.append(current_chunk)
            current_chunk, current_length = [], len(base_query)
        current_chunk.append(v)
        current_length += len(cond)
    if current_chunk: chunks.append(current_chunk)
    return chunks

if uploaded_file:
    file_basename = os.path.splitext(uploaded_file.name)[0]
    ref_set_name = f"{file_basename}_Hashes"
    
    indicators = defaultdict(list)
    all_hashes = [] 
    
    try:
        # --- DATA INGESTION ---
        raw_rows = []
        
        if uploaded_file.name.endswith('.xlsx'):
            df = pd.read_excel(uploaded_file, header=None)
            for _, row in df.iterrows():
                if len(row) >= 2 and pd.notna(row[0]) and pd.notna(row[1]):
                    raw_rows.append((str(row[0]), str(row[1])))
        else:
            file_bytes = uploaded_file.read()
            content = None
            for encoding_type in ['utf-8-sig', 'utf-8', 'cp1256', 'windows-1256', 'latin1']:
                try:
                    content = file_bytes.decode(encoding_type)
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                st.error("Could not parse file text encoding.")
                st.stop()

            for line in content.strip().split('\n'):
                if not line or ',' not in line: continue
                parts = [x.strip() for x in line.rsplit(',', 1)]
                if len(parts) == 2:
                    raw_rows.append((parts[1], parts[0]))
        
        # --- EXTRACTION PROCESSING ---
        for raw_type, raw_value in raw_rows:
            if str(raw_value).lower() == 'nan': continue
            
            if apply_defang:
                clean_type = get_standard_label(raw_type)
                clean_value = fang(str(raw_value))
                if clean_type in ["fqdn", "domain"]:
                    clean_value = clean_value.replace("[", "").replace("]", "")
            else:
                clean_type = raw_type.lower().strip()
                clean_value = raw_value.strip()

            if clean_type in CONFIG:
                if clean_value not in indicators[clean_type]:
                    indicators[clean_type].append(clean_value)
                if clean_type in ['md5', 'sha256', 'sha1'] and clean_value not in all_hashes:
                    all_hashes.append(clean_value)

        # --- UI DISPLAY & EXPORT ---
        if indicators:
            if apply_defang:
                st.success("✨ Data standardized and parsed successfully!")
            
            preview_data = [{"Value": val, "Type": key.upper()} for key, vals in indicators.items() for val in vals]
            preview_df = pd.DataFrame(preview_data)
            
            st.write("### Processed IOC Preview")
            st.dataframe(preview_df)
            
            # Excel export buffer
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                preview_df.to_excel(writer, index=False, sheet_name='Processed IOCs')
            
            st.download_button(
                label="📥 Download Defanged/Processed IOCs (.xlsx)",
                data=excel_buffer.getvalue(),
                file_name=f"processed_{file_basename}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

        # Handle Reference Set Exports
        if all_hashes:
            df_hashes = pd.DataFrame(all_hashes, columns=['Hash'])
            hash_buffer = io.BytesIO()
            with pd.ExcelWriter(hash_buffer, engine='openpyxl') as writer:
                df_hashes.to_excel(writer, index=False, sheet_name='Hashes')
                
            st.sidebar.download_button(
                label=f"📥 Export {ref_set_name}.xlsx",
                data=hash_buffer.getvalue(),
                file_name=f"{ref_set_name}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

        # --- GENERATE QUERIES ---
        # Adjusted logic: Only Tarshid gets the domain filter constraint. Alraedah and SHL pass cleanly.
        domain_filter = ' WHERE "domainId"=\'3\' AND ' if client == "Tarshid" else ' WHERE '
        st.subheader(f"Generated Queries for {client}")

        for label, vals in indicators.items():
            conf = CONFIG[label]
            scan_name = f"{file_basename}-HUNT-{conf['cat']}"
            base_query = f"SELECT '{scan_name}' AS 'Scan Name', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{conf['col']}\" FROM events {domain_filter} "
            
            with st.expander(f"{label.upper()} ({len(vals)} items)"):
                result = get_chunks(vals, conf, base_query)
                if result == "REF_SET":
                    st.info(f"Query too long. Using Reference Set: {ref_set_name}")
                    st.code(f"{base_query} (\"{conf['col']}\" IN REFERENCE_SET('{ref_set_name}')) ORDER BY \"startTime\" DESC LAST 90 DAYS", language="sql")
                else:
                    for i, chunk in enumerate(result):
                        if conf['is_ilike']:
                            cond = " OR ".join([f'"{conf["col"]}" ILIKE \'%{v}%\'' for v in chunk])
                            query = f"{base_query} ({cond}) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                        else:
                            vals_str = ",".join([f"'{v}'" for v in chunk])
                            query = f"{base_query} (\"{conf['col']}\" IN ({vals_str})) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                        if len(result) > 1: st.write(f"**Query Part {i+1}**")
                        st.code(query, language="sql")
                        
    except Exception as e:
        st.error(f"Error parsing file data: {e}")
