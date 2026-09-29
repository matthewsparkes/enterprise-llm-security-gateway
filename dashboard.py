import sqlite3
import requests
import streamlit as st
import pandas as pd

DB_FILE = "security_logs.db"
GATEWAY_URL = "http://127.0.0.1:8000/v1/chat/secure-gateway"

st.set_page_config(page_title="Enterprise LLM Security Gateway", layout="wide")

st.title("Enterprise LLM Security Gateway 🛡️")
st.caption("Inspects prompts for data loss prevention (DLP), blocks injections, and enforces fail-closed egress controls.")


# interative console for sending prompts

with st.container(border=True):
    col_u, col_p = st.columns([1, 4])
    with col_u:
        user_id = st.text_input("User ID", value="user_01")
    with col_p:
        user_prompt = st.text_input("Prompt", placeholder="Enter operational question or test prompt...")

    if st.button("Send Prompt", type="primary"):
        if not user_prompt.strip():
            st.warning("Please enter a prompt.")
        else:
            with st.spinner("Evaluating through security gateway..."):
                try:
                    res = requests.post(
                        GATEWAY_URL,
                        json={"user_id": user_id, "prompt": user_prompt},
                        timeout=60
                    )
                    if res.status_code == 200:
                        data = res.json()
                        st.success("Status: 200 OK — Allowed")
                        if data["redactions_applied"]:
                            st.info(f"DLP Redactions: {', '.join(data['redactions_applied'])}")
                        st.text(f"Sanitized Prompt Sent to Model: {data['llm_prompt_sent']}")
                        st.markdown(f"**Model Response:**\n\n{data['llm_response']}")
                    else:
                        err = res.json().get("detail", {})
                        st.error("Status: 403 Forbidden — Blocked by Ingress Perimeter")
                        st.text(f"Violations detected: {err.get('reasons')}")
                except requests.exceptions.Timeout:
                    st.error("Request timed out waiting for the local model.")
                except Exception as e:
                    st.error(f"Could not reach security gateway: {e}")

st.divider()


# audit log table

st.subheader("Security Audit Logs")

def load_data():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            df = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY id DESC", conn)
            if not df.empty:
                if "is_safe" in df.columns:
                    df["is_safe"] = df["is_safe"].map({1: "Yes", 0: "No"}).fillna(df["is_safe"])
                if "timestamp" in df.columns:
                    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", utc=True).dt.strftime("%d %b %Y, %H:%M:%S")
            return df
    except sqlite3.OperationalError:
        return pd.DataFrame()

df = load_data()

if not df.empty:
    display_cols = ["id", "timestamp", "user_id", "is_safe", "prompt_text", "sanitized_text", "llm_response", "violations"]
    st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
else:
    st.info("No audit logs recorded yet. Send a prompt above to generate activity.")

if st.button("Refresh Table"):
    st.rerun()