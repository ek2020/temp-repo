
import streamlit as st
import pandas as pd
import plotly.express as px
import json, glob, io, os

# ------------------------- PAGE SETUP -------------------------
st.set_page_config(page_title="AWS Security Posture Dashboard", layout="wide")

st.markdown(
    "<h2 style='text-align:center;color:#00BFFF;'>🔐 AWS Security Posture Dashboard</h2>",
    unsafe_allow_html=True
)
st.caption("Aggregated findings across AWS Security Hub, GuardDuty, Inspector, IAM Access Analyzer, and Detective.")
st.markdown("---")

# ------------------------- LOAD & NORMALIZE FINDINGS -------------------------
records = []

for file in glob.glob("*.json"):
    service_name = os.path.basename(file).split("-")[0].capitalize()
    with open(file) as f:
        data = json.load(f)

        # Handle standard findings (SecurityHub, GuardDuty, etc.)
        findings = data.get("Findings", data.get("findings", []))
        if findings:
            for fnd in findings:
                sev = fnd.get("Severity", "Medium")

                # Normalize severity format
                if isinstance(sev, dict):
                    sev_label = sev.get("Label") or sev.get("Normalized") or "Medium"
                elif isinstance(sev, (int, float)):
                    sev_label = (
                        "Critical" if sev >= 8
                        else "High" if sev >= 5
                        else "Medium" if sev >= 3
                        else "Low"
                    )
                else:
                    sev_label = str(sev).capitalize()

                records.append({
                    "Service": service_name,
                    "Account": fnd.get("AwsAccountId", fnd.get("resourceOwnerAccount", "")),
                    "Region": fnd.get("Region", "us-east-2"),
                    "Resource": str(fnd.get("Resource", fnd.get("resource", ""))),
                    "Severity": sev_label,
                    "Title": fnd.get("Title", fnd.get("id", f"Finding from {service_name}")),
                    "Description": fnd.get("Description", fnd.get("findingDetails", "")),
                    "Status": fnd.get("Workflow", {}).get("Status", fnd.get("status", "ACTIVE")),
                    "CreatedAt": fnd.get("CreatedAt", "")
                })
        else:
            # Handle non-standard JSON (Detective, IAM, etc.)
            records.append({
                "Service": service_name,
                "Account": "",
                "Region": "us-east-2",
                "Resource": "",
                "Severity": "Informational",
                "Title": f"No critical findings for {service_name}",
                "Description": f"{service_name} data loaded but no security findings reported.",
                "Status": "N/A",
                "CreatedAt": ""
            })

# ------------------------- CREATE DATAFRAME -------------------------
df = pd.DataFrame(records)
if df.empty:
    st.warning("No findings detected in this directory.")
    st.stop()

# Normalize severity
df["Severity"] = df["Severity"].str.upper()

# ------------------------- DERIVED COLUMNS -------------------------
def team_map(service):
    s = str(service).lower()
    if "guardduty" in s or "securityhub" in s:
        return "CAPSA Team"
    elif "inspector" in s or "accessanalyzer" in s:
        return "BCG Team"
    elif "detective" in s:
        return "Both BCG & CAPSA Team"
    else:
        return "Others"

def fix_timeline(sev):
    sev = sev.lower()
    if sev == "critical":
        return "5 Days"
    elif sev == "high":
        return "1 Week"
    elif sev == "medium":
        return "2 Weeks"
    elif sev == "low":
        return "3 Weeks"
    else:
        return "N/A"

def fix_cost(sev):
    sev = sev.lower()
    if sev == "critical":
        return "$250/hour"
    elif sev == "high":
        return "$150/hour"
    elif sev == "medium":
        return "$75/hour"
    elif sev == "low":
        return "$25/hour"
    else:
        return "Minimal"

df["Team"] = df["Service"].apply(team_map)
df["Fix Timeline"] = df["Severity"].apply(fix_timeline)
df["Cost to Fix (Est.)"] = df["Severity"].apply(fix_cost)

# ------------------------- FILTER PANEL -------------------------
with st.sidebar:
    st.header("🔍 Filters")
    selected_services = st.multiselect("Service", sorted(df["Service"].unique()))
    selected_severity = st.multiselect("Severity", sorted(df["Severity"].unique()))
    selected_team = st.multiselect("Team", sorted(df["Team"].unique()))

filtered = df.copy()
if selected_services:
    filtered = filtered[filtered["Service"].isin(selected_services)]
if selected_severity:
    filtered = filtered[filtered["Severity"].isin(selected_severity)]
if selected_team:
    filtered = filtered[filtered["Team"].isin(selected_team)]

# ------------------------- METRICS SUMMARY -------------------------
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Findings", len(filtered))
col2.metric("Critical", len(filtered[filtered["Severity"]=="CRITICAL"]))
col3.metric("High", len(filtered[filtered["Severity"]=="HIGH"]))
col4.metric("Medium/Low", len(filtered[filtered["Severity"].isin(["MEDIUM","LOW"])]))

# ------------------------- PLOTLY VISUALS -------------------------
st.markdown("### 📊 Findings Visualization")

c1, c2 = st.columns(2)

with c1:
    fig1 = px.bar(
        filtered.groupby("Severity").size().reset_index(name="Count"),
        x="Severity", y="Count", color="Severity",
        color_discrete_map={
            "CRITICAL":"#ff4d4d",
            "HIGH":"#ffa64d",
            "MEDIUM":"#ffd24d",
            "LOW":"#5cd65c",
            "INFORMATIONAL":"#66ccff"
        },
        title="Findings by Severity"
    )
    fig1.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig1, use_container_width=True)

with c2:
    fig2 = px.pie(
        filtered, names="Team", title="Team Distribution",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    fig2.update_traces(textposition='inside', textinfo='percent+label')
    st.plotly_chart(fig2, use_container_width=True)

# ------------------------- TABLE -------------------------
st.markdown("### 🧾 Detailed Findings Table")
st.dataframe(
    filtered[[
        "Service","Severity","Team","Fix Timeline","Cost to Fix (Est.)",
        "Title","Description","Account","Region","Status"
    ]],
    use_container_width=True,
    hide_index=True
)

# ------------------------- EXCEL EXPORT -------------------------
st.markdown("### 📤 Export Excel Report")

output = io.BytesIO()
with pd.ExcelWriter(output, engine="openpyxl") as writer:
    filtered.to_excel(writer, sheet_name="AWS_Security_Findings", index=False)
excel_bytes = output.getvalue()

st.download_button(
    label="📥 Download Excel Report",
    data=excel_bytes,
    file_name="AWS_Security_Findings_Enhanced.xlsx",
    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

st.success("✅ Dashboard loaded successfully — use filters, charts, or export the Excel summary.")

