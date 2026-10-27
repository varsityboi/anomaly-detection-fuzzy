"""GrayZone dashboard: replays the test traffic and shows the neuro-fuzzy risk level for every flow.
Run from the project folder:  streamlit run app/dashboard.py"""
import pandas as pd
import streamlit as st

st.set_page_config(page_title="GrayZone", layout="wide")
LEVELS = {0: "Monitor", 1: "Investigate", 2: "High"}

# same severity table as in 05_fuzzy (0 = harmless, 1 = worst)
SEVERITY = {
    "BENIGN": 0.0, "PortScan": 0.3,
    "FTP-Patator": 0.5, "SSH-Patator": 0.5, "Web Attack - Brute Force": 0.5, "Web Attack - XSS": 0.6,
    "DoS Hulk": 0.8, "DoS GoldenEye": 0.8, "DoS slowloris": 0.8, "DoS Slowhttptest": 0.8, "DDoS": 0.9,
    "Web Attack - Sql Injection": 0.9, "Bot": 0.9, "Infiltration": 1.0, "Heartbleed": 1.0,
}

def severity_word(s):
    return "None" if s == 0 else ("Low" if s < 0.4 else ("Medium" if s < 0.7 else "High"))

def expected_action(s):
    return "Monitor" if s == 0 else ("Investigate" if s < 0.7 else "High")

@st.cache_data
def load():
    df = pd.read_parquet("data/fuzzy/dashboard.parquet")
    df["level_name"] = df["fuzzy_tuned"].map(LEVELS)
    df["minute"] = df["ts"].dt.floor("min")
    return df

df = load()

# ---------------- sidebar filters ----------------
st.sidebar.title("Filters")
days = sorted(df["ts"].dt.date.unique())
day = st.sidebar.selectbox("Day", days, index=len(days) - 1)
levels = st.sidebar.multiselect("Risk level", list(LEVELS.values()), default=["High", "Investigate"])
ip = st.sidebar.text_input("Source IP contains", "")
show_truth = st.sidebar.checkbox("Show true labels (evaluation mode)", value=True)

d = df[df["ts"].dt.date == day]
if ip:
    d = d[d["Source IP"].str.contains(ip, regex=False)]

# ---------------- header numbers ----------------
st.title("GrayZone: neuro-fuzzy alert triage")
st.caption(f"Test traffic on {day}. Every flow gets a risk score 0-100 from the fuzzy layer.")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Flows", f"{len(d):,}")
c2.metric("High", f"{(d['fuzzy_tuned'] == 2).sum():,}")
c3.metric("Investigate", f"{(d['fuzzy_tuned'] == 1).sum():,}")
c4.metric("Monitor", f"{(d['fuzzy_tuned'] == 0).sum():,}")

if show_truth:
    b = d["label"] == "BENIGN"
    c1, c2 = st.columns(2)
    c1.metric("False High alerts: fuzzy", f"{(b & (d['fuzzy_tuned'] == 2)).sum():,}")
    c2.metric("False High alerts: crisp threshold", f"{(b & (d['crisp_A'] == 2)).sum():,}")

# ---------------- timeline ----------------
st.subheader("Alerts per minute")
timeline = (d[d["fuzzy_tuned"] > 0]
            .pivot_table(index="minute", columns="level_name", values="risk", aggfunc="size", fill_value=0))
if len(timeline):
    st.bar_chart(timeline)
else:
    st.info("No alerts for this selection.")

# ---------------- alert table ----------------
st.subheader("Alerts, highest risk first")
cols = ["ts", "Source IP", "Destination IP", "Destination Port", "level_name", "risk",
        "pred", "p_attack", "anomaly_pct", "scan_evidence", "top_rule"]
if show_truth:
    cols.append("label")
alerts = d[d["level_name"].isin(levels)].sort_values("risk", ascending=False)
st.dataframe(alerts[cols].head(500).round({"risk": 1, "p_attack": 3, "anomaly_pct": 3, "scan_evidence": 3}),
             width="stretch", hide_index=True)

# ---------------- one alert explained ----------------
st.subheader("Why was this flagged?")
if len(alerts):
    pick = st.selectbox("Pick an alert", alerts.index[:200],
                        format_func=lambda i: f"{alerts.at[i, 'ts']:%H:%M}  {alerts.at[i, 'Source IP']}  "
                                              f"risk {alerts.at[i, 'risk']:.0f}  {alerts.at[i, 'level_name']}")
    row = alerts.loc[pick]
    st.markdown(f"**Risk {row['risk']:.0f} → {row['level_name']}**  \nMain reason: *{row['top_rule']}*")
    inputs = pd.Series({"Attack confidence": row["p_attack"], "Anomaly (vs normal)": row["anomaly_pct"],
                        "Severity of likely attack": row["severity"], "Scan evidence": row["scan_evidence"]})
    st.bar_chart(inputs)
    st.write(f"Classifier's best guess: **{row['pred']}**"
             + (f" · true label: **{row['label']}**" if show_truth else ""))

# ---------------- attack lookup ----------------
st.divider()
st.subheader("Attack lookup")
query = st.text_input("Type an attack name (e.g. DoS, Web, Bot, Scan)", "")
scope_all_days = st.checkbox("Search all days (not just the selected one)", value=True)

if query:
    base = df if scope_all_days else d
    q = query.lower()
    matched = sorted(l for l in base["label"].unique() if q in l.lower() and l != "BENIGN")
    if not matched:
        st.warning(f"No attack label contains '{query}'. Known attacks: "
                   + ", ".join(sorted(l for l in SEVERITY if l != "BENIGN")))
    else:
        hits = base[base["label"].isin(matched)]
        summary = []
        for lab in matched:
            g = hits[hits["label"] == lab]
            sev = SEVERITY.get(lab, float("nan"))
            summary.append({
                "attack": lab,
                "severity": sev,
                "severity level": severity_word(sev),
                "should be": expected_action(sev),
                "flows": len(g),
                "High %": round((g["fuzzy_tuned"] == 2).mean() * 100, 1),
                "Investigate %": round((g["fuzzy_tuned"] == 1).mean() * 100, 1),
                "Monitor (missed) %": round((g["fuzzy_tuned"] == 0).mean() * 100, 1),
                "avg risk": round(g["risk"].mean(), 1),
            })
        st.dataframe(pd.DataFrame(summary), width="stretch", hide_index=True)
        st.caption("severity: our danger table (0 = harmless, 1 = worst). "
                   "'should be' = the level this attack type deserves; the % columns show what the fuzzy layer actually gave.")

        st.markdown(f"**{len(hits):,} flows** of: {', '.join(matched)} (highest risk first)")
        show = ["ts", "label", "Source IP", "Destination IP", "Destination Port", "risk",
                "fuzzy_tuned", "pred", "p_attack", "anomaly_pct", "scan_evidence", "top_rule"]
        table = hits.sort_values("risk", ascending=False)[show].head(500)
        table["fuzzy_tuned"] = table["fuzzy_tuned"].map(LEVELS)
        st.dataframe(table.rename(columns={"fuzzy_tuned": "level"})
                          .round({"risk": 1, "p_attack": 3, "anomaly_pct": 3, "scan_evidence": 3}),
                     width="stretch", hide_index=True)