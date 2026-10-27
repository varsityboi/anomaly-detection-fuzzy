"""GrayZone dashboard: replays the test traffic and shows the neuro-fuzzy risk level for every flow.
Run from the project folder:  streamlit run app/dashboard.py"""
import pandas as pd
import streamlit as st

st.set_page_config(page_title="GrayZone", layout="wide")
LEVELS = {0: "Monitor", 1: "Investigate", 2: "High"}

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