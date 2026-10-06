import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# =========================
# PAGE SETTINGS
# =========================
st.set_page_config(
    page_title="NetShield AI",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# CSS INSIDE APP.PY
# =========================
st.markdown("""
<style>

.stApp {
    background: linear-gradient(135deg, #020b14, #082238, #03121f);
    color: white;
}

.title {
    text-align: center;
    color: #00e6b8;
    font-size: 48px;
    font-weight: bold;
    margin-top: 20px;
}

.subtitle {
    text-align: center;
    color: #b8c7d4;
    font-size: 18px;
    margin-bottom: 30px;
}

.section {
    color: #00e6b8;
    font-size: 25px;
    font-weight: bold;
    margin-top: 30px;
}

.card {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(0,230,184,0.3);
    border-radius: 18px;
    padding: 22px;
    text-align: center;
    min-height: 120px;
}

.card-title {
    color: #aabccc;
    font-size: 14px;
    font-weight: bold;
}

.number {
    color: #00e6b8;
    font-size: 32px;
    font-weight: bold;
    margin-top: 10px;
}

.green {
    color: #00e6b8;
}

.red {
    color: #ff5252;
}

.stButton > button {
    width: 100%;
    background: linear-gradient(90deg, #00b894, #00cec9);
    color: white;
    border: none;
    border-radius: 12px;
    padding: 13px;
    font-size: 17px;
    font-weight: bold;
}

.alert {
    background: rgba(255,50,50,0.12);
    border-left: 5px solid #ff5252;
    border-radius: 12px;
    padding: 20px;
    color: #ff7777;
    margin-top: 15px;
}

.safe {
    background: rgba(0,230,184,0.12);
    border-left: 5px solid #00e6b8;
    border-radius: 12px;
    padding: 20px;
    color: #00e6b8;
    margin-top: 15px;
}

.footer {
    text-align: center;
    color: #71879b;
    margin-top: 40px;
    padding: 20px;
}

</style>
""", unsafe_allow_html=True)


# =========================
# HEADER
# =========================
st.markdown(
    '<div class="title">🛡️ NetShield AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Intelligent Network Intrusion Detection and Threat Monitoring System'
    '</div>',
    unsafe_allow_html=True
)


# =========================
# NETWORK DATA
# =========================
np.random.seed(42)

data = pd.DataFrame({
    "Packet Length": np.random.randint(40, 1500, 500),
    "Packet Count": np.random.randint(1, 1000, 500),
    "Failed Connections": np.random.randint(0, 20, 500),
    "Source Bytes": np.random.randint(100, 50000, 500)
})

# Threat detection rule
data["Status"] = np.where(
    (data["Failed Connections"] > 12) |
    (data["Packet Count"] > 850),
    "Suspicious",
    "Normal"
)


# =========================
# AI MODEL
# =========================
X = data[
    [
        "Packet Length",
        "Packet Count",
        "Failed Connections",
        "Source Bytes"
    ]
]

y = data["Status"]

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)


# =========================
# STATISTICS
# =========================
total = len(data)

normal = int(
    (data["Status"] == "Normal").sum()
)

threats = int(
    (data["Status"] == "Suspicious").sum()
)


# =========================
# DASHBOARD
# =========================
st.markdown(
    '<div class="section">📊 Security Monitoring Dashboard</div>',
    unsafe_allow_html=True
)

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"""
    <div class="card">
        <div class="card-title">🌐 NETWORK TRAFFIC</div>
        <div class="number">{total}</div>
        <div>Packets Monitored</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="card">
        <div class="card-title">🟢 NORMAL</div>
        <div class="number green">{normal}</div>
        <div>Safe Traffic</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="card">
        <div class="card-title">🔴 THREATS</div>
        <div class="number red">{threats}</div>
        <div>Suspicious Traffic</div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown("""
    <div class="card">
        <div class="card-title">⚡ SYSTEM</div>
        <div class="number green">ONLINE</div>
        <div>AI Monitoring Active</div>
    </div>
    """, unsafe_allow_html=True)


# =========================
# THREAT GRAPH
# =========================
st.markdown(
    '<div class="section">🚨 Threat Monitoring</div>',
    unsafe_allow_html=True
)

chart = pd.DataFrame({
    "Normal": [normal],
    "Suspicious": [threats]
})

st.bar_chart(chart)


# =========================
# AI INTRUSION DETECTION
# =========================
st.markdown(
    '<div class="section">🔍 AI Intrusion Detection</div>',
    unsafe_allow_html=True
)

c1, c2 = st.columns(2)

with c1:

    packet_length = st.number_input(
        "📦 Packet Length",
        40,
        1500,
        500
    )

    packet_count = st.number_input(
        "📊 Packet Count",
        1,
        1000,
        200
    )

with c2:

    failed_connections = st.number_input(
        "⚠️ Failed Connections",
        0,
        20,
        2
    )

    source_bytes = st.number_input(
        "📡 Source Bytes",
        100,
        50000,
        10000
    )


# =========================
# ANALYZE BUTTON
# =========================
if st.button("🛡️ ANALYZE NETWORK TRAFFIC"):

    new_data = pd.DataFrame({
        "Packet Length": [packet_length],
        "Packet Count": [packet_count],
        "Failed Connections": [failed_connections],
        "Source Bytes": [source_bytes]
    })

    result = model.predict(new_data)[0]

    confidence = (
        model.predict_proba(new_data).max() * 100
    )

    if result == "Suspicious":

        st.markdown(f"""
        <div class="alert">
        🚨 <b>THREAT DETECTED</b>
        <br><br>
        Suspicious network activity detected.
        <br><br>
        AI Confidence: <b>{confidence:.1f}%</b>
        </div>
        """, unsafe_allow_html=True)

    else:

        st.markdown(f"""
        <div class="safe">
        🟢 <b>NETWORK SECURE</b>
        <br><br>
        No suspicious activity detected.
        <br><br>
        AI Confidence: <b>{confidence:.1f}%</b>
        </div>
        """, unsafe_allow_html=True)


# =========================
# NETWORK LOGS
# =========================
st.markdown(
    '<div class="section">📋 Network Activity Logs</div>',
    unsafe_allow_html=True
)

st.dataframe(
    data.head(15),
    use_container_width=True
)


# =========================
# FOOTER
# =========================
st.markdown("""
<div class="footer">
🛡️ <b>NetShield AI</b>
<br><br>
Intelligent Network Intrusion Detection and Threat Monitoring System
<br><br>
Python • Machine Learning • Random Forest • Streamlit
</div>
""", unsafe_allow_html=True)