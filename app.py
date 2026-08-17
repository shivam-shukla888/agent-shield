"""
AgentShield — Streamlit Enterprise Security Product UI (app.py)
AI Agent Vulnerability Assessment & Quantitative Risk Analysis Platform
"""

import streamlit as st


import api_client
import components_3d
import styles
from ui_components.overview import render_overview_tab
from ui_components.scan_studio import render_scan_studio_tab
from ui_components.audit_log import render_audit_log_tab
from ui_components.sandbox import render_sandbox_tab

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION & STYLES INJECTION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="AgentShield | Enterprise AI Agent Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

styles.inject_styles()

# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------------------------------
def get_secret(key: str, default: str) -> str:
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default

if "backend_url" not in st.session_state:
    st.session_state.backend_url = get_secret("BACKEND_URL", "http://localhost:8000")

if "api_key" not in st.session_state:
    st.session_state.api_key = get_secret("API_KEY", "changeme-generate-a-real-key")

if "target_auth_header" not in st.session_state:
    st.session_state.target_auth_header = ""

if "demo_mode" not in st.session_state:
    st.session_state.demo_mode = False

PROBE_CATALOG = {
    "Direct Prompt Injection": ["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"],
    "Sensitive Info Disclosure": ["PII_DISCLOSURE_001"],
    "Excessive Agency": ["EXCESSIVE_AGENCY_001", "TOOL_AUTH_001"],
    "Infrastructure": ["SSRF_VALIDATION_001"],
}

# -----------------------------------------------------------------------------
# SIDEBAR — CONNECTION CONFIG & SYSTEM HEALTH
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Backend Connection")

    backend_input = st.text_input(
        "FastAPI Backend URL",
        value=st.session_state.backend_url,
        help="Target URL for the AgentShield REST API backend",
    )
    if backend_input != st.session_state.backend_url:
        st.session_state.backend_url = backend_input

    api_key_input = st.text_input(
        "API Key",
        value=st.session_state.api_key,
        type="password",
        help="X-API-Key header required by backend endpoints",
    )
    if api_key_input != st.session_state.api_key:
        st.session_state.api_key = api_key_input

    st.divider()

    st.markdown("### 🧪 Demo Mode")
    st.caption("Runs entirely offline against mock scan data — no live backend required. Useful for offline demos.")
    demo_toggle = st.toggle("Enable Demo Mode", value=st.session_state.demo_mode)
    if demo_toggle != st.session_state.demo_mode:
        st.session_state.demo_mode = demo_toggle
        st.rerun()

    st.divider()
    st.markdown("### 📊 System Health Status")
    is_online = api_client.check_backend_health(st.session_state.backend_url)
    is_ready = api_client.check_backend_readiness(st.session_state.backend_url)

    if st.session_state.demo_mode:
        st.markdown('• **API Status:** <span class="pill-medium">🟡 DEMO MODE</span> (Offline)', unsafe_allow_html=True)
        st.markdown('• **Storage Status:** <span class="pill-medium">MOCK</span> (InMemory)', unsafe_allow_html=True)
    elif is_online and is_ready:
        st.markdown('• **API Status:** <span class="pill-safe">🟢 ONLINE</span> (HTTP 200)', unsafe_allow_html=True)
        st.markdown('• **Storage Status:** <span class="pill-safe">🟢 READY</span> (SQL/Memory)', unsafe_allow_html=True)
    elif is_online:
        st.markdown('• **API Status:** <span class="pill-safe">🟢 ONLINE</span> (HTTP 200)', unsafe_allow_html=True)
        st.markdown('• **Storage Status:** <span class="pill-high">🟡 DEGRADED</span> (DB Error)', unsafe_allow_html=True)
    else:
        st.markdown('• **API Status:** <span class="pill-critical">🔴 UNREACHABLE</span> (Offline)', unsafe_allow_html=True)

    st.divider()
    st.markdown("### 📚 Quick Documentation")
    st.markdown("• [FastAPI Swagger Docs](http://localhost:8000/docs)")
    st.markdown("• [Standalone Dashboard](http://localhost:8000/dashboard)")
    st.markdown("• [GitHub Repository](https://github.com/shivam-shukla888/agent-shield)")

    st.markdown(
        '<div class="footer-credit">Built by '
        '<a href="https://github.com/shivam-shukla888" target="_blank">Shivam Shukla</a> · '
        '<a href="https://github.com/shivam-shukla888/agent-shield" target="_blank">source</a></div>',
        unsafe_allow_html=True,
    )

# -----------------------------------------------------------------------------
# HEADER & HERO GRAPHICS
# -----------------------------------------------------------------------------
components_3d.render_hero_attack_graph(height=140)

st.markdown("""
<div style="margin-top: -10px; margin-bottom: 16px;">
    <h1 style="font-size: 1.9rem; font-weight: 800; letter-spacing: -0.03em; color: #131b2e;">
        🛡️ AgentShield Platform
    </h1>
    <p style="color: #434655; font-size: 0.92rem; font-family: 'JetBrains Mono', monospace; font-weight: 500;">
        Enterprise AI Agent Vulnerability Assessment &amp; Quantitative Risk Scoring
    </p>
</div>
""", unsafe_allow_html=True)

# Connection Status Banner
c_status1, c_status2 = st.columns([3, 1])
with c_status1:
    if st.session_state.demo_mode:
        st.markdown('<span class="pill-medium">🟡 DEMO MODE — Offline Mock Scan Data Active</span>', unsafe_allow_html=True)
    elif is_online:
        st.markdown('<span class="pill-safe">🟢 CONNECTED — AgentShield API Online (v1.0.0)</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="pill-critical"><span class="pulse-dot"></span> BACKEND UNREACHABLE — Check URL in sidebar or enable Demo Mode</span>', unsafe_allow_html=True)

with c_status2:
    if not is_online and not st.session_state.demo_mode:
        if st.button("Enable Demo Mode", use_container_width=True):
            st.session_state.demo_mode = True
            st.rerun()

st.divider()

# -----------------------------------------------------------------------------
# NAVIGATION TABS
# -----------------------------------------------------------------------------
tab_home, tab_studio, tab_audit, tab_sandbox = st.tabs([
    "📊 Executive Overview",
    "🛡️ Scan Studio",
    "📜 Audit Log & Reports",
    "🧪 Adversarial Sandbox",
])

scans_data = api_client.list_scans(st.session_state.backend_url, st.session_state.api_key, st.session_state.demo_mode)

with tab_home:
    render_overview_tab(scans_data, PROBE_CATALOG)

with tab_studio:
    render_scan_studio_tab(st.session_state.backend_url, st.session_state.api_key, st.session_state.demo_mode)

with tab_audit:
    render_audit_log_tab(st.session_state.backend_url, st.session_state.api_key, st.session_state.demo_mode)

with tab_sandbox:
    render_sandbox_tab(st.session_state.backend_url, st.session_state.api_key, st.session_state.demo_mode)

