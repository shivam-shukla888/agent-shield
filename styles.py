"""
AgentShield v2 - Custom Styling & Typography Engine (styles.py)
Cybernetic Precision Light Theme Design System
Primary: Electric Blue (#2563eb / #004ac6), Success: Emerald (#006c4a / #10b981), Error: Crimson (#d52022 / #ba1a1a)
Canvas: Slate Light (#faf8ff / #f8fafc), Surface: Pure White (#ffffff), Text: Slate Navy (#131b2e)
Typography: Plus Jakarta Sans (Headlines) + Inter (Body) + JetBrains Mono (Code/Telemetry/IDs)
"""

GLOBAL_CSS = """
<style>
    /* Google Fonts & Material Symbols Injection */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap');

    /* Global Root Semantic Variables (Cybernetic Precision Design System) */
    :root {
        --bg-canvas: #faf8ff;
        --bg-surface: #ffffff;
        --bg-container-low: #f2f3ff;
        --bg-container: #eaedff;
        --bg-container-high: #e2e7ff;
        
        --border-color: #c3c6d7;
        --border-subtle: #e2e7ff;
        --border-active: #2563eb;
        
        --primary-blue: #004ac6;
        --primary-container: #2563eb;
        --secondary-emerald: #006c4a;
        --secondary-container: #82f5c1;
        --tertiary-crimson: #d52022;
        --error-crimson: #ba1a1a;
        --warning-amber: #d97706;
        --info-blue: #3b82f6;

        --text-on-surface: #131b2e;
        --text-subtle: #434655;
        --text-muted: #737686;
        --text-inverse: #ffffff;

        --font-headline: 'Plus Jakarta Sans', sans-serif;
        --font-body: 'Inter', sans-serif;
        --font-code: 'JetBrains Mono', monospace;
    }

    /* Overall App Background Override */
    .stApp {
        background-color: var(--bg-canvas) !important;
        color: var(--text-on-surface) !important;
        font-family: var(--font-body) !important;
    }

    /* Header Bar & Top Nav */
    .app-header-container {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 14px;
        padding: 1rem 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 1px 3px rgba(19, 27, 46, 0.04);
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    /* Override Headings */
    h1, h2, h3, h4, h5, h6 {
        font-family: var(--font-headline) !important;
        letter-spacing: -0.02em !important;
        color: var(--text-on-surface) !important;
        font-weight: 700 !important;
    }

    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #f2f3ff;
    }
    ::-webkit-scrollbar-thumb {
        background: #c3c6d7;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #737686;
    }

    /* Sidebar Overrides */
    section[data-testid="stSidebar"] {
        background-color: #f2f3ff !important;
        border-right: 1px solid var(--border-subtle) !important;
    }

    section[data-testid="stSidebar"] * {
        color: var(--text-on-surface) !important;
        font-family: var(--font-body) !important;
    }

    /* Custom Buttons Override */
    .stButton > button {
        background: var(--bg-surface) !important;
        color: var(--text-on-surface) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        padding: 0.55rem 1.2rem !important;
        font-family: var(--font-body) !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        transition: all 0.2s ease-in-out !important;
        box-shadow: 0 1px 2px rgba(19, 27, 46, 0.04) !important;
    }

    .stButton > button:hover {
        border-color: var(--primary-container) !important;
        color: var(--primary-blue) !important;
        background: var(--bg-container-low) !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.12) !important;
    }

    /* Primary Accent Button */
    .stButton > button[kind="primary"] {
        background: var(--primary-container) !important;
        color: var(--text-inverse) !important;
        border: 1px solid var(--primary-blue) !important;
        box-shadow: 0 2px 8px rgba(37, 99, 235, 0.25) !important;
    }

    .stButton > button[kind="primary"]:hover {
        background: var(--primary-blue) !important;
        box-shadow: 0 4px 16px rgba(37, 99, 235, 0.35) !important;
        transform: translateY(-1px) !important;
    }

    /* Custom Text Input & Select Box Override */
    .stTextInput > div > div > input, .stSelectbox > div > div, .stTextArea > div > div > textarea {
        background-color: var(--bg-surface) !important;
        color: var(--text-on-surface) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        font-family: var(--font-code) !important;
        font-size: 0.88rem !important;
    }

    .stTextInput > div > div > input:focus, .stTextArea > div > div > textarea:focus {
        border-color: var(--primary-container) !important;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15) !important;
    }

    /* Custom Dataframe / Table Override */
    div[data-testid="stDataFrame"] {
        background: var(--bg-surface) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
        box-shadow: 0 1px 3px rgba(19, 27, 46, 0.03) !important;
    }

    /* Tab Custom Styling */
    button[data-baseweb="tab"] {
        font-family: var(--font-headline) !important;
        font-weight: 600 !important;
        color: var(--text-subtle) !important;
        border-bottom: 2px solid transparent !important;
        padding: 0.75rem 1.25rem !important;
        transition: all 0.2s ease !important;
        font-size: 0.92rem !important;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        color: var(--primary-blue) !important;
        border-bottom-color: var(--primary-container) !important;
        background: var(--bg-surface) !important;
        border-radius: 8px 8px 0 0 !important;
    }

    /* Custom Badges & HTML Pills */
    .pill-critical {
        background: #ffdad6;
        color: #93000a;
        border: 1px solid #ffb4ab;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
    }

    .pill-high {
        background: #fef3c7;
        color: #92400e;
        border: 1px solid #fde68a;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }

    .pill-medium {
        background: #e0f2fe;
        color: #075985;
        border: 1px solid #bae6fd;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }

    .pill-safe, .pill-low {
        background: #d1fae5;
        color: #065f46;
        border: 1px solid #a7f3d0;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }

    /* Pulsing Dot for Critical Alerts */
    .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: var(--tertiary-crimson);
        border-radius: 50%;
        box-shadow: 0 0 8px var(--tertiary-crimson);
        animation: pulse-red 1.8s infinite;
    }

    @keyframes pulse-red {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(213, 32, 34, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(213, 32, 34, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(213, 32, 34, 0); }
    }

    /* Custom Container Panels */
    .soc-panel {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.35rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 1px 3px rgba(19, 27, 46, 0.03);
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }

    .soc-panel:hover {
        border-color: var(--border-color);
        box-shadow: 0 4px 12px rgba(19, 27, 46, 0.06);
    }

    /* Monospace Code Styling */
    .mono-code {
        font-family: var(--font-code);
        color: var(--primary-blue);
        font-weight: 600;
    }

    /* Metric Card Styling */
    .metric-card {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.1rem;
        text-align: center;
        box-shadow: 0 1px 3px rgba(19, 27, 46, 0.03);
    }
    .metric-value {
        font-family: var(--font-code);
        font-size: 1.8rem;
        font-weight: 700;
        color: var(--text-on-surface);
    }
    .metric-label {
        color: var(--text-subtle);
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.25rem;
    }

    /* Security Posture Matrix Cards */
    .posture-card {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.1rem 1.25rem;
        margin-bottom: 0.85rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 1px 2px rgba(19, 27, 46, 0.03);
        transition: border-color 0.2s ease;
    }
    .posture-card:hover {
        border-color: var(--primary-container);
    }
    .posture-title {
        font-family: var(--font-headline);
        font-size: 0.95rem;
        font-weight: 600;
        color: var(--text-on-surface);
    }
    .posture-desc {
        font-size: 0.8rem;
        color: var(--text-subtle);
        margin-top: 0.2rem;
    }
    .evidence-box {
        background: #0f172a;
        border-left: 3px solid var(--warning-amber);
        border-radius: 6px;
        padding: 0.8rem 1rem;
        font-family: var(--font-code);
        font-size: 0.83rem;
        color: #f8fafc;
        margin: 0.6rem 0;
        overflow-x: auto;
    }
    .remediation-box {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 0.9rem 1.1rem;
        margin-top: 0.6rem;
    }

    /* Node Pipeline Visualizer Styling */
    .pipeline-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 14px;
        padding: 1.2rem;
        margin-bottom: 1.5rem;
        gap: 0.5rem;
        overflow-x: auto;
    }
    .pipeline-node {
        background: var(--bg-container-low);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 0.75rem 1rem;
        text-align: center;
        min-width: 140px;
        box-shadow: 0 1px 2px rgba(19, 27, 46, 0.03);
    }
    .pipeline-node-active {
        background: #dbe1ff;
        border-color: var(--primary-container);
        color: var(--primary-blue);
    }
    .pipeline-arrow {
        color: var(--text-muted);
        font-size: 1.2rem;
        font-weight: bold;
    }

    /* Restrained footer credit */
    .footer-credit {
        color: var(--text-muted);
        font-size: 0.75rem;
        font-family: var(--font-code);
        text-align: center;
        padding: 1rem 0 0.5rem 0;
    }
    .footer-credit a {
        color: var(--text-subtle);
        text-decoration: none;
    }
    .footer-credit a:hover {
        color: var(--primary-blue);
    }
</style>
"""

def inject_styles():
    import streamlit as st
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


