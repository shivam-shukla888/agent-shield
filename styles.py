"""
AgentShield v2 - Custom Styling & Typography Engine (styles.py)
Opinionated palette: Deep Charcoal (#0B0D12), Warm Text (#EDEDED), Crimson (#E23D5A), Amber (#FF6B35), Sage/Teal (#4ECDC4)
Typography: Sora (Sans) + JetBrains Mono (Code/IDs)
"""

GLOBAL_CSS = """
<style>
    /* Google Fonts Injection */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Sora:wght@400;600;700;800&display=swap');

    /* Global Root Variables */
    :root {
        --bg-charcoal: #0B0D12;
        --bg-panel: rgba(18, 22, 32, 0.85);
        --bg-card-hover: rgba(28, 35, 52, 0.95);
        --bg-input: #121622;
        
        --border-muted: rgba(255, 255, 255, 0.08);
        --border-active: rgba(226, 61, 90, 0.4);
        
        --accent-crimson: #E23D5A;
        --accent-amber: #FF6B35;
        --accent-teal: #4ECDC4;
        --text-bright: #EDEDED;
        --text-subtle: #94A3B8;
        --text-dark: #64748B;

        --font-heading: 'Sora', sans-serif;
        --font-code: 'JetBrains Mono', monospace;
    }

    /* Overall App Background Override */
    .stApp {
        background-color: var(--bg-charcoal) !important;
        color: var(--text-bright) !important;
        font-family: var(--font-heading) !important;
    }

    /* Override Headings */
    h1, h2, h3, h4, h5, h6 {
        font-family: var(--font-heading) !important;
        letter-spacing: -0.02em !important;
        color: var(--text-bright) !important;
    }

    /* Sidebar Overrides */
    section[data-testid="stSidebar"] {
        background-color: #07080D !important;
        border-right: 1px solid var(--border-muted) !important;
    }

    section[data-testid="stSidebar"] * {
        color: var(--text-subtle) !important;
        font-family: var(--font-heading) !important;
    }

    /* Custom Buttons Override */
    .stButton > button {
        background: linear-gradient(135deg, #181E2E 0%, #111522 100%) !important;
        color: var(--text-bright) !important;
        border: 1px solid var(--border-muted) !important;
        border-radius: 10px !important;
        padding: 0.6rem 1.2rem !important;
        font-family: var(--font-heading) !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }

    .stButton > button:hover {
        border-color: var(--accent-crimson) !important;
        color: #FFFFFF !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(226, 61, 90, 0.25) !important;
    }

    /* Primary Accent Button */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, var(--accent-crimson) 0%, #A81B34 100%) !important;
        color: #FFFFFF !important;
        border: none !important;
        box-shadow: 0 4px 15px rgba(226, 61, 90, 0.4) !important;
    }

    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #FF4D6D 0%, #C92A45 100%) !important;
        box-shadow: 0 8px 25px rgba(226, 61, 90, 0.6) !important;
    }

    /* Custom Text Input & Select Box Override */
    .stTextInput > div > div > input, .stSelectbox > div > div {
        background-color: var(--bg-input) !important;
        color: var(--text-bright) !important;
        border: 1px solid var(--border-muted) !important;
        border-radius: 10px !important;
        font-family: var(--font-code) !important;
        font-size: 0.9rem !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: var(--accent-teal) !important;
        box-shadow: 0 0 0 3px rgba(78, 205, 196, 0.2) !important;
    }

    /* Custom Dataframe / Table Override */
    div[data-testid="stDataFrame"] {
        background: var(--bg-panel) !important;
        border: 1px solid var(--border-muted) !important;
        border-radius: 12px !important;
    }

    /* Custom Badges & HTML Pills */
    .pill-critical {
        background: rgba(226, 61, 90, 0.18);
        color: #FF8096;
        border: 1px solid rgba(226, 61, 90, 0.4);
        padding: 0.25rem 0.65rem;
        border-radius: 20px;
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
    }

    .pill-high {
        background: rgba(255, 107, 53, 0.18);
        color: #FFB088;
        border: 1px solid rgba(255, 107, 53, 0.4);
        padding: 0.25rem 0.65rem;
        border-radius: 20px;
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }

    .pill-safe {
        background: rgba(78, 205, 196, 0.18);
        color: #A3F3ED;
        border: 1px solid rgba(78, 205, 196, 0.4);
        padding: 0.25rem 0.65rem;
        border-radius: 20px;
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }

    /* Pulsing Dot for Critical Alerts */
    .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: var(--accent-crimson);
        border-radius: 50%;
        box-shadow: 0 0 8px var(--accent-crimson);
        animation: pulse-red 1.8s infinite;
    }

    @keyframes pulse-red {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(226, 61, 90, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(226, 61, 90, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(226, 61, 90, 0); }
    }

    /* Custom Container Panels */
    .soc-panel {
        background: var(--bg-panel);
        border: 1px solid var(--border-muted);
        border-radius: 14px;
        padding: 1.5rem;
        margin-bottom: 1.25rem;
    }

    /* Monospace ID Text */
    .mono-code {
        font-family: var(--font-code);
        color: var(--accent-teal);
    }
</style>
"""

def inject_styles():
    import streamlit as st
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
