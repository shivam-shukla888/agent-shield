"""
AgentShield v2 - Custom Styling & Typography Engine (styles.py)
Cybernetic Precision Light Theme Design System
Source of Truth: design/stitch_mockups/stitch_agentshield_security_platform/cybernetic_precision/DESIGN.md
"""

THEME = {
    "colors": {
        "surface": "#faf8ff",
        "surface-dim": "#d2d9f4",
        "surface-bright": "#faf8ff",
        "surface-container-lowest": "#ffffff",
        "surface-container-low": "#f2f3ff",
        "surface-container": "#eaedff",
        "surface-container-high": "#e2e7ff",
        "surface-container-highest": "#dae2fd",
        "on-surface": "#131b2e",
        "on-surface-variant": "#434655",
        "inverse-surface": "#283044",
        "inverse-on-surface": "#eef0ff",
        "outline": "#737686",
        "outline-variant": "#c3c6d7",
        "surface-tint": "#0053db",
        "primary": "#004ac6",
        "on-primary": "#ffffff",
        "primary-container": "#2563eb",
        "on-primary-container": "#eeefff",
        "inverse-primary": "#b4c5ff",
        "secondary": "#006c4a",
        "on-secondary": "#ffffff",
        "secondary-container": "#82f5c1",
        "on-secondary-container": "#00714e",
        "tertiary": "#ae0010",
        "on-tertiary": "#ffffff",
        "tertiary-container": "#d52022",
        "on-tertiary-container": "#ffecea",
        "error": "#ba1a1a",
        "on-error": "#ffffff",
        "error-container": "#ffdad6",
        "on-error-container": "#93000a",
        "primary-fixed": "#dbe1ff",
        "primary-fixed-dim": "#b4c5ff",
        "on-primary-fixed": "#00174b",
        "on-primary-fixed-variant": "#003ea8",
        "secondary-fixed": "#85f8c4",
        "secondary-fixed-dim": "#68dba9",
        "on-secondary-fixed": "#002114",
        "on-secondary-fixed-variant": "#005137",
        "tertiary-fixed": "#ffdad6",
        "tertiary-fixed-dim": "#ffb4ab",
        "on-tertiary-fixed": "#410002",
        "on-tertiary-fixed-variant": "#93000b",
        "background": "#faf8ff",
        "on-background": "#131b2e",
        "surface-variant": "#dae2fd",
    },
    "typography": {
        "display-lg": {
            "fontFamily": "Plus Jakarta Sans",
            "fontSize": "40px",
            "fontWeight": "700",
            "lineHeight": "48px",
            "letterSpacing": "-0.02em",
        },
        "headline-md": {
            "fontFamily": "Plus Jakarta Sans",
            "fontSize": "24px",
            "fontWeight": "600",
            "lineHeight": "32px",
            "letterSpacing": "-0.01em",
        },
        "headline-sm": {
            "fontFamily": "Plus Jakarta Sans",
            "fontSize": "18px",
            "fontWeight": "600",
            "lineHeight": "24px",
        },
        "body-lg": {
            "fontFamily": "Inter",
            "fontSize": "16px",
            "fontWeight": "400",
            "lineHeight": "24px",
        },
        "body-md": {
            "fontFamily": "Inter",
            "fontSize": "14px",
            "fontWeight": "400",
            "lineHeight": "20px",
        },
        "body-sm": {
            "fontFamily": "Inter",
            "fontSize": "12px",
            "fontWeight": "400",
            "lineHeight": "16px",
        },
        "code-md": {
            "fontFamily": "JetBrains Mono",
            "fontSize": "13px",
            "fontWeight": "500",
            "lineHeight": "20px",
        },
        "code-sm": {
            "fontFamily": "JetBrains Mono",
            "fontSize": "11px",
            "fontWeight": "500",
            "lineHeight": "16px",
        },
        "label-caps": {
            "fontFamily": "JetBrains Mono",
            "fontSize": "10px",
            "fontWeight": "700",
            "lineHeight": "12px",
            "letterSpacing": "0.05em",
        },
    },
    "rounded": {
        "sm": "0.25rem",
        "DEFAULT": "0.5rem",
        "md": "0.75rem",
        "lg": "1rem",
        "xl": "1.5rem",
        "full": "9999px",
    },
    "spacing": {
        "unit": "4px",
        "xs": "4px",
        "sm": "8px",
        "md": "16px",
        "lg": "24px",
        "xl": "48px",
        "gutter": "16px",
        "margin-mobile": "16px",
        "margin-desktop": "32px",
    },
}

GLOBAL_CSS = f"""
<style>
    /* Google Fonts & Material Symbols Injection */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap');

    /* Global Root Semantic Variables (Cybernetic Precision Design System) */
    :root {{
        --bg-canvas: {THEME["colors"]["background"]};
        --bg-surface: {THEME["colors"]["surface-container-lowest"]};
        --bg-container-low: {THEME["colors"]["surface-container-low"]};
        --bg-container: {THEME["colors"]["surface-container"]};
        --bg-container-high: {THEME["colors"]["surface-container-high"]};
        
        --border-color: {THEME["colors"]["outline-variant"]};
        --border-subtle: {THEME["colors"]["surface-container-high"]};
        --border-outline: {THEME["colors"]["outline"]};
        --border-active: {THEME["colors"]["primary-container"]};
        
        --primary-blue: {THEME["colors"]["primary"]};
        --primary-container: {THEME["colors"]["primary-container"]};
        --secondary-emerald: {THEME["colors"]["secondary"]};
        --secondary-container: {THEME["colors"]["secondary-container"]};
        --tertiary-crimson: {THEME["colors"]["tertiary-container"]};
        --error-crimson: {THEME["colors"]["error"]};
        --warning-amber: #d97706;
        --info-blue: #3b82f6;

        --text-on-surface: {THEME["colors"]["on-surface"]};
        --text-subtle: {THEME["colors"]["on-surface-variant"]};
        --text-muted: {THEME["colors"]["outline"]};
        --text-inverse: {THEME["colors"]["on-primary"]};

        --font-headline: '{THEME["typography"]["headline-md"]["fontFamily"]}', sans-serif;
        --font-body: '{THEME["typography"]["body-md"]["fontFamily"]}', sans-serif;
        --font-code: '{THEME["typography"]["code-md"]["fontFamily"]}', monospace;

        --radius-sm: {THEME["rounded"]["sm"]};
        --radius-default: {THEME["rounded"]["DEFAULT"]};
        --radius-md: {THEME["rounded"]["md"]};
        --radius-lg: {THEME["rounded"]["lg"]};
        --radius-full: {THEME["rounded"]["full"]};
    }}

    /* Overall App Background & Header Override */
    .stApp {{
        background-color: var(--bg-canvas) !important;
        color: var(--text-on-surface) !important;
        font-family: var(--font-body) !important;
    }}

    header[data-testid="stHeader"] {{
        background-color: var(--bg-canvas) !important;
        color: var(--text-on-surface) !important;
    }}

    .main .block-container {{
        padding-top: 2rem !important;
    }}

    /* Streamlit Inline Code Blocks Override (Fixes solid black status badges) */
    code, pre, .mono-code, div[data-testid="stMarkdownContainer"] code, span[data-baseweb="tag"] {{
        font-family: var(--font-code) !important;
        background-color: var(--bg-container-low) !important;
        color: var(--primary-blue) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: var(--radius-sm) !important;
        padding: 0.15rem 0.4rem !important;
        font-size: 0.85rem !important;
    }}

    /* Header Bar & Top Nav */
    .app-header-container {{
        background: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-default);
        padding: 1rem 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: none;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }}

    /* Override Headings - Plus Jakarta Sans */
    h1, h2, h3, h4, h5, h6 {{
        font-family: var(--font-headline) !important;
        letter-spacing: -0.01em !important;
        color: var(--text-on-surface) !important;
        font-weight: 600 !important;
    }}

    /* Custom Scrollbar */
    ::-webkit-scrollbar {{
        width: 6px;
        height: 6px;
    }}
    ::-webkit-scrollbar-track {{
        background: var(--bg-container-low);
    }}
    ::-webkit-scrollbar-thumb {{
        background: var(--border-color);
        border-radius: var(--radius-sm);
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: var(--text-muted);
    }}

    /* Sidebar Overrides */
    section[data-testid="stSidebar"] {{
        background-color: var(--bg-container-low) !important;
        border-right: 1px solid var(--border-color) !important;
    }}

    section[data-testid="stSidebar"] * {{
        color: var(--text-on-surface) !important;
        font-family: var(--font-body) !important;
    }}

    /* Custom Buttons Override - DESIGN.md spec:
       Primary: solid electric blue (#004AC6) fill with white Inter text, 8px radius.
       Secondary: slate-navy outline, white background, 8px radius.
    */
    .stButton > button {{
        background: var(--bg-surface) !important;
        color: var(--text-on-surface) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: var(--radius-default) !important;
        padding: 0.5rem 1rem !important;
        font-family: var(--font-body) !important;
        font-weight: 500 !important;
        font-size: 0.88rem !important;
        transition: all 0.15s ease-in-out !important;
        box-shadow: none !important;
    }}

    .stButton > button:hover {{
        border-color: var(--border-outline) !important;
        color: var(--text-on-surface) !important;
        background: var(--bg-container-low) !important;
    }}

    /* Primary Button */
    .stButton > button[kind="primary"] {{
        background: {THEME["colors"]["primary"]} !important;
        color: {THEME["colors"]["on-primary"]} !important;
        border: 1px solid {THEME["colors"]["primary"]} !important;
        border-radius: var(--radius-default) !important;
        box-shadow: none !important;
    }}

    .stButton > button[kind="primary"]:hover {{
        background: {THEME["colors"]["primary-container"]} !important;
        border-color: {THEME["colors"]["primary-container"]} !important;
    }}

    /* Custom Text Input, Textarea, Select Box Override */
    .stTextInput > div > div > input, .stSelectbox > div > div, .stTextArea > div > div > textarea {{
        background-color: var(--bg-surface) !important;
        color: var(--text-on-surface) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: var(--radius-default) !important;
        font-family: var(--font-body) !important;
        font-size: 0.88rem !important;
    }}

    .stTextInput > div > div > input:focus, .stTextArea > div > div > textarea:focus {{
        border-color: var(--primary-container) !important;
        box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2) !important;
    }}

    /* Dataframe / Table Override */
    div[data-testid="stDataFrame"] {{
        background: var(--bg-surface) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: var(--radius-default) !important;
        box-shadow: none !important;
    }}

    /* Tab Custom Styling */
    button[data-baseweb="tab"] {{
        font-family: var(--font-headline) !important;
        font-weight: 600 !important;
        color: var(--text-subtle) !important;
        border-bottom: 2px solid transparent !important;
        padding: 0.75rem 1.25rem !important;
        transition: all 0.2s ease !important;
        font-size: 0.92rem !important;
    }}

    button[data-baseweb="tab"][aria-selected="true"] {{
        color: var(--primary-blue) !important;
        border-bottom-color: var(--primary-blue) !important;
        background: var(--bg-surface) !important;
        border-radius: var(--radius-default) var(--radius-default) 0 0 !important;
    }}

    /* Status Chips / Badges — Tinted background, colored text in JetBrains Mono per DESIGN.md */
    .pill-critical {{
        background-color: {THEME["colors"]["error-container"]};
        color: {THEME["colors"]["on-error-container"]};
        border: 1px solid {THEME["colors"]["tertiary-fixed-dim"]};
        padding: 0.25rem 0.65rem;
        border-radius: var(--radius-full);
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
    }}

    .pill-high {{
        background-color: #fef3c7;
        color: #92400e;
        border: 1px solid #fde68a;
        padding: 0.25rem 0.65rem;
        border-radius: var(--radius-full);
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }}

    .pill-medium {{
        background-color: #e0f2fe;
        color: #075985;
        border: 1px solid #bae6fd;
        padding: 0.25rem 0.65rem;
        border-radius: var(--radius-full);
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }}

    .pill-safe, .pill-low {{
        background-color: {THEME["colors"]["secondary-container"]};
        color: {THEME["colors"]["on-secondary-container"]};
        border: 1px solid {THEME["colors"]["secondary-fixed-dim"]};
        padding: 0.25rem 0.65rem;
        border-radius: var(--radius-full);
        font-family: var(--font-code);
        font-weight: 700;
        font-size: 0.75rem;
    }}

    /* Pulsing Dot for Critical Alerts */
    .pulse-dot {{
        width: 8px;
        height: 8px;
        background-color: {THEME["colors"]["error"]};
        border-radius: 50%;
        box-shadow: 0 0 6px {THEME["colors"]["error"]};
        animation: pulse-red 1.8s infinite;
    }}

    @keyframes pulse-red {{
        0% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(186, 26, 26, 0.7); }}
        70% {{ transform: scale(1); box-shadow: 0 0 0 6px rgba(186, 26, 26, 0); }}
        100% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(186, 26, 26, 0); }}
    }}

    /* Custom Container Panels & Cards — White surface, 1px border (#C3C6D7), 8px radius, no heavy shadows */
    .soc-panel {{
        background: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-default);
        padding: 1.25rem;
        margin-bottom: 1.25rem;
        box-shadow: none;
        transition: border-color 0.2s ease;
    }}

    .soc-panel:hover {{
        border-color: var(--border-outline);
    }}

    /* Monospace Code Styling for IDs and parameters */
    .mono-code {{
        font-family: var(--font-code);
        color: var(--primary-blue);
        font-weight: 600;
    }}

    /* Metric Card Styling */
    .metric-card {{
        background: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-default);
        padding: 1.1rem;
        text-align: center;
        box-shadow: none;
    }}
    .metric-value {{
        font-family: var(--font-code);
        font-size: 1.8rem;
        font-weight: 700;
        color: var(--text-on-surface);
    }}
    .metric-label {{
        color: var(--text-subtle);
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.25rem;
    }}

    /* Security Posture Matrix Cards */
    .posture-card {{
        background: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-default);
        padding: 1rem 1.2rem;
        margin-bottom: 0.85rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: none;
        transition: border-color 0.2s ease;
    }}
    .posture-card:hover {{
        border-color: var(--primary-blue);
    }}
    .posture-title {{
        font-family: var(--font-headline);
        font-size: 0.95rem;
        font-weight: 600;
        color: var(--text-on-surface);
    }}
    .posture-desc {{
        font-size: 0.8rem;
        color: var(--text-subtle);
        margin-top: 0.2rem;
    }}
    .evidence-box {{
        background: {THEME["colors"]["inverse-surface"]};
        border-left: 3px solid #d97706;
        border-radius: var(--radius-sm);
        padding: 0.8rem 1rem;
        font-family: var(--font-code);
        font-size: 0.83rem;
        color: {THEME["colors"]["inverse-on-surface"]};
        margin: 0.6rem 0;
        overflow-x: auto;
    }}
    .remediation-box {{
        background: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-default);
        padding: 0.9rem 1.1rem;
        margin-top: 0.6rem;
    }}

    /* Node Pipeline Visualizer Styling */
    .pipeline-container {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-default);
        padding: 1.2rem;
        margin-bottom: 1.5rem;
        gap: 0.5rem;
        overflow-x: auto;
    }}
    .pipeline-node {{
        background: var(--bg-container-low);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-default);
        padding: 0.75rem 1rem;
        text-align: center;
        min-width: 140px;
        box-shadow: none;
    }}
    .pipeline-node-active {{
        background: {THEME["colors"]["primary-fixed"]};
        border-color: var(--primary-blue);
        color: var(--primary-blue);
    }}
    .pipeline-arrow {{
        color: var(--text-muted);
        font-size: 1.2rem;
        font-weight: bold;
    }}

    /* Restrained footer credit */
    .footer-credit {{
        color: var(--text-muted);
        font-size: 0.75rem;
        font-family: var(--font-code);
        text-align: center;
        padding: 1rem 0 0.5rem 0;
    }}
    .footer-credit a {{
        color: var(--text-subtle);
        text-decoration: none;
    }}
    .footer-credit a:hover {{
        color: var(--primary-blue);
    }}
</style>
"""

def inject_styles():
    import streamlit as st
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)



