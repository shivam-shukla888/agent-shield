"""
AgentShield UI Components — Executive Security Overview Module (ui_components/overview.py)
"""

from typing import Any, Dict, List, Optional
import streamlit as st
import components_3d



def render_overview_tab(scans_data: Optional[List[Dict[str, Any]]], probe_catalog: Dict[str, List[str]]):
    """
    Renders the Executive Security Overview dashboard tab.
    """
    if scans_data is None:
        st.error("⚠️ Unable to connect to AgentShield backend API. Verify backend URL and API Key in sidebar configuration.")
        return

    st.markdown("""
    <div style="background: #f2f3ff; border-left: 4px solid #004ac6; padding: 1.1rem 1.3rem; border-radius: 10px; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(19, 27, 46, 0.03);">
        <strong style="color: #004ac6; font-size: 0.88rem; letter-spacing: 0.06em; text-transform: uppercase;">Core Architectural Security Directive</strong>
        <p style="color: #131b2e; font-size: 0.92rem; margin-top: 0.4rem; line-height: 1.5;">
            <strong>"LLM alignment is not authorization."</strong> System prompts and LLM fine-tuning are soft boundaries. Privileged tool execution MUST be governed by an out-of-band deterministic policy layer outside model context.
        </p>
    </div>
    """, unsafe_allow_html=True)

    total_scans = len(scans_data)
    total_findings = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    total_score_sum = 0
    passed_scans = 0

    # Categorized findings tracker for dynamic posture pills (Task 3)
    vector_severities: Dict[str, List[str]] = {
        "prompt_injection": [],
        "prompt_leak": [],
        "pii_exfiltration": [],
        "ssrf": [],
        "excessive_agency": [],
    }

    for s in scans_data:
        findings = s.get("findings", [])
        total_findings += len(findings)
        if not findings:
            passed_scans += 1

        for f in findings:
            sev = (f.get("severity") or "MEDIUM").upper()
            cat = str(f.get("category") or f.get("probe_id") or "").upper()

            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1
            elif sev == "MEDIUM":
                medium_count += 1
            else:
                low_count += 1

            if "OVERRIDE" in cat or "INJECTION" in cat:
                vector_severities["prompt_injection"].append(sev)
            elif "LEAK" in cat or "SYSTEM_PROMPT" in cat or "DISCLOSURE" in cat:
                vector_severities["prompt_leak"].append(sev)
            elif "PII" in cat or "CREDENTIAL" in cat or "DATA" in cat:
                vector_severities["pii_exfiltration"].append(sev)
            elif "SSRF" in cat or "SUBNET" in cat:
                vector_severities["ssrf"].append(sev)
            elif "AGENCY" in cat or "TOOL" in cat or "AUTH" in cat:
                vector_severities["excessive_agency"].append(sev)

        score = s.get("risk_score")
        if score is None and "risk_assessments" in s:
            r_list = s.get("risk_assessments", [])
            score = r_list[0].get("risk_score") if r_list else 0
        total_score_sum += (score or 0)

    avg_score = int(total_score_sum / max(total_scans, 1)) if total_scans > 0 else 0
    pass_rate = int((passed_scans / max(total_scans, 1)) * 100) if total_scans > 0 else 100
    risk_level_str = (
        "NO DATA YET" if total_scans == 0
        else "CRITICAL RISK" if avg_score >= 85
        else "HIGH RISK" if avg_score >= 60
        else "MEDIUM RISK" if avg_score >= 30
        else "LOW RISK / ALIGNED"
    )

    # HERO RISK & METRICS
    g_col1, g_col2 = st.columns([1, 2])
    with g_col1:
        st.markdown("#### Security Risk Index")
        components_3d.render_risk_score_gauge(avg_score, height=160)

    with g_col2:
        st.markdown("#### Security System Posture Metrics")
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f'<div class="metric-card"><div class="metric-value">{total_scans}</div><div class="metric-label">Scans Executed</div></div>', unsafe_allow_html=True)
        with m2:
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #ba1a1a;">{total_findings}</div><div class="metric-label">Active Findings</div></div>', unsafe_allow_html=True)
        with m3:
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #006c4a;">{pass_rate}%</div><div class="metric-label">Pass Rate</div></div>', unsafe_allow_html=True)
        with m4:
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #004ac6;">{len(sum(probe_catalog.values(), []))}</div><div class="metric-label">Probes Active</div></div>', unsafe_allow_html=True)

    # "WHY THIS SCORE?" EXPANDER INTERACTION
    with st.expander(f"❓ Why this risk score? ({avg_score}/100 — {risk_level_str})"):
        st.markdown(f"**Calculated Score:** `{avg_score} / 100` — **Risk Level:** `{risk_level_str}`")
        st.caption("AgentShield RiskEngine calculates scores using AgentShield MVP policy weights across 5 environmental dimensions:")

        c_risk1, c_risk2 = st.columns(2)
        with c_risk1:
            st.markdown("• **Business Impact (30% weight)**: Range 0 to 100")
            st.markdown("• **Exploitability (25% weight)**: Range 25 to 100")
            st.markdown("• **Blast Radius (20% weight)**: Range 20 to 100")
        with c_risk2:
            st.markdown("• **Asset Sensitivity (15% weight)**: Range 10 to 100")
            st.markdown("• **Tool Privilege (10% weight)**: Range 0 to 100")
            st.markdown(f"• **Active Findings Filter**: `{total_findings}` identified vulnerability trace(s)")

    st.divider()

    # Dynamic Threat Vector Pill Generator helper
    def get_posture_pill(sevs: List[str]) -> str:
        if total_scans == 0:
            return '<span class="pill-medium">NO DATA YET — RUN AUDIT</span>'
        if not sevs:
            return '<span class="pill-safe">SECURE</span>'
        if "CRITICAL" in sevs:
            return '<span class="pill-critical"><span class="pulse-dot"></span> CRITICAL</span>'
        if "HIGH" in sevs:
            return '<span class="pill-high">HIGH RISK</span>'
        if "MEDIUM" in sevs:
            return '<span class="pill-medium">MEDIUM RISK</span>'
        return '<span class="pill-safe">LOW RISK</span>'

    pill_prompt_inj = get_posture_pill(vector_severities["prompt_injection"])
    pill_prompt_leak = get_posture_pill(vector_severities["prompt_leak"])
    pill_pii = get_posture_pill(vector_severities["pii_exfiltration"])
    pill_ssrf = get_posture_pill(vector_severities["ssrf"])
    pill_agency = get_posture_pill(vector_severities["excessive_agency"])

    # THREAT VECTOR SECURITY POSTURE MATRIX
    st.markdown("### Threat Vector Security Posture Matrix")
    st.caption("Real-time threat posture evaluation computed dynamically from scan finding history.")

    posture_col1, posture_col2 = st.columns(2)
    with posture_col1:
        st.markdown(f"""
        <div class="posture-card">
            <div>
                <div class="posture-title">Direct Prompt Injection</div>
                <div class="posture-desc">Tests instruction override & persona jailbreak probes</div>
            </div>
            {pill_prompt_inj}
        </div>
        <div class="posture-card">
            <div>
                <div class="posture-title">System Prompt Extraction</div>
                <div class="posture-desc">Verifies refusal to disclose developer directives</div>
            </div>
            {pill_prompt_leak}
        </div>
        <div class="posture-card">
            <div>
                <div class="posture-title">Sensitive Data Exfiltration</div>
                <div class="posture-desc">Audits PII, passkeys, & API credential disclosures</div>
            </div>
            {pill_pii}
        </div>
        """, unsafe_allow_html=True)

    with posture_col2:
        st.markdown(f"""
        <div class="posture-card">
            <div>
                <div class="posture-title">SSRF & Network Boundary</div>
                <div class="posture-desc">Blocks AWS IMDS (169.254.169.254) & private subnets</div>
            </div>
            {pill_ssrf}
        </div>
        <div class="posture-card">
            <div>
                <div class="posture-title">Excessive Agency & Misuse</div>
                <div class="posture-desc">Prevents unauthorized tool execution without authorization</div>
            </div>
            {pill_agency}
        </div>
        <div class="posture-card">
            <div>
                <div class="posture-title">Deterministic Policy Layer</div>
                <div class="posture-desc">Out-of-band authorization boundary enforcement</div>
            </div>
            <span class="pill-safe">ACTIVE</span>
        </div>
        """, unsafe_allow_html=True)

    st.divider()


    # 5-STAGE AUDIT LIFECYCLE PIPELINE
    st.markdown("### Security Audit Lifecycle Pipeline")
    w1, w2, w3, w4, w5 = st.columns(5)
    steps = [
        ("1. TARGET", "Validate REST URL & auth headers"),
        ("2. PROBES", "Dispatch 20 probe suites"),
        ("3. ANALYSIS", "Observe response & headers"),
        ("4. FINDINGS", "Deterministic evaluation"),
        ("5. REMEDIATION", "Generate policy patches"),
    ]
    for col, (title, desc) in zip((w1, w2, w3, w4, w5), steps):
        with col:
            st.markdown(f"""
            <div class="soc-panel" style="padding: 1rem; text-align: center;">
                <h4 style="font-size: 0.82rem; color: #004ac6; text-transform: uppercase;">{title}</h4>
                <p style="color: #434655; font-size: 0.78rem; margin-top: 0.3rem;">{desc}</p>
            </div>
            """, unsafe_allow_html=True)

