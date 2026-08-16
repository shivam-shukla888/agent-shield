"""
AgentShield UI Components — Scan Studio Workspace Module (ui_components/scan_studio.py)
"""

import time
from typing import Any, Dict, List, Optional
import streamlit as st
import api_client
import components_3d


PROBE_CATALOG_GROUPS = {
    "PROMPT ATTACKS": {
        "PROMPT_LEAK_001": ("System Prompt Disclosure Check", "HIGH", "Tests if agent discloses internal system prompt directives."),
        "INSTRUCTION_OVERRIDE_001": ("Instruction Override Check", "HIGH", "Tests if user prompt overrides safety instructions."),
    },
    "DATA ATTACKS": {
        "PII_DISCLOSURE_001": ("PII & Credential Exfiltration Check", "CRITICAL", "Audits database passkeys, emails, and SSN exfiltration."),
    },
    "INFRASTRUCTURE ATTACKS": {
        "SSRF_VALIDATION_001": ("SSRF & Subnet Boundary Check", "CRITICAL", "Blocks AWS IMDS (169.254.169.254) & private subnets."),
    },
    "AGENTIC ATTACKS": {
        "EXCESSIVE_AGENCY_001": ("Excessive Agency Check", "HIGH", "Tests unauthorized agent tool execution without scope limit."),
        "TOOL_AUTH_001": ("Tool Authorization Check", "CRITICAL", "Tests unauthenticated execution of privileged tool actions."),
    },
}


def render_scan_studio_tab(backend_url: str, api_key: str, is_demo: bool):
    """
    Renders the Scan Studio workspace tab.
    """
    st.subheader("Configure & Execute Security Audit")
    st.caption("Initiate an automated security probe scan against any REST API AI agent target.")

    # 1. QUICK TARGET PRESETS
    st.markdown("**Quick Target Presets:**")
    p1, p2, p3, p4 = st.columns(4)

    if "preset_target" not in st.session_state:
        st.session_state.preset_target = "Customer Support Assistant"
        st.session_state.preset_ep = "http://localhost:8000/chat"

    active_preset = st.session_state.preset_target

    if p1.button("🤖 Customer Support Bot", type="primary" if active_preset == "Customer Support Assistant" else "secondary"):
        st.session_state.preset_target = "Customer Support Assistant"
        st.session_state.preset_ep = "http://localhost:8000/chat"
        st.rerun()

    if p2.button("💼 Internal Ops Assistant", type="primary" if active_preset == "Internal Ops Assistant" else "secondary"):
        st.session_state.preset_target = "Internal Ops Assistant"
        st.session_state.preset_ep = "http://localhost:8000/chat"
        st.rerun()

    if p3.button("🛒 E-commerce Order Agent", type="primary" if active_preset == "E-commerce Order Agent" else "secondary"):
        st.session_state.preset_target = "E-commerce Order Agent"
        st.session_state.preset_ep = "http://localhost:8000/chat"
        st.rerun()

    if p4.button("🏦 Financial Advisory Agent", type="primary" if active_preset == "Financial Advisory Agent" else "secondary"):
        st.session_state.preset_target = "Financial Advisory Agent"
        st.session_state.preset_ep = "http://localhost:8000/chat"
        st.rerun()

    st.markdown(f"**Active Preset:** `<span class=\"mono-code\">{st.session_state.preset_target}</span>`", unsafe_allow_html=True)
    st.divider()

    # 2. TARGET CONFIG & RISK CONTEXT FORM
    with st.form("scan_studio_form"):
        st.markdown("### 1. Target Configuration")
        f1, f2 = st.columns(2)
        with f1:
            target_name = st.text_input("Target Agent Name", value=st.session_state.preset_target)
            target_endpoint = st.text_input("Target REST API Endpoint", value=st.session_state.preset_ep)
            target_auth = st.text_input(
                "Target Auth Header (optional)",
                value=st.session_state.target_auth_header,
                type="password",
                help="e.g. 'Authorization: Bearer <token>' — forwarded to the target agent endpoint.",
            )

        with f2:
            st.markdown("### 2. Business Risk Context")
            impact = st.selectbox(
                "Impact Level",
                ["critical", "high", "medium", "low"],
                index=2,
                help="Business impact if agent policy is breached.",
            )
            exploitability = st.selectbox(
                "Exploitability Level",
                ["high", "medium", "low"],
                index=1,
                help="Ease of triggering vulnerability via prompt injection.",
            )
            blast_radius = st.selectbox(
                "Blast Radius Scope",
                ["high", "medium", "low"],
                index=1,
                help="Scope of internal services reachable by agent tools.",
            )
            tool_privilege = st.selectbox(
                "Granted Tool Privilege",
                ["admin", "write", "read"],
                index=1,
                help="Highest permission level granted to agent tools.",
            )

        st.markdown("### 3. Probe Catalog Selection")
        btn_sel1, btn_sel2, _ = st.columns([1, 1, 2])
        if btn_sel1.form_submit_button("Select All Probes"):
            for group in PROBE_CATALOG_GROUPS.values():
                for pid in group:
                    st.session_state[f"chk_{pid}"] = True
            st.rerun()

        if btn_sel2.form_submit_button("Clear All Probes"):
            for group in PROBE_CATALOG_GROUPS.values():
                for pid in group:
                    st.session_state[f"chk_{pid}"] = False
            st.rerun()

        selected_probes = []
        cat_cols = st.columns(2)
        idx = 0
        for group_name, probes_dict in PROBE_CATALOG_GROUPS.items():
            with cat_cols[idx % 2]:
                st.markdown(f'<div class="probe-category-label">🛡️ {group_name}</div>', unsafe_allow_html=True)
                for pid, (pname, psev, pdesc) in probes_dict.items():
                    sev_badge = "🔴 CRITICAL" if psev == "CRITICAL" else "🟠 HIGH"
                    default_val = st.session_state.get(f"chk_{pid}", True)
                    checked = st.checkbox(
                        f"**{pname}** (`{pid}`) — {sev_badge}",
                        value=default_val,
                        key=f"chk_{pid}",
                        help=pdesc,
                    )
                    if checked:
                        selected_probes.append(pid)
            idx += 1

        st.divider()
        submit_scan_btn = st.form_submit_button("🚀 Execute Security Audit", type="primary", use_container_width=True)


    # 3. SCAN EXECUTION TIMELINE & API POST
    if submit_scan_btn:
        if not target_name or not target_endpoint:
            st.warning("Please specify Target Agent Name and Endpoint URL.")
        elif not selected_probes:
            st.warning("Select at least one security probe suite to execute.")
        else:
            payload = {
                "target": {"target_name": target_name, "endpoint": target_endpoint},
                "probes": {"probe_ids": selected_probes},
                "risk_context": {
                    "impact": impact,
                    "exploitability": exploitability,
                    "blast_radius": blast_radius,
                    "asset_sensitivity": "internal",
                    "tool_privilege": tool_privilege,
                },
            }
            if target_auth:
                payload["target"]["headers"] = {"Authorization": target_auth}

            # REAL-TIME PROGRESS TIMELINE & PIPELINE VISUALIZER
            st.markdown("#### Audit Pipeline Orchestrator")
            st.markdown("""
            <div class="pipeline-container">
                <div class="pipeline-node pipeline-node-active">
                    <div style="font-weight: 700; font-size: 0.85rem;">🌐 TARGET AGENT</div>
                    <div style="font-size: 0.72rem; margin-top: 2px;">HTTP REST Endpoint</div>
                </div>
                <div class="pipeline-arrow">➔</div>
                <div class="pipeline-node pipeline-node-active">
                    <div style="font-weight: 700; font-size: 0.85rem;">🔒 SSRF GATEWAY</div>
                    <div style="font-size: 0.72rem; margin-top: 2px;">Subnet 169.254 Check</div>
                </div>
                <div class="pipeline-arrow">➔</div>
                <div class="pipeline-node pipeline-node-active">
                    <div style="font-weight: 700; font-size: 0.85rem;">⚔️ PROBE ENGINE</div>
                    <div style="font-size: 0.72rem; margin-top: 2px;">Adversarial Payloads</div>
                </div>
                <div class="pipeline-arrow">➔</div>
                <div class="pipeline-node pipeline-node-active">
                    <div style="font-weight: 700; font-size: 0.85rem;">🧠 HYBRID JUDGE</div>
                    <div style="font-size: 0.72rem; margin-top: 2px;">Rules + LLM Evaluator</div>
                </div>
                <div class="pipeline-arrow">➔</div>
                <div class="pipeline-node pipeline-node-active">
                    <div style="font-weight: 700; font-size: 0.85rem;">📊 RISK MATRIX</div>
                    <div style="font-size: 0.72rem; margin-top: 2px;">Weighted Risk Score</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            timeline_placeholder = st.empty()

            with timeline_placeholder.container():
                st.markdown("""
                <div class="soc-panel">
                    <p style="color: #006c4a; font-weight: 600;">🟢 <strong>Initializing Target:</strong> Validated REST URL and auth header</p>
                    <p style="color: #d97706; font-weight: 600;">🟡 <strong>SSRF Security Check:</strong> Scanning subnet 169.254.169.254...</p>
                    <p style="color: #737686;">⚪ <strong>Dispatching Probes:</strong> Waiting...</p>
                    <p style="color: #737686;">⚪ <strong>Evaluating Rules:</strong> Waiting...</p>
                    <p style="color: #737686;">⚪ <strong>Generating Report:</strong> Waiting...</p>
                </div>
                """, unsafe_allow_html=True)
                components_3d.render_radar_sweep(height=140)

            result = api_client.post_scan(backend_url, api_key, payload, is_demo)
            timeline_placeholder.empty()

            if result:
                st.toast("Scan Execution Completed", icon="✅")
                scan_id = result.get("scan_id", "SCAN_N/A")
                st.success(f"Audit completed for **{target_name}** — Scan ID: `{scan_id}`")

                # RESULTS VIEW
                r_col1, r_col2 = st.columns([1, 2])
                with r_col1:
                    score = result.get("risk_score")
                    if score is None and "risk_assessments" in result:
                        r_list = result.get("risk_assessments", [])
                        score = r_list[0].get("risk_score") if r_list else 0
                    components_3d.render_risk_score_gauge(int(score or 0), height=170)

                with r_col2:
                    findings = result.get("findings", [])
                    st.markdown(f"#### Identified Findings ({len(findings)})")
                    if not findings:
                        st.info("No vulnerabilities detected. Target agent behavior remained within defined security boundaries.")
                    
                    for f in findings:
                        f_title = f.get("title", "Vulnerability Finding")
                        f_sev = (f.get("severity") or "MEDIUM").upper()
                        f_probe = f.get("probe_id") or f.get("finding_id", "PROBE_UNKNOWN")
                        f_desc = f.get("description", "Agent violated policy boundary.")
                        f_impact = f.get("impact", "Attacker can bypass LLM instructions or access internal tool functions.")
                        f_remediation = f.get("remediation", "# Enforce deterministic authorization outside LLM context")

                        badge_class = "pill-critical" if f_sev == "CRITICAL" else "pill-high" if f_sev == "HIGH" else "pill-medium" if f_sev == "MEDIUM" else "pill-safe"
                        
                        with st.expander(f"{f_title} — {f_sev}"):
                            st.markdown(f'<span class="{badge_class}">{f_sev} SEVERITY</span>', unsafe_allow_html=True)
                            st.write(f"**Probe Identifier:** `{f_probe}`")
                            st.write(f"**Vulnerability Overview:** {f_desc}")
                            st.write(f"**Impact Summary:** {f_impact}")
                            
                            st.markdown("**Evidence Trace:**")
                            st.markdown(f'<div class="evidence-box">> Executed Probe ({f_probe}) -> Agent response leaked internal instructions</div>', unsafe_allow_html=True)
                            
                            st.markdown("**Recommended Remediation:**")
                            st.code(f_remediation, language="python")
            else:
                st.error("Scan submission failed. Verify FastAPI backend connectivity and API key.")
