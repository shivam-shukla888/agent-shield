"""
AgentShield UI Components — Audit Log & Security Investigation Module (ui_components/audit_log.py)
"""

from typing import Any, Dict, List
import pandas as pd
import streamlit as st
import api_client
import components_3d


def render_audit_log_tab(backend_url: str, api_key: str, is_demo: bool):
    """
    Renders the Audit Log & Investigation Console tab.
    """
    st.subheader("Security Audit Log & Investigation Console")
    st.caption("Search historical scan runs, investigate vulnerability traces, and export sanitized evidence reports.")

    scans = api_client.list_scans(backend_url, api_key, is_demo)
    if not scans:
        st.info("No security scans recorded yet. Run your first audit from the Scan Studio tab.")
        if st.button("Run First Security Scan", type="primary"):
            st.session_state.active_tab = 1
            st.rerun()
        return

    # SEARCH & MULTI-LEVEL FILTERS
    fl_1, fl_2, fl_3 = st.columns([2, 1, 1])
    with fl_1:
        query = st.text_input("🔍 Search Target, Scan ID, or Probe ID", "")
    with fl_2:
        severity_flt = st.selectbox("Filter Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "SAFE"])
    with fl_3:
        status_flt = st.selectbox("Filter Status", ["ALL", "COMPLETED", "RUNNING", "FAILED"])

    filtered = scans

    if query:
        q_clean = query.lower()
        filtered = [
            s for s in filtered
            if q_clean in str(s.get("target_name") or s.get("target", {}).get("target_name", "")).lower()
            or q_clean in str(s.get("scan_id", "")).lower()
        ]

    if status_flt != "ALL":
        filtered = [s for s in filtered if s.get("status") == status_flt]

    if severity_flt != "ALL":
        out = []
        for s in filtered:
            f_list = s.get("findings", [])
            if any((f.get("severity") or "").upper() == severity_flt for f in f_list):
                out.append(s)
        filtered = out

    # DATATABLE
    rows = []
    for s in filtered:
        target_str = s.get("target_name") or s.get("target", {}).get("target_name", "Unknown Target")
        r_score = s.get("risk_score")
        if r_score is None and "risk_assessments" in s:
            r_list = s.get("risk_assessments", [])
            r_score = r_list[0].get("risk_score") if r_list else 0

        findings = s.get("findings", [])
        crit_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
        high_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")

        rows.append({
            "Scan ID": s.get("scan_id"),
            "Target Agent": target_str,
            "Status": s.get("status"),
            "Risk Index": int(r_score or 0),
            "Total Findings": len(findings),
            "Critical": crit_count,
            "High": high_count,
        })

    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    st.divider()

    # DEDICATED SCAN INVESTIGATION VIEW
    st.subheader("🔍 Scan Run Detailed Investigation")
    selected_id = st.selectbox("Select Scan ID to Inspect", [s.get("scan_id") for s in filtered])

    if selected_id:
        scan_obj = next((s for s in filtered if s.get("scan_id") == selected_id), None)
        if scan_obj:
            target_name = scan_obj.get("target_name") or scan_obj.get("target", {}).get("target_name", "Target Agent")
            st.markdown(f"### Audit Report for `{target_name}` (`{selected_id}`)")

            inv_col1, inv_col2 = st.columns([1, 2])
            with inv_col1:
                r_score = scan_obj.get("risk_score")
                if r_score is None and "risk_assessments" in scan_obj:
                    r_list = scan_obj.get("risk_assessments", [])
                    r_score = r_list[0].get("risk_score") if r_list else 0
                components_3d.render_risk_score_gauge(int(r_score or 0), height=160)

            with inv_col2:
                st.markdown("#### Attack Surface Breakdown")
                findings = scan_obj.get("findings", [])
                if not findings:
                    st.success("🟢 No policy breaches detected. Target agent behavior remained within security parameters.")
                else:
                    st.write(f"**Total Findings:** `{len(findings)}`")
                    for f in findings:
                        f_title = f.get("title", "Finding")
                        f_sev = (f.get("severity") or "MEDIUM").upper()
                        f_probe = f.get("probe_id") or f.get("finding_id", "PROBE_UNKNOWN")
                        f_desc = f.get("description", "Vulnerability detected.")
                        f_impact = f.get("impact", "Attacker can exploit LLM control flow.")
                        f_rem = f.get("remediation", "# Mitigation snippet")

                        badge_class = "pill-critical" if f_sev == "CRITICAL" else "pill-high" if f_sev == "HIGH" else "pill-medium" if f_sev == "MEDIUM" else "pill-safe"

                        with st.expander(f"{f_title} — {f_sev}"):
                            st.markdown(f'<span class="{badge_class}">{f_sev} SEVERITY</span>', unsafe_allow_html=True)
                            st.write(f"**Probe ID:** `{f_probe}`")
                            st.write(f"**Description:** {f_desc}")
                            st.write(f"**Impact:** {f_impact}")
                            st.markdown("**Evidence Trace:**")
                            st.markdown(f'<div class="evidence-box">> Response trace confirms policy violation ({f_probe})</div>', unsafe_allow_html=True)
                            st.markdown("**Recommended Remediation:**")
                            st.code(f_rem, language="python")

            st.divider()

            # REPORT EXPORT CENTER
            st.subheader("📥 Multi-Format Report Export Center")
            st.caption("Download sanitized security evidence reports for executive reviews, developer documentation, or CI/CD pipelines.")

            c1, c2, c3, c4 = st.columns(4)

            html_b = api_client.get_report(backend_url, api_key, selected_id, "html", is_demo)
            if html_b:
                c1.download_button(
                    "🌐 HTML Report",
                    data=html_b,
                    file_name=f"{selected_id}_report.html",
                    mime="text/html",
                    use_container_width=True,
                    help="Interactive shareable HTML security report.",
                )

            pdf_b = api_client.get_report(backend_url, api_key, selected_id, "pdf", is_demo)
            if pdf_b:
                c2.download_button(
                    "📄 PDF Report",
                    data=pdf_b,
                    file_name=f"{selected_id}_report.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    help="Sanitized executive security & compliance PDF report.",
                )

            md_b = api_client.get_report(backend_url, api_key, selected_id, "markdown", is_demo)
            if md_b:
                c3.download_button(
                    "📝 Markdown Report",
                    data=md_b,
                    file_name=f"{selected_id}_report.md",
                    mime="text/markdown",
                    use_container_width=True,
                    help="Developer documentation & ticket attachment report.",
                )

            json_b = api_client.get_report(backend_url, api_key, selected_id, "json", is_demo)
            if json_b:
                c4.download_button(
                    "📦 Raw JSON DTO",
                    data=json_b,
                    file_name=f"{selected_id}_report.json",
                    mime="application/json",
                    use_container_width=True,
                    help="Machine-readable JSON export for CI/CD automation.",
                )

            with st.expander("🔍 Advanced Scan Object Payload Inspector"):
                st.json(scan_obj)
