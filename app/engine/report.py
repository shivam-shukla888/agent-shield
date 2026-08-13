"""
Reporting Engine (STEP 16A & STEP 16B)

This module implements the deterministic ReportEngine responsible for converting completed
security scan results (ScanResult or ScanResponse) into sanitized human-readable SecurityReport DTOs
and rendering reports into Markdown, JSON, HTML, or PDF formats.

ARCHITECTURAL DIRECTIVES:
1. Deterministic output: The same scan input produces the exact same report structure and content.
2. Zero recalculation: Consumes already calculated Finding and RiskAssessment objects. Does NOT re-score.
3. Zero LLM / Zero Network: Executive summaries and recommendations are generated deterministically using code rules.
4. Strict Sanitization: Excludes credentials, API keys, bearer tokens, DB connection strings, raw HTTP headers,
   and raw target response bodies.
5. Report ID is deterministically derived as `REPORT_<scan_id>` unless explicitly specified.
"""

from datetime import datetime, timezone
import html
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union
from fpdf import FPDF

from app.domain.finding import Finding
from app.domain.report import ReportFinding, ReportFormat, ReportRisk, SecurityReport
from app.domain.risk import RiskAssessment
from app.domain.scan import ScanResult

if TYPE_CHECKING:
    from app.api.schemas import ScanFindingResponse, ScanResponse, ScanRiskResponse

MAX_REPORT_EVIDENCE_LENGTH = 500
MAX_REPORT_FINDINGS = 100
MAX_REPORT_RECOMMENDATIONS = 50


RECOMMENDATIONS_MAP = {
    "system_prompt_disclosure": (
        "Review system prompt isolation and ensure sensitive system instructions cannot be disclosed through adversarial input."
    ),
    "instruction_override": (
        "Strengthen instruction hierarchy enforcement and validate resistance against prompt injection and instruction override attacks."
    ),
    "tool_authorization": (
        "Enforce strict authorization boundaries for tool invocation and require explicit permission checks before privileged operations."
    ),
}


def _pdf_clean(text: Any) -> str:
    """Sanitize text to safe latin-1 encoding for standard FPDF core fonts."""
    if text is None:
        return ""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class SecurityReportPDF(FPDF):
    """Custom FPDF layout for AgentGuard security reports."""

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(30, 41, 59)
        self.cell(0, 10, "AgentGuard Security Report", border=False, new_x="LMARGIN", new_y="NEXT", align="L")
        self.set_draw_color(226, 232, 240)
        self.line(10, 20, 200, 20)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


class ReportEngine:
    """
    Deterministic security report generation and rendering engine.
    """

    def create_report(
        self,
        scan_data: Union[ScanResult, ScanResponse],
        generated_at: Optional[datetime] = None,
        report_id: Optional[str] = None,
    ) -> SecurityReport:
        """
        Convert a completed scan result container or API response into a sanitized SecurityReport.
        """
        if hasattr(scan_data, "scan_id"):
            scan_id = scan_data.scan_id
            target_name = scan_data.target_name
            status = str(scan_data.status.value if hasattr(scan_data.status, "value") else scan_data.status)
            raw_findings = scan_data.findings
            raw_risks = scan_data.risk_assessments
            summary_dict = scan_data.summary.model_dump() if hasattr(scan_data.summary, "model_dump") else (
                scan_data.summary.__dict__ if hasattr(scan_data.summary, "__dict__") else dict(scan_data.summary)
            )
        else:
            raise ValueError("scan_data must be a valid ScanResult or ScanResponse instance")

        report_id_str = report_id or f"REPORT_{scan_id}"
        timestamp = generated_at or datetime.now(timezone.utc)

        converted_findings = self._convert_findings(raw_findings)
        converted_risks = self._convert_risks(raw_risks)

        exec_summary = self._generate_executive_summary(
            target_name=target_name,
            status=status,
            summary_dict=summary_dict,
            risks=converted_risks,
            findings=converted_findings,
        )

        recommendations = self._generate_recommendations(converted_findings)

        metadata = {
            "engine": "AgentGuard Reporting Engine v1.0",
            "deterministic": True,
        }

        return SecurityReport(
            report_id=report_id_str,
            scan_id=scan_id,
            target_name=target_name,
            status=status,
            generated_at=timestamp,
            executive_summary=exec_summary,
            summary=summary_dict,
            findings=converted_findings,
            risk_assessments=converted_risks,
            recommendations=recommendations,
            metadata=metadata,
        )

    def _convert_findings(self, raw_findings: List[Any]) -> List[ReportFinding]:
        """Convert domain or response findings into ReportFinding DTOs."""
        report_findings: List[ReportFinding] = []
        seen_ids = set()

        for f in raw_findings[:MAX_REPORT_FINDINGS]:
            if hasattr(f, "finding_id"):
                fid = getattr(f, "finding_id")
                if fid in seen_ids:
                    continue
                seen_ids.add(fid)

                cat_raw = getattr(f, "category")
                cat_str = str(cat_raw.value if hasattr(cat_raw, "value") else cat_raw)

                sev_raw = getattr(f, "severity")
                sev_str = str(sev_raw.value if hasattr(sev_raw, "value") else sev_raw)
                
                ev_str: Optional[str] = None
                evidence_list = getattr(f, "evidence", None)
                if evidence_list:
                    first_ev = evidence_list[0]
                    ev_summary = getattr(first_ev, "summary", "") or getattr(first_ev, "description", "")
                    if ev_summary:
                        ev_str = str(ev_summary)[:MAX_REPORT_EVIDENCE_LENGTH]

                report_findings.append(
                    ReportFinding(
                        finding_id=fid,
                        category=cat_str,
                        title=getattr(f, "title"),
                        severity=sev_str,
                        confidence=float(getattr(f, "confidence")),
                        description=getattr(f, "description"),
                        evidence=ev_str,
                        affected_probe_ids=list(getattr(f, "affected_probe_ids", [])),
                        affected_execution_ids=list(getattr(f, "affected_execution_ids", [])),
                        remediation=getattr(f, "remediation"),
                    )
                )

        return report_findings

    def _convert_risks(self, raw_risks: List[Any]) -> List[ReportRisk]:
        """Convert domain or response risk assessments into ReportRisk DTOs."""
        report_risks: List[ReportRisk] = []
        seen_ids = set()

        for r in raw_risks:
            if hasattr(r, "risk_id"):
                rid = getattr(r, "risk_id")
                if rid in seen_ids:
                    continue
                seen_ids.add(rid)

                lvl_raw = getattr(r, "risk_level")
                lvl_str = str(lvl_raw.value if hasattr(lvl_raw, "value") else lvl_raw)

                factors_obj = getattr(r, "factors", None)
                if hasattr(factors_obj, "model_dump"):
                    factors_dict = factors_obj.model_dump()
                elif hasattr(factors_obj, "__dict__"):
                    factors_dict = {k: str(v.value if hasattr(v, "value") else v) for k, v in factors_obj.__dict__.items()}
                elif isinstance(factors_obj, dict):
                    factors_dict = factors_obj
                else:
                    factors_dict = {}

                report_risks.append(
                    ReportRisk(
                        risk_id=rid,
                        finding_id=getattr(r, "finding_id"),
                        risk_level=lvl_str,
                        risk_score=float(getattr(r, "risk_score")),
                        confidence=float(getattr(r, "confidence")),
                        factors={k: str(v) for k, v in factors_dict.items()},
                        rationale=getattr(r, "rationale"),
                    )
                )

        report_risks.sort(key=lambda x: (x.risk_score, x.risk_id), reverse=True)
        return report_risks

    def _generate_executive_summary(
        self,
        target_name: str,
        status: str,
        summary_dict: Dict[str, int],
        risks: List[ReportRisk],
        findings: List[ReportFinding],
    ) -> str:
        """Generate concise, deterministic executive summary string."""
        total_probes = summary_dict.get("total_probes", len(findings))
        total_findings = summary_dict.get("total_findings", len(findings))
        status_upper = status.upper()

        if not risks:
            if total_findings == 0:
                return (
                    f"Scan completed with status '{status_upper}' against target '{target_name}'. "
                    f"{total_probes} probes were evaluated and 0 security findings were identified. "
                    "No contextual risks were detected."
                )
            else:
                return (
                    f"Scan completed with status '{status_upper}' against target '{target_name}'. "
                    f"{total_probes} probes were evaluated and {total_findings} security findings were identified."
                )

        highest_risk = risks[0]
        highest_level = highest_risk.risk_level.upper()
        highest_score_str = f"{highest_risk.risk_score:.2f}"

        return (
            f"Scan completed with status '{status_upper}' against target '{target_name}'. "
            f"{total_probes} probes were evaluated and {total_findings} security findings were identified. "
            f"The highest contextual risk was {highest_level} with a score of {highest_score_str}."
        )

    def _generate_recommendations(self, findings: List[ReportFinding]) -> List[str]:
        """Generate deduplicated remediation recommendations."""
        recs_set = set()

        for f in findings:
            cat_key = f.category.lower().strip()
            if cat_key in RECOMMENDATIONS_MAP:
                recs_set.add(RECOMMENDATIONS_MAP[cat_key])
            else:
                formatted_cat = cat_key.replace("_", " ").title()
                recs_set.add(f"Implement defense-in-depth mitigations and validation for category '{formatted_cat}'.")

        return sorted(list(recs_set))[:MAX_REPORT_RECOMMENDATIONS]

    def render_markdown(self, report: SecurityReport) -> str:
        """Render SecurityReport object as GitHub Flavored Markdown."""
        lines = [
            "# AgentGuard Security Report",
            "",
            "## Executive Summary",
            "",
            report.executive_summary,
            "",
            "## Scan Information",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Report ID | `{report.report_id}` |",
            f"| Scan ID | `{report.scan_id}` |",
            f"| Target Name | {report.target_name} |",
            f"| Status | `{report.status.upper()}` |",
            f"| Generated At | {report.generated_at.isoformat()} |",
            "",
            "## Security Summary",
            "",
            f"- **Total Probes Evaluated**: {report.summary.get('total_probes', 0)}",
            f"- **Completed Executions**: {report.summary.get('completed_executions', 0)}",
            f"- **Failed Executions**: {report.summary.get('failed_executions', 0)}",
            f"- **Total Findings**: {report.summary.get('total_findings', 0)}",
            f"- **Critical Risks**: {report.summary.get('critical_risks', 0)}",
            f"- **High Risks**: {report.summary.get('high_risks', 0)}",
            f"- **Medium Risks**: {report.summary.get('medium_risks', 0)}",
            f"- **Low Risks**: {report.summary.get('low_risks', 0)}",
            f"- **Info Risks**: {report.summary.get('info_risks', 0)}",
            "",
            "## Findings",
            "",
        ]

        if not report.findings:
            lines.append("No security findings were identified.")
            lines.append("")
        else:
            for idx, finding in enumerate(report.findings[:MAX_REPORT_FINDINGS], start=1):
                lines.extend(
                    [
                        f"### {idx}. {finding.title}",
                        f"- **Finding ID**: `{finding.finding_id}`",
                        f"- **Category**: `{finding.category}`",
                        f"- **Severity**: `{finding.severity.upper()}`",
                        f"- **Confidence**: {finding.confidence:.2f}",
                        f"- **Affected Probes**: {', '.join(finding.affected_probe_ids) if finding.affected_probe_ids else 'None'}",
                        f"- **Description**: {finding.description}",
                        f"- **Evidence**: {finding.evidence if finding.evidence else 'No raw evidence retained'}",
                        f"- **Remediation**: {finding.remediation}",
                        "",
                    ]
                )

        lines.extend(["## Risk Assessments", ""])

        if not report.risk_assessments:
            lines.append("No risk assessments were recorded.")
            lines.append("")
        else:
            for idx, risk in enumerate(report.risk_assessments, start=1):
                lines.extend(
                    [
                        f"### Risk {idx}: {risk.risk_level.upper()} ({risk.risk_score:.2f})",
                        f"- **Risk ID**: `{risk.risk_id}`",
                        f"- **Finding ID**: `{risk.finding_id}`",
                        f"- **Risk Level**: `{risk.risk_level.upper()}`",
                        f"- **Risk Score**: {risk.risk_score:.2f}",
                        f"- **Confidence**: {risk.confidence:.2f}",
                        f"- **Rationale**: {risk.rationale}",
                        "",
                    ]
                )

        lines.extend(["## Recommendations", ""])

        if not report.recommendations:
            lines.append("No specific remediation recommendations are required.")
            lines.append("")
        else:
            for idx, rec in enumerate(report.recommendations[:MAX_REPORT_RECOMMENDATIONS], start=1):
                lines.append(f"{idx}. {rec}")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self, report: SecurityReport) -> Dict[str, Any]:
        """Convert SecurityReport object to a JSON-serializable dictionary."""
        data = report.model_dump()
        if isinstance(data.get("generated_at"), datetime):
            data["generated_at"] = data["generated_at"].isoformat()
        return data

    def render_json(self, report: SecurityReport) -> str:
        """Render SecurityReport object as formatted JSON string."""
        return json.dumps(self.to_dict(report), indent=2)

    def render_html(self, report: SecurityReport) -> str:
        """
        Render SecurityReport object as clean, self-contained HTML.
        Escapes untrusted string inputs with html.escape(). No external CSS/JS.
        """
        esc_target = html.escape(report.target_name)
        esc_status = html.escape(report.status.upper())
        esc_summary = html.escape(report.executive_summary)
        esc_report_id = html.escape(report.report_id)
        esc_scan_id = html.escape(report.scan_id)
        esc_generated = html.escape(report.generated_at.isoformat())

        findings_html = ""
        if not report.findings:
            findings_html = "<p class='empty-text'>No security findings were identified.</p>"
        else:
            for idx, f in enumerate(report.findings[:MAX_REPORT_FINDINGS], start=1):
                sev_cls = html.escape(f.severity.lower())
                ev_html = f"<div class='evidence-box'><strong>Evidence:</strong> {html.escape(f.evidence)}</div>" if f.evidence else ""
                probes_str = html.escape(", ".join(f.affected_probe_ids)) if f.affected_probe_ids else "None"
                findings_html += f"""
                <div class="card finding-card">
                    <div class="card-header">
                        <h3>{idx}. {html.escape(f.title)}</h3>
                        <span class="badge badge-{sev_cls}">{html.escape(f.severity.upper())}</span>
                    </div>
                    <div class="card-body">
                        <p><strong>Finding ID:</strong> <code>{html.escape(f.finding_id)}</code></p>
                        <p><strong>Category:</strong> <code>{html.escape(f.category)}</code></p>
                        <p><strong>Confidence:</strong> {f.confidence:.2f}</p>
                        <p><strong>Affected Probes:</strong> {probes_str}</p>
                        <p><strong>Description:</strong> {html.escape(f.description)}</p>
                        {ev_html}
                        <p class="remediation"><strong>Remediation:</strong> {html.escape(f.remediation)}</p>
                    </div>
                </div>
                """

        risks_html = ""
        if not report.risk_assessments:
            risks_html = "<p class='empty-text'>No risk assessments were recorded.</p>"
        else:
            for idx, r in enumerate(report.risk_assessments, start=1):
                lvl_cls = html.escape(r.risk_level.lower())
                risks_html += f"""
                <div class="card risk-card">
                    <div class="card-header">
                        <h3>Risk {idx}: {html.escape(r.risk_level.upper())} ({r.risk_score:.2f})</h3>
                        <span class="badge badge-{lvl_cls}">{r.risk_score:.2f}</span>
                    </div>
                    <div class="card-body">
                        <p><strong>Risk ID:</strong> <code>{html.escape(r.risk_id)}</code></p>
                        <p><strong>Finding ID:</strong> <code>{html.escape(r.finding_id)}</code></p>
                        <p><strong>Confidence:</strong> {r.confidence:.2f}</p>
                        <p><strong>Rationale:</strong> {html.escape(r.rationale)}</p>
                    </div>
                </div>
                """

        recs_html = ""
        if not report.recommendations:
            recs_html = "<p class='empty-text'>No specific remediation recommendations are required.</p>"
        else:
            recs_items = "".join([f"<li>{html.escape(rec)}</li>" for rec in report.recommendations[:MAX_REPORT_RECOMMENDATIONS]])
            recs_html = f"<ol class='recs-list'>{recs_items}</ol>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentGuard Security Report - {esc_target}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --primary: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }}
        h1 {{
            color: var(--primary);
            margin: 0 0 0.5rem 0;
        }}
        h2 {{
            color: var(--primary);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
            margin-top: 2rem;
        }}
        .exec-summary {{
            background: #0284c715;
            border-left: 4px solid var(--primary);
            padding: 1rem 1.5rem;
            border-radius: 4px;
            margin-bottom: 2rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.5rem;
            background: var(--card-bg);
            border-radius: 6px;
            overflow: hidden;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #0f172a;
            color: var(--text-muted);
        }}
        code {{
            font-family: monospace;
            background: #0f172a;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            color: #38bdf8;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            padding: 1.25rem;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .card-header h3 {{
            margin: 0;
            font-size: 1.2rem;
        }}
        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-weight: bold;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #fff; }}
        .badge-info {{ background: var(--info); color: #fff; }}
        .evidence-box {{
            background: #0f172a;
            border-left: 3px solid var(--medium);
            padding: 0.75rem;
            margin: 0.75rem 0;
            font-family: monospace;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .remediation {{
            color: #4ade80;
        }}
        .empty-text {{
            color: var(--text-muted);
            font-style: italic;
        }}
        footer {{
            margin-top: 4rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            padding-top: 1rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AgentGuard Security Report</h1>
            <p>Target: <strong>{esc_target}</strong> | Generated At: {esc_generated}</p>
        </header>

        <section class="exec-summary">
            <h2>Executive Summary</h2>
            <p>{esc_summary}</p>
        </section>

        <section>
            <h2>Scan Information</h2>
            <table>
                <tr><th>Report ID</th><td><code>{esc_report_id}</code></td></tr>
                <tr><th>Scan ID</th><td><code>{esc_scan_id}</code></td></tr>
                <tr><th>Target Name</th><td>{esc_target}</td></tr>
                <tr><th>Execution Status</th><td><code>{esc_status}</code></td></tr>
                <tr><th>Generated Timestamp</th><td>{esc_generated}</td></tr>
            </table>
        </section>

        <section>
            <h2>Security Summary</h2>
            <table>
                <tr><th>Total Probes Evaluated</th><td>{report.summary.get('total_probes', 0)}</td></tr>
                <tr><th>Completed Executions</th><td>{report.summary.get('completed_executions', 0)}</td></tr>
                <tr><th>Failed Executions</th><td>{report.summary.get('failed_executions', 0)}</td></tr>
                <tr><th>Total Findings</th><td>{report.summary.get('total_findings', 0)}</td></tr>
                <tr><th>Critical Risks</th><td>{report.summary.get('critical_risks', 0)}</td></tr>
                <tr><th>High Risks</th><td>{report.summary.get('high_risks', 0)}</td></tr>
                <tr><th>Medium Risks</th><td>{report.summary.get('medium_risks', 0)}</td></tr>
                <tr><th>Low Risks</th><td>{report.summary.get('low_risks', 0)}</td></tr>
                <tr><th>Info Risks</th><td>{report.summary.get('info_risks', 0)}</td></tr>
            </table>
        </section>

        <section>
            <h2>Findings</h2>
            {findings_html}
        </section>

        <section>
            <h2>Risk Assessments</h2>
            {risks_html}
        </section>

        <section>
            <h2>Recommendations</h2>
            {recs_html}
        </section>

        <footer>
            <p>Generated by AgentGuard Security Testing & Risk Analysis Platform</p>
        </footer>
    </div>
</body>
</html>"""

    def render_pdf(self, report: SecurityReport) -> bytes:
        """
        Render SecurityReport object as valid PDF document bytes using fpdf2.
        Consumes SecurityReport DTO only. Does not perform recalculations or network calls.
        """
        pdf = SecurityReportPDF(orientation="P", unit="mm", format="A4")
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # 1. Executive Summary
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(56, 189, 248)
        pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 41, 59)
        pdf.multi_cell(0, 5, _pdf_clean(report.executive_summary), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # 2. Scan Information
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(56, 189, 248)
        pdf.cell(0, 8, "Scan Information", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 5, _pdf_clean(f"Report ID: {report.report_id}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _pdf_clean(f"Scan ID: {report.scan_id}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _pdf_clean(f"Target Name: {report.target_name}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _pdf_clean(f"Status: {report.status.upper()}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _pdf_clean(f"Generated At: {report.generated_at.isoformat()}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # 3. Security Summary Counts
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(56, 189, 248)
        pdf.cell(0, 8, "Security Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 5, _pdf_clean(f"Total Probes Evaluated: {report.summary.get('total_probes', 0)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _pdf_clean(f"Completed Executions: {report.summary.get('completed_executions', 0)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _pdf_clean(f"Total Findings: {report.summary.get('total_findings', 0)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _pdf_clean(f"Critical Risks: {report.summary.get('critical_risks', 0)} | High Risks: {report.summary.get('high_risks', 0)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # 4. Findings Section
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(56, 189, 248)
        pdf.cell(0, 8, "Findings", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 41, 59)

        if not report.findings:
            pdf.cell(0, 5, "No security findings were identified.", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        else:
            for idx, f in enumerate(report.findings[:MAX_REPORT_FINDINGS], start=1):
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 6, _pdf_clean(f"{idx}. {f.title} [{f.severity.upper()}]"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 5, _pdf_clean(f"Finding ID: {f.finding_id} | Category: {f.category} | Confidence: {f.confidence:.2f}"), new_x="LMARGIN", new_y="NEXT")
                pdf.multi_cell(0, 5, _pdf_clean(f"Description: {f.description}"), new_x="LMARGIN", new_y="NEXT")
                if f.evidence:
                    pdf.multi_cell(0, 5, _pdf_clean(f"Evidence: {f.evidence[:MAX_REPORT_EVIDENCE_LENGTH]}"), new_x="LMARGIN", new_y="NEXT")
                pdf.multi_cell(0, 5, _pdf_clean(f"Remediation: {f.remediation}"), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)

        # 5. Risk Assessments Section
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(56, 189, 248)
        pdf.cell(0, 8, "Risk Assessments", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 41, 59)

        if not report.risk_assessments:
            pdf.cell(0, 5, "No risk assessments were recorded.", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        else:
            for idx, r in enumerate(report.risk_assessments, start=1):
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 6, _pdf_clean(f"Risk {idx}: {r.risk_level.upper()} (Score: {r.risk_score:.2f})"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 5, _pdf_clean(f"Risk ID: {r.risk_id} | Finding ID: {r.finding_id}"), new_x="LMARGIN", new_y="NEXT")
                pdf.multi_cell(0, 5, _pdf_clean(f"Rationale: {r.rationale}"), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)

        # 6. Recommendations Section
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(56, 189, 248)
        pdf.cell(0, 8, "Recommendations", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 41, 59)

        if not report.recommendations:
            pdf.cell(0, 5, "No specific remediation recommendations are required.", new_x="LMARGIN", new_y="NEXT")
        else:
            for idx, rec in enumerate(report.recommendations[:MAX_REPORT_RECOMMENDATIONS], start=1):
                pdf.multi_cell(0, 5, _pdf_clean(f"{idx}. {rec}"), new_x="LMARGIN", new_y="NEXT")

        return bytes(pdf.output())
