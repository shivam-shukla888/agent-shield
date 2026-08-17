"""
Minimal Sample Scan Smoke Test & Sample HTML Report Generator (Task 7)

Executes an end-to-end security scan against local test_target fixture
and generates docs/examples/sample_scan_report.html as a committed example artifact.
"""

import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from fastapi.testclient import TestClient


from app.adapters.http import GenericHTTPAdapter
from app.api.schemas import (
    ImpactLevel,
    ProbeSelectionRequest,
    RiskContextRequest,
    ScanRequest,
    TargetScanRequest,
)
from app.api.service import ScanService
from app.domain.risk import AssetSensitivity, BlastRadiusLevel, ExploitabilityLevel, ToolPrivilege
from app.domain.target import TargetConfig
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.report import ReportEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.repositories import InMemoryScanRepository
from test_target.main import local_target_app
from test_target.tools import reset_test_state


from app.security.ssrf import SSRFValidator


def run_smoke_scan_and_generate_report() -> Path:
    reset_test_state()

    test_client = TestClient(local_target_app)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        res = test_client.request(
            method=request.method,
            url=str(request.url),
            content=request.content,
            headers=dict(request.headers),
        )
        return httpx.Response(
            status_code=res.status_code,
            headers=dict(res.headers),
            content=res.content,
        )

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = TargetConfig(
        name="Local Synthetic Agent Target",
        endpoint="http://testagent.local/chat",
        request_template={"prompt": "{{input}}"},
        response_path="response",
        timeout_seconds=5.0,
    )
    ssrf_validator = SSRFValidator(dns_resolver=lambda h: ["93.184.216.34"])
    adapter = GenericHTTPAdapter(config=config, client=client, ssrf_validator=ssrf_validator)

    attack_engine = AttackEngine(adapter=adapter)
    evaluator = DeterministicEvaluator()
    finding_engine = FindingEngine()
    risk_engine = RiskEngine()
    scan_engine = ScanEngine(
        attack_engine=attack_engine,
        evaluator=evaluator,
        finding_engine=finding_engine,
        risk_engine=risk_engine,
    )
    repo = InMemoryScanRepository()
    report_engine = ReportEngine()
    service = ScanService(scan_engine=scan_engine, repository=repo, report_engine=report_engine)

    scan_req = ScanRequest(
        scan_id="SMOKE_SCAN_2026_SAMPLE",
        target=TargetScanRequest(
            target_name="Local Synthetic Agent Target",
            endpoint="http://testagent.local/chat",
            request_template={"prompt": "{{input}}"},
            response_path="response",
        ),
        probes=ProbeSelectionRequest(
            probe_ids=["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001", "TOOL_AUTH_001"]
        ),
        risk_context=RiskContextRequest(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.WRITE,
        ),
    )

    # Submit and run scan directly
    scan_resp = service.submit_scan(scan_req)

    # Generate HTML report
    report_content, media_type, filename = service.generate_report("SMOKE_SCAN_2026_SAMPLE", report_format="html")

    # Save artifact to docs/examples/sample_scan_report.html
    output_dir = Path("docs/examples")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "sample_scan_report.html"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"[+] Successfully ran smoke scan '{scan_resp.scan_id}' with status '{scan_resp.status}'")
    print(f"[+] Generated sample HTML report: {report_path.resolve()}")
    return report_path


if __name__ == "__main__":
    run_smoke_scan_and_generate_report()
