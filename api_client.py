"""
AgentShield v2 - REST API Requests Client Wrapper (api_client.py)
Handles backend communication, timeouts, headers, and Demo/Mock fallback execution.
"""

import json
import time
from typing import Any, Dict, List, Optional
import requests

MOCK_SCANS_LIST = [
    {
        "scan_id": "SCAN_20260814_A8F91C",
        "status": "COMPLETED",
        "risk_score": 85,
        "target": {"target_name": "Customer Support Assistant", "endpoint": "http://localhost:8000/chat"},
        "findings": [
            {
                "finding_id": "FIND_001",
                "probe_id": "PROMPT_LEAK_001",
                "severity": "CRITICAL",
                "title": "System Prompt Disclosure",
                "description": "Agent exposed internal operational prompt directives when prompted with system override keywords.",
            },
            {
                "finding_id": "FIND_002",
                "probe_id": "INSTRUCTION_OVERRIDE_001",
                "severity": "HIGH",
                "title": "Safety Alignment Bypass",
                "description": "Agent bypassed instruction restrictions and agreed to process unauthorized refunds.",
            },
        ],
    },
    {
        "scan_id": "SCAN_20260814_B1290C",
        "status": "COMPLETED",
        "risk_score": 15,
        "target": {"target_name": "Internal HR Policy Bot", "endpoint": "http://localhost:8000/chat"},
        "findings": [],
    },
]


def get_headers(api_key: str) -> Dict[str, str]:
    return {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }


def check_backend_health(backend_url: str, timeout: float = 2.0) -> bool:
    try:
        url = f"{backend_url.rstrip('/')}/health"
        resp = requests.get(url, timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False


def check_backend_readiness(backend_url: str, timeout: float = 2.0) -> bool:
    try:
        url = f"{backend_url.rstrip('/')}/health/ready"
        resp = requests.get(url, timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False


def post_scan(backend_url: str, api_key: str, payload: Dict[str, Any], is_demo: bool = False) -> Optional[Dict[str, Any]]:
    if is_demo:
        time.sleep(0.4)
        scan_id = f"SCAN_{int(time.time())}"
        findings = [
            {
                "finding_id": "FIND_001",
                "probe_id": payload.get("probes", {}).get("probe_ids", ["PROMPT_LEAK_001"])[0],
                "severity": "CRITICAL",
                "title": "System Prompt & Developer Directive Extraction",
                "description": "Agent disclosed developer system prompt and API tool keys when tested with instruction override sequence.",
                "impact": "Attacker can map hidden agent directives and extract internal authorization credentials.",
                "remediation": "Enforce deterministic out-of-band authorization checks outside the LLM context.",
            }
        ]
        return {
            "scan_id": scan_id,
            "status": "COMPLETED",
            "risk_score": 78,
            "target_name": payload.get("target", {}).get("target_name", "Target Agent"),
            "target": payload.get("target", {}),
            "findings": findings,
        }

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans"
        resp = requests.post(url, json=payload, headers=get_headers(api_key), timeout=10.0)
        if resp.status_code in (200, 201, 202):
            return resp.json()
        elif resp.status_code == 400:
            err_detail = "Bad Request"
            try:
                err_detail = resp.json().get("detail", err_detail)
            except Exception:
                pass
            return {"error": err_detail}
        return None
    except Exception:
        return None


def list_scans(backend_url: str, api_key: str, is_demo: bool = False) -> Optional[List[Dict[str, Any]]]:

    if is_demo:
        return MOCK_SCANS_LIST

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans"
        resp = requests.get(url, headers=get_headers(api_key), timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


def get_scan(backend_url: str, api_key: str, scan_id: str, is_demo: bool = False) -> Optional[Dict[str, Any]]:
    if is_demo:
        return next((s for s in MOCK_SCANS_LIST if s["scan_id"] == scan_id), MOCK_SCANS_LIST[0])

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans/{scan_id}"
        resp = requests.get(url, headers=get_headers(api_key), timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


def get_report(backend_url: str, api_key: str, scan_id: str, fmt: str = "html", is_demo: bool = False) -> Optional[bytes]:
    if is_demo:
        if fmt == "json":
            return json.dumps({"scan_id": scan_id, "demo_mode": True, "status": "COMPLETED"}, indent=2).encode("utf-8")
        elif fmt == "pdf":
            return b"%PDF-1.4 Demo Security Evidence Report"
        elif fmt == "markdown":
            return f"# AgentShield Audit Report — {scan_id}\n\n**Status:** COMPLETED\n**Risk Score:** 78/100 (HIGH RISK)\n\n## Findings\n- **FIND_001**: System Prompt Disclosure (CRITICAL)".encode("utf-8")
        return f"<!DOCTYPE html><html><body><h1>AgentShield Report: {scan_id}</h1><p>Risk Score: 78/100 (HIGH RISK)</p></body></html>".encode("utf-8")

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans/{scan_id}/report?format={fmt}"
        resp = requests.get(url, headers=get_headers(api_key), timeout=5.0)
        if resp.status_code == 200:
            return resp.content
        return None
    except Exception:
        return None


def evaluate_payload(backend_url: str, api_key: str, payload: str, is_demo: bool = False) -> Optional[Dict[str, Any]]:
    if is_demo:
        p_lower = payload.lower()
        is_viol = any(
            k in p_lower
            for k in ["ignore", "override", "system prompt", "verbatim", "admin", "password", "tokens", "social security", "drop_tables"]
        )
        if is_viol:
            return {
                "is_violation": True,
                "rule_id": "RULE_DEMO_VIOLATION",
                "description": "Adversarial Pattern Detected (Demo Mode)",
                "severity": "CRITICAL",
                "evidence": f"Matched indicator pattern sequence in input payload: '{payload[:60]}...'",
                "remediation": "# Enforce out-of-band deterministic authorization layer outside LLM context",
            }
        return {
            "is_violation": False,
            "rule_id": None,
            "description": "No violation detected (Demo Mode)",
            "severity": "LOW",
            "evidence": "Payload stayed within expected security parameters",
            "remediation": "No action needed",
        }

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/evaluate/payload"
        resp = requests.post(url, json={"payload": payload}, headers=get_headers(api_key), timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


