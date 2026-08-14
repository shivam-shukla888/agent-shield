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


def post_scan(backend_url: str, api_key: str, payload: Dict[str, Any], is_demo: bool = False) -> Optional[Dict[str, Any]]:
    if is_demo:
        time.sleep(0.4)
        scan_id = f"SCAN_{int(time.time())}"
        findings = [
            {
                "finding_id": "FIND_001",
                "probe_id": payload.get("probes", {}).get("probe_ids", ["PROMPT_LEAK_001"])[0],
                "severity": "HIGH",
                "title": "System Prompt & Key Disclosure",
                "description": "Agent exposed developer directives when tested with instruction override payload.",
            }
        ]
        return {
            "scan_id": scan_id,
            "status": "COMPLETED",
            "risk_score": 75,
            "target": payload.get("target", {}),
            "findings": findings,
        }

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans"
        resp = requests.post(url, json=payload, headers=get_headers(api_key), timeout=10.0)
        if resp.status_code in (200, 201, 202):
            return resp.json()
        return None
    except Exception:
        return None


def list_scans(backend_url: str, api_key: str, is_demo: bool = False) -> List[Dict[str, Any]]:
    if is_demo:
        return MOCK_SCANS_LIST

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans"
        resp = requests.get(url, headers=get_headers(api_key), timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
        return MOCK_SCANS_LIST
    except Exception:
        return MOCK_SCANS_LIST


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
            return json.dumps({"scan_id": scan_id, "demo_mode": True}).encode("utf-8")
        elif fmt == "pdf":
            return b"%PDF-1.4 Demo PDF Report Content"
        return f"<html><body><h1>Demo Report for {scan_id}</h1></body></html>".encode("utf-8")

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans/{scan_id}/report?format={fmt}"
        resp = requests.get(url, headers=get_headers(api_key), timeout=5.0)
        if resp.status_code == 200:
            return resp.content
        return None
    except Exception:
        return None
