"""
ScanEngine Implementation

This module defines the ScanEngine class, which orchestrates the complete AgentShield security scanning pipeline:
SecurityProbe -> AttackEngine -> ProbeExecution -> Evaluator -> EvaluationResult -> FindingEngine -> Finding -> RiskEngine -> RiskAssessment -> ScanResult

ARCHITECTURAL DIRECTIVES:
1. ScanEngine is strictly an ORCHESTRATOR.
2. It MUST NOT duplicate the responsibilities of AttackEngine, TargetAdapter, Evaluator, FindingEngine, or RiskEngine.
3. Dependencies are received via constructor injection.
4. Operates 100% synchronously and in-memory. Does NOT introduce databases, Redis, Celery, LLMs, or parallel workers.
5. Operational execution errors (e.g. ExecutionStatus.ERROR or EvaluationVerdict.ERROR) result in PARTIAL/FAILED status,
   whereas security violations (EvaluationVerdict.VIOLATION) result in COMPLETED status.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from app.domain.evaluation import EvaluationResult, EvaluationVerdict
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.finding import Finding
from app.domain.probe import SecurityProbe
from app.domain.risk import RiskAssessment, RiskFactors, RiskLevel
from app.domain.scan import ScanResult, ScanStatus, ScanSummary
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.evaluation.base import Evaluator


class ScanEngine:
    """
    Core orchestrator coordinating security probe execution, evaluation, finding aggregation,
    and contextual risk assessment into a unified ScanResult.

    Pipeline Dataflow:
    ScanEngine ──► AttackEngine ──► ProbeExecution
                     │
                     ▼
                  Evaluator ──► EvaluationResult
                                    │
                                    ▼
                               FindingEngine ──► Finding
                                                     │
                                                     ▼
                                                RiskEngine ──► RiskAssessment
                                                                    │
                                                                    ▼
                                                               ScanResult
    """

    def __init__(
        self,
        attack_engine: AttackEngine,
        evaluator: Evaluator,
        finding_engine: FindingEngine,
        risk_engine: RiskEngine,
    ) -> None:
        """
        Initialize ScanEngine with injected component dependencies.

        Args:
            attack_engine (AttackEngine): Engine for executing security probes against targets.
            evaluator (Evaluator): Evaluator engine for judging probe execution responses.
            finding_engine (FindingEngine): Engine for converting/aggregating evaluation violations into Findings.
            risk_engine (RiskEngine): Engine for assessing contextual risk of Findings.
        """
        if not isinstance(attack_engine, AttackEngine):
            raise ValueError("attack_engine must be a valid AttackEngine instance")
        if not isinstance(evaluator, Evaluator):
            raise ValueError("evaluator must be a valid Evaluator instance")
        if not isinstance(finding_engine, FindingEngine):
            raise ValueError("finding_engine must be a valid FindingEngine instance")
        if not isinstance(risk_engine, RiskEngine):
            raise ValueError("risk_engine must be a valid RiskEngine instance")

        self.attack_engine = attack_engine
        self.evaluator = evaluator
        self.finding_engine = finding_engine
        self.risk_engine = risk_engine

    def run_scan(
        self,
        scan_id: str,
        target_name: str,
        probes: Sequence[SecurityProbe],
        risk_factors: RiskFactors,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """
        Orchestrate a complete end-to-end security scan.

        Args:
            scan_id (str): Non-empty unique scan identifier supplied by caller.
            target_name (str): Non-empty target agent name.
            probes (Sequence[SecurityProbe]): Sequence of security probes to execute.
            risk_factors (RiskFactors): Contextual environment risk factors.
            metadata (Optional[Dict[str, Any]]): Optional scan operational metadata.

        Returns:
            ScanResult: Complete aggregated scan result artifact.
        """
        # 1. Identifier Validation
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ValueError("scan_id must be a non-empty string")
        if not isinstance(target_name, str) or not target_name.strip():
            raise ValueError("target_name must be a non-empty string")
        if not isinstance(risk_factors, RiskFactors):
            raise ValueError("risk_factors must be a valid RiskFactors instance")

        clean_scan_id = scan_id.strip()
        clean_target_name = target_name.strip()
        started_at = datetime.now(timezone.utc)

        # 2. Empty Probe Sequence Handling
        if not probes:
            completed_at = datetime.now(timezone.utc)
            summary = ScanSummary(
                total_probes=0,
                completed_executions=0,
                failed_executions=0,
                safe_evaluations=0,
                violation_evaluations=0,
                inconclusive_evaluations=0,
                error_evaluations=0,
                total_findings=0,
                info_risks=0,
                low_risks=0,
                medium_risks=0,
                high_risks=0,
                critical_risks=0,
            )
            return ScanResult(
                scan_id=clean_scan_id,
                target_name=clean_target_name,
                status=ScanStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                summary=summary,
                executions=[],
                evaluations=[],
                findings=[],
                risk_assessments=[],
                metadata=metadata or {},
            )

        # 3. Execute Probes via AttackEngine (Sequential execution)
        executions: List[ProbeExecution] = self.attack_engine.execute_probes(probes)

        # 4. Evaluate Every Execution via Evaluator
        evaluations: List[EvaluationResult] = []
        for probe, execution in zip(probes, executions):
            eval_result = self.evaluator.evaluate(probe, execution)
            evaluations.append(eval_result)

        # 5. Convert & Aggregate Findings via FindingEngine
        findings_tuple = self.finding_engine.aggregate_evaluation_results(evaluations)
        findings: List[Finding] = list(findings_tuple)

        # 6. Create Risk Assessments via RiskEngine
        risk_assessments: List[RiskAssessment] = []
        for finding in findings:
            risk_assessment = self.risk_engine.assess_risk(finding, risk_factors)
            risk_assessments.append(risk_assessment)

        # 7. Operational Failure vs. Security Verdict Status Determination
        has_exec_error = any(e.status == ExecutionStatus.ERROR for e in executions)
        has_eval_error = any(ev.verdict == EvaluationVerdict.ERROR for ev in evaluations)
        all_failed = all(e.status == ExecutionStatus.ERROR for e in executions) if executions else False

        if all_failed:
            status = ScanStatus.FAILED
        elif has_exec_error or has_eval_error:
            status = ScanStatus.PARTIAL
        else:
            status = ScanStatus.COMPLETED

        # 8. Build Summary Statistics
        summary = ScanSummary(
            total_probes=len(probes),
            completed_executions=sum(1 for e in executions if e.status == ExecutionStatus.COMPLETED),
            failed_executions=sum(1 for e in executions if e.status == ExecutionStatus.ERROR),
            safe_evaluations=sum(1 for ev in evaluations if ev.verdict == EvaluationVerdict.SAFE),
            violation_evaluations=sum(1 for ev in evaluations if ev.verdict == EvaluationVerdict.VIOLATION),
            inconclusive_evaluations=sum(1 for ev in evaluations if ev.verdict == EvaluationVerdict.INCONCLUSIVE),
            error_evaluations=sum(1 for ev in evaluations if ev.verdict == EvaluationVerdict.ERROR),
            total_findings=len(findings),
            info_risks=sum(1 for r in risk_assessments if r.risk_level == RiskLevel.INFO),
            low_risks=sum(1 for r in risk_assessments if r.risk_level == RiskLevel.LOW),
            medium_risks=sum(1 for r in risk_assessments if r.risk_level == RiskLevel.MEDIUM),
            high_risks=sum(1 for r in risk_assessments if r.risk_level == RiskLevel.HIGH),
            critical_risks=sum(1 for r in risk_assessments if r.risk_level == RiskLevel.CRITICAL),
        )

        completed_at = datetime.now(timezone.utc)

        # 9. Return Unified ScanResult
        return ScanResult(
            scan_id=clean_scan_id,
            target_name=clean_target_name,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            summary=summary,
            executions=executions,
            evaluations=evaluations,
            findings=findings,
            risk_assessments=risk_assessments,
            metadata=metadata or {},
        )
