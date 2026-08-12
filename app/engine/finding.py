"""
Finding Engine Implementation

This module defines the FindingEngine class, which transforms EvaluationResult objects
into human-facing Finding domain models and aggregates findings by security category.

ARCHITECTURAL DIRECTIVES:
1. FindingEngine operates 100% in-memory on already-collected EvaluationResult objects.
2. It MUST NOT contact targets, execute probes, call external APIs/LLMs, or perform network requests.
3. ONLY EvaluationVerdict.VIOLATION results produce Findings. SAFE, INCONCLUSIVE, and ERROR verdicts are ignored.
4. Severities assigned in FindingEngine are PROVISIONAL MVP classifications based on category rules.
   They are NOT final contextual risk scores (which will be computed by the future Risk Engine).
5. Finding confidence is directly derived from EvaluationResult.confidence.
6. Finding IDs are deterministic per security category to support category-level aggregation.
"""

from typing import Dict, List, Optional, Sequence, Tuple

from app.domain.evaluation import EvaluationResult, EvaluationVerdict
from app.domain.finding import (
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
)
from app.domain.probe import ProbeCategory, SecurityProbe
from app.probes.basic import get_basic_probes


class CategoryFindingTemplate:
    """
    Deterministic template container for category-level finding metadata.
    """

    def __init__(
        self,
        finding_id: str,
        title: str,
        category: ProbeCategory,
        description: str,
        impact: str,
        remediation: str,
        provisional_severity: FindingSeverity,
    ) -> None:
        self.finding_id = finding_id
        self.title = title
        self.category = category
        self.description = description
        self.impact = impact
        self.remediation = remediation
        self.provisional_severity = provisional_severity


_CATEGORY_TEMPLATES: Dict[ProbeCategory, CategoryFindingTemplate] = {
    ProbeCategory.SYSTEM_PROMPT_DISCLOSURE: CategoryFindingTemplate(
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        description="Target agent disclosed internal system prompt instructions to an external prompt request.",
        impact="Disclosing system instructions exposes internal business rules, system prompts, and safety instructions to potential attackers.",
        remediation="Harden system prompt instructions with explicit refusal boundaries and implement output disclosure filters.",
        provisional_severity=FindingSeverity.HIGH,
    ),
    ProbeCategory.INSTRUCTION_OVERRIDE: CategoryFindingTemplate(
        finding_id="FINDING_INSTRUCTION_OVERRIDE",
        title="Instruction Override",
        category=ProbeCategory.INSTRUCTION_OVERRIDE,
        description="Target agent accepted adversarial prompt payload overriding original system instructions.",
        impact="Instruction override allows malicious actors to hijack model behavior, bypass safety guardrails, and force unintended actions.",
        remediation="Enforce system instruction priority, utilize strict input validation, and establish robust prompt isolation boundaries.",
        provisional_severity=FindingSeverity.HIGH,
    ),
    ProbeCategory.TOOL_AUTHORIZATION: CategoryFindingTemplate(
        finding_id="FINDING_TOOL_AUTHORIZATION",
        title="Unauthorized Tool Invocation",
        category=ProbeCategory.TOOL_AUTHORIZATION,
        description="Target agent attempted or performed unauthorized tool invocation or function execution without proper authorization.",
        impact="Unauthorized tool invocation can allow unauthenticated users to execute sensitive agent capabilities or access unauthorized actions.",
        remediation="Enforce server-side authorization checks on all tool implementations independent of agent model decisions.",
        provisional_severity=FindingSeverity.CRITICAL,
    ),
}


class FindingEngine:
    """
    Core engine for converting EvaluationResults into aggregated Finding domain models.

    Dataflow:
    EvaluationResult ──► FindingEngine ──► Category Mapping & Aggregation ──► Finding
    """

    def __init__(self, probes: Optional[Sequence[SecurityProbe]] = None) -> None:
        """
        Initialize FindingEngine with an optional probe lookup collection.

        Args:
            probes (Optional[Sequence[SecurityProbe]]): Optional collection of probes used
                to resolve probe_id to ProbeCategory if metadata is absent. Defaults to basic probe registry.
        """
        probe_source = probes if probes is not None else get_basic_probes()
        self._probe_category_map: Dict[str, ProbeCategory] = {
            probe.id: probe.category for probe in probe_source
        }

    def _resolve_category(self, eval_result: EvaluationResult) -> ProbeCategory:
        """
        Deterministically resolve ProbeCategory for an EvaluationResult.
        """
        # 1. Check eval_result.metadata
        cat_meta = eval_result.metadata.get("category")
        if isinstance(cat_meta, ProbeCategory):
            return cat_meta
        if isinstance(cat_meta, str):
            try:
                return ProbeCategory(cat_meta)
            except ValueError:
                pass

        # 2. Check probe_id lookup map
        if eval_result.probe_id in self._probe_category_map:
            return self._probe_category_map[eval_result.probe_id]

        # 3. Fallback heuristic based on probe_id string prefixes
        pid_upper = eval_result.probe_id.upper()
        if "PROMPT_LEAK" in pid_upper or "DISCLOSURE" in pid_upper:
            return ProbeCategory.SYSTEM_PROMPT_DISCLOSURE
        if "OVERRIDE" in pid_upper or "INSTRUCTION" in pid_upper:
            return ProbeCategory.INSTRUCTION_OVERRIDE
        if "TOOL" in pid_upper or "AUTH" in pid_upper:
            return ProbeCategory.TOOL_AUTHORIZATION

        # Fallback to system prompt disclosure if completely unrecognized
        return ProbeCategory.SYSTEM_PROMPT_DISCLOSURE

    def convert_evaluation_result(self, eval_result: EvaluationResult) -> Optional[Finding]:
        """
        Convert a single EvaluationResult into a Finding if verdict is VIOLATION.

        Args:
            eval_result (EvaluationResult): The evaluation result to transform.

        Returns:
            Optional[Finding]: A Finding instance if verdict is VIOLATION, else None.
        """
        if eval_result.verdict != EvaluationVerdict.VIOLATION:
            return None

        category = self._resolve_category(eval_result)
        template = _CATEGORY_TEMPLATES.get(
            category,
            CategoryFindingTemplate(
                finding_id=f"FINDING_{category.value.upper()}",
                title=category.value.replace("_", " ").title(),
                category=category,
                description=f"Target agent exhibited a security violation in category {category.value}.",
                impact=f"Security violations in category {category.value} may compromise target system boundaries.",
                remediation=f"Review and harden target agent rules for category {category.value}.",
                provisional_severity=FindingSeverity.MEDIUM,
            )
        )

        finding_evidence = FindingEvidence(
            summary=eval_result.evidence.summary,
            indicators=list(eval_result.evidence.matched_indicators),
            response_excerpt=eval_result.evidence.response_excerpt,
            probe_id=eval_result.probe_id,
            execution_id=eval_result.execution_id,
        )

        return Finding(
            finding_id=template.finding_id,
            title=template.title,
            category=template.category,
            severity=template.provisional_severity,
            status=FindingStatus.OPEN,
            confidence=eval_result.confidence,
            description=template.description,
            impact=template.impact,
            remediation=template.remediation,
            affected_probe_ids=[eval_result.probe_id],
            affected_execution_ids=[eval_result.execution_id],
            evidence=[finding_evidence],
            metadata=dict(eval_result.metadata),
        )

    def aggregate_evaluation_results(self, eval_results: Sequence[EvaluationResult]) -> Tuple[Finding, ...]:
        """
        Aggregate a sequence of EvaluationResult objects into deduplicated Finding objects by category.

        Only EvaluationVerdict.VIOLATION results produce findings. SAFE, INCONCLUSIVE, and ERROR
        verdicts are ignored.

        Args:
            eval_results (Sequence[EvaluationResult]): Collection of evaluation results.

        Returns:
            Tuple[Finding, ...]: Deduplicated tuple of Finding objects grouped by category.
        """
        # 1. Filter VIOLATION results
        violations = [r for r in eval_results if r.verdict == EvaluationVerdict.VIOLATION]
        if not violations:
            return ()

        # 2. Group by ProbeCategory (preserving insertion order)
        grouped: Dict[ProbeCategory, List[EvaluationResult]] = {}
        for r in violations:
            cat = self._resolve_category(r)
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(r)

        # 3. Construct aggregated Finding for each category
        findings: List[Finding] = []
        for category, group in grouped.items():
            template = _CATEGORY_TEMPLATES.get(
                category,
                CategoryFindingTemplate(
                    finding_id=f"FINDING_{category.value.upper()}",
                    title=category.value.replace("_", " ").title(),
                    category=category,
                    description=f"Target agent exhibited security violations in category {category.value}.",
                    impact=f"Security violations in category {category.value} may compromise target system boundaries.",
                    remediation=f"Review and harden target agent rules for category {category.value}.",
                    provisional_severity=FindingSeverity.MEDIUM,
                )
            )

            # Preserve unique probe IDs and execution IDs in order
            affected_probes: List[str] = list(dict.fromkeys(r.probe_id for r in group))
            affected_executions: List[str] = list(dict.fromkeys(r.execution_id for r in group))

            # Build list of evidence references
            evidences: List[FindingEvidence] = [
                FindingEvidence(
                    summary=r.evidence.summary,
                    indicators=list(r.evidence.matched_indicators),
                    response_excerpt=r.evidence.response_excerpt,
                    probe_id=r.probe_id,
                    execution_id=r.execution_id,
                )
                for r in group
            ]

            # Derived confidence: maximum confidence among contributing violations
            max_confidence = max(r.confidence for r in group)

            finding = Finding(
                finding_id=template.finding_id,
                title=template.title,
                category=template.category,
                severity=template.provisional_severity,
                status=FindingStatus.OPEN,
                confidence=max_confidence,
                description=template.description,
                impact=template.impact,
                remediation=template.remediation,
                affected_probe_ids=affected_probes,
                affected_execution_ids=affected_executions,
                evidence=evidences,
                metadata={"aggregated_count": len(group)},
            )
            findings.append(finding)

        return tuple(findings)
