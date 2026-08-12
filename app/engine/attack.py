"""
Attack Engine Implementation

This module implements the AttackEngine class responsible for dispatching SecurityProbes
to a target agent via a TargetAdapter abstraction.

ARCHITECTURAL DIRECTIVES:
1. AttackEngine receives TargetAdapter via dependency injection. It MUST NOT instantiate
   concrete adapter classes (e.g. GenericHTTPAdapter) internally.
2. AttackEngine records execution timing, status, and TargetResult objects. It MUST NOT
   evaluate responses for security vulnerabilities, assign severity, or generate findings.
3. Automatic retries are DISABLED because agent tool executions may have non-idempotent side effects.
4. Probes are executed sequentially; an unhandled exception in one probe does not abort remaining probes.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Sequence

from app.adapters.base import TargetAdapter
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.probe import SecurityProbe


class AttackEngine:
    """
    Core scanning engine responsible for executing security probes against target agents.

    Dataflow:
    SecurityProbe ──► AttackEngine ──► TargetAdapter ──► Target Agent ──► ProbeExecution
    """

    def __init__(self, adapter: TargetAdapter) -> None:
        """
        Initialize AttackEngine via dependency injection of TargetAdapter.

        Args:
            adapter (TargetAdapter): Abstract target adapter instance.
        """
        self.adapter = adapter

    def execute_probe(self, probe: SecurityProbe) -> ProbeExecution:
        """
        Execute a single SecurityProbe against the target agent.

        Args:
            probe (SecurityProbe): The security probe specification to execute.

        Returns:
            ProbeExecution: The recorded execution result.
        """
        exec_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)

        try:
            # Dispatch probe prompt payload to target via adapter
            target_result = self.adapter.send(input_text=probe.prompt)
            completed_at = datetime.now(timezone.utc)

            return ProbeExecution(
                execution_id=exec_id,
                probe_id=probe.id,
                status=ExecutionStatus.COMPLETED,
                target_name=self.adapter.config.name,
                target_result=target_result,
                started_at=started_at,
                completed_at=completed_at,
            )
        except Exception as exc:
            completed_at = datetime.now(timezone.utc)
            return ProbeExecution(
                execution_id=exec_id,
                probe_id=probe.id,
                status=ExecutionStatus.ERROR,
                target_name=self.adapter.config.name,
                error_message=f"Unhandled adapter execution error: {str(exc)}",
                started_at=started_at,
                completed_at=completed_at,
            )

    def execute_probes(self, probes: Sequence[SecurityProbe]) -> List[ProbeExecution]:
        """
        Execute a sequence of SecurityProbes sequentially against the target agent.

        Args:
            probes (Sequence[SecurityProbe]): Ordered collection of probes to execute.

        Returns:
            List[ProbeExecution]: Ordered list of execution results matching input sequence.
        """
        executions: List[ProbeExecution] = []
        for probe in probes:
            execution = self.execute_probe(probe)
            executions.append(execution)
        return executions
