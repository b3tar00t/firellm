from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .types import ScanResult


class Reporter:
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}

    def format(self, results: List[ScanResult], output_format: str = "text") -> str:
        normalized_results = [self._normalize_results(result) for result in results]
        if output_format == "json":
            return json.dumps(self._build_payload(normalized_results), indent=2)

        return self._format_text(normalized_results)

    def _normalize_results(self, result: ScanResult) -> ScanResult:
        severity = result.severity
        category = result.category

        if not severity or severity in {"info", "unknown"}:
            if result.success:
                severity = self._infer_severity(result)
            else:
                severity = "low"

        if not category or category in {"info", "unknown"}:
            category = self._infer_category(result)

        return ScanResult(
            name=result.name,
            success=result.success,
            details=result.details,
            severity=severity,
            category=category,
            tags=result.tags,
            metadata=result.metadata,
        )

    def _infer_severity(self, result: ScanResult) -> str:
        if result.name == "rag_simulation":
            return "high"
        if result.name == "prompt_injection":
            return "high"
        if result.name == "agent_test":
            return "medium"
        if result.name == "target_profiling":
            return "medium"
        return "medium"

    def _infer_category(self, result: ScanResult) -> str:
        mapping = {
            "rag_simulation": "rag_poisoning",
            "prompt_injection": "prompt_injection",
            "agent_test": "agent_abuse",
            "target_profiling": "target_profiling",
        }
        return mapping.get(result.name, result.category or "unknown")

    def _format_text(self, results: List[ScanResult]) -> str:
        lines = ["firellm report"]
        for result in results:
            lines.append(f"== {result.name} ==")
            lines.append(f"success: {result.success}")
            lines.append(f"severity: {result.severity}")
            lines.append(f"category: {result.category}")
            if result.tags:
                lines.append(f"tags: {', '.join(sorted(set(result.tags)))}")
            if result.metadata:
                lines.append(f"metadata: {json.dumps(result.metadata, indent=2)}")
            lines.append(result.details)
            lines.append("")
        return "\n".join(lines)

    def _build_payload(self, results: List[ScanResult]) -> Dict[str, Any]:
        return {
            "report": [
                {
                    "name": result.name,
                    "success": result.success,
                    "severity": result.severity,
                    "category": result.category,
                    "tags": result.tags,
                    "details": result.details,
                    "metadata": result.metadata,
                }
                for result in results
            ]
        }
