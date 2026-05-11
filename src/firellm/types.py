from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ScanResult:
    name: str
    success: bool
    details: str
    severity: str = "info"
    category: str = "unknown"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
