from __future__ import annotations

from pathlib import Path

from firellm.reporter import Reporter
from firellm.types import ScanResult


def test_reporter_writes_file_output(tmp_path: Path) -> None:
    reporter = Reporter()
    result = ScanResult(
        name="prompt_injection",
        success=True,
        severity="high",
        category="prompt_injection",
        details="test details",
        metadata={"provider": "openai"},
    )

    output_file = tmp_path / "report.txt"
    rendered = reporter.write([result], output_format="text", destination=str(output_file))

    assert rendered.startswith("firellm report")
    assert output_file.exists()
    assert "test details" in output_file.read_text(encoding="utf-8")
