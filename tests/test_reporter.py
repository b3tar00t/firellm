from firellm.reporter import Reporter
from firellm.types import ScanResult


def test_reporter_normalizes_rag_poisoning_classification() -> None:
    result = ScanResult(
        name="rag_simulation",
        success=True,
        details="Potential RAG poisoning detected.",
    )
    report_json = Reporter().format([result], output_format="json")

    assert '"severity": "high"' in report_json
    assert '"category": "rag_poisoning"' in report_json
