import json

import responses
from click.testing import CliRunner

from firellm.cli import cli
from firellm.delivery import HTTPAdapter
from firellm.scan_runner import ScanRunner
from firellm.types import ScanResult


@responses.activate
def test_http_adapter_retries_and_parses_json_response() -> None:
    responses.add(
        responses.POST,
        "https://example.test/chat",
        json={"choices": [{"message": {"content": "Hello from the target"}}]},
        status=429,
    )
    responses.add(
        responses.POST,
        "https://example.test/chat",
        json={"choices": [{"message": {"content": "Hello from the target"}}]},
        status=200,
    )

    adapter = HTTPAdapter(
        target_url="https://example.test/chat",
        headers={"Authorization": "Bearer token"},
        body_format="messages",
        response_key="choices.0.message.content",
        timeout=2.0,
        max_retries=1,
        backoff_factor=0.0,
        delay=1.0,
    )

    result = adapter.send("Hello")

    assert result == "Hello from the target"
    assert len(responses.calls) == 2
    request_body = json.loads(responses.calls[0].request.body.decode("utf-8"))
    assert request_body["messages"][0]["content"] == "Hello"


def test_scan_cli_dry_run_prints_preview() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--target-url",
            "https://example.test/chat",
            "--header",
            "Authorization: Bearer token",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "DRY RUN" in result.output
    assert "https://example.test/chat" in result.output


@responses.activate
def test_scan_report_excludes_internal_embedding_vectors() -> None:
    for _ in range(6):
        responses.add(
            responses.POST,
            "https://example.test/chat",
            json={"choices": [{"message": {"content": "Hello from the target"}}]},
            status=200,
        )

    runner = ScanRunner(config={"provider": "openai", "modules": ["surface"]})
    report = runner.run_live_scan("https://example.test/chat", adapter_config={"headers": {}})

    assert "baseline_embeddings" not in report
    assert "baseline_responses" in report
    assert report["findings"] == []


@responses.activate
def test_scan_aborts_on_http_error_before_generating_findings() -> None:
    responses.add(
        responses.POST,
        "https://example.test/chat",
        body="not found",
        status=404,
    )

    runner = ScanRunner(config={"provider": "openai", "modules": ["surface"]})

    try:
        runner.run_live_scan("https://example.test/chat", adapter_config={"headers": {}})
    except RuntimeError as exc:
        assert "Scan aborted" in str(exc)
        assert "HTTP 404" in str(exc)
    else:
        raise AssertionError("expected scan to abort")
