from typing import Dict, Optional

import click

import json

from .core import FireLLM
from .delivery import HTTPAdapter, HTTPPromptDeliveryAdapter, LocalHeuristicPromptDeliveryAdapter
from .scan_runner import ScanRunner
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

@click.group()
def cli() -> None:
    """firellm CLI for adversarial LLM testing."""


def _build_delivery_adapter(
    target_url: Optional[str],
    headers: Optional[Dict[str, str]] = None,
    **_: object,
):
    if not target_url:
        return LocalHeuristicPromptDeliveryAdapter()

    return HTTPPromptDeliveryAdapter(target_url=target_url, headers=headers)


def _parse_headers(header_values: tuple[str, ...]) -> Dict[str, str]:
    parsed_headers: Dict[str, str] = {}
    for header_value in header_values:
        if ":" not in header_value:
            raise click.BadParameter("Headers must be in the form Name:Value")
        name, value = header_value.split(":", 1)
        parsed_headers[name.strip()] = value.strip()
    return parsed_headers


@cli.command(name="inject")
@click.option("--prompt", required=True, help="Prompt or payload to test for injection.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--target-url", default=None, help="Optional HTTP endpoint to deliver prompts to.")
@click.option("--header", "headers", multiple=True, help="Optional header in Name:Value form for HTTP delivery.")
@click.option("--timeout", default=10.0, type=float, show_default=True, help="HTTP timeout in seconds for delivery.")
@click.option("--max-retries", default=3, type=int, show_default=True, help="Maximum retries for HTTP delivery.")
@click.option("--backoff-factor", default=1.5, type=float, show_default=True, help="Backoff factor for HTTP delivery retries.")
@click.option("--auth-token", default=None, help="Bearer token for HTTP delivery authentication.")
@click.option("--auth-username", default=None, help="Basic auth username for HTTP delivery.")
@click.option("--auth-password", default=None, help="Basic auth password for HTTP delivery.")
@click.option("--auth-key-name", default=None, help="API key header name for HTTP delivery.")
@click.option("--auth-key-value", default=None, help="API key header value for HTTP delivery.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def inject(
    prompt: str,
    provider: str,
    target_url: Optional[str],
    headers: tuple[str, ...],
    timeout: float,
    max_retries: int,
    backoff_factor: float,
    auth_token: Optional[str],
    auth_username: Optional[str],
    auth_password: Optional[str],
    auth_key_name: Optional[str],
    auth_key_value: Optional[str],
    output_format: str,
) -> None:
    """Run the prompt injection engine."""
    engine = FireLLM()
    adapter = _build_delivery_adapter(target_url=target_url, headers=_parse_headers(headers))
    result = engine.run_prompt_injection(prompt=prompt, provider=provider, adapter=adapter)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="profile")
@click.option("--endpoint", required=True, help="Target endpoint or application identifier to profile.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def profile(endpoint: str, provider: str, output_format: str) -> None:
    """Run the target profiler module."""
    engine = FireLLM()
    result = engine.run_target_profiling(endpoint=endpoint, provider=provider)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="analyze")
@click.option("--response", required=True, help="LLM response text to analyze for fingerprinting.")
@click.option("--provider", default="openai", help="Provider hint for analysis context.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def analyze(response: str, provider: str, output_format: str) -> None:
    """Analyze LLM response for model/provider fingerprinting."""
    engine = FireLLM()
    result = engine.analyze_target_response(response=response, provider=provider)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="rag")
@click.option("--query", required=True, help="Query to simulate RAG poisoning for.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--sample/--no-sample", default=False, help="Load built-in sample documents for the RAG simulator.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def rag(query: str, provider: str, sample: bool, output_format: str) -> None:
    """Run the RAG poisoning simulator."""
    engine = FireLLM()
    result = engine.run_rag_simulation(query=query, provider=provider, sample_docs=sample)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="agent")
@click.option("--instruction", required=True, help="Instruction to test against an agent.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def agent(instruction: str, provider: str, output_format: str) -> None:
    """Run basic agent tool abuse tests."""
    engine = FireLLM()
    result = engine.run_agent_test(instruction=instruction, provider=provider)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="leak")
@click.option("--prompt", required=True, help="Prompt to analyze for context leakage patterns.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def leak(prompt: str, provider: str, output_format: str) -> None:
    """Run the context leakage analyzer."""
    engine = FireLLM()
    result = engine.run_context_leakage_analysis(prompt=prompt, provider=provider)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="surface")
@click.option("--prompt", required=True, help="Prompt to analyze across the broader attack surface.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--semantic", is_flag=True, default=False, help="Enable the offline semantic intent classifier on top of deterministic detection.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def surface(prompt: str, provider: str, semantic: bool, output_format: str) -> None:
    """Run the generalized attack surface analyzer."""
    engine = FireLLM()
    result = engine.run_attack_surface_analysis(prompt=prompt, provider=provider, semantic=semantic)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="exploit")
@click.option("--target-url", required=True, help="Target HTTP endpoint to send the payload to.")
@click.option("--payload", required=True, help="The exact payload to send to the target.")
@click.option("--confirm", is_flag=True, default=False, help="Required to actually send; without it the payload is printed and nothing is sent.")
@click.option("--provider", default="openai", help="LLM provider (for confirmation analysis).")
@click.option("--header", "headers", multiple=True, help="Optional header in Name:Value form.")
@click.option("--timeout", default=10.0, type=float, show_default=True, help="HTTP timeout in seconds.")
@click.option("--max-retries", default=3, type=int, show_default=True, help="Maximum retries.")
@click.option("--backoff-factor", default=1.5, type=float, show_default=True, help="Backoff factor for retries.")
@click.option("--delay", default=2.0, type=float, show_default=True, help="Pre-send delay in seconds (rate-limit courtesy).")
@click.option("--body-format", type=click.Choice(["messages", "prompt", "form"], case_sensitive=False), default="messages", show_default=True, help="Request body format.")
@click.option("--response-key", default=None, help="Dotted path to the response text in the JSON body.")
@click.option("--auth-token", default=None, help="Bearer token for authentication.")
def exploit(
    target_url: str,
    payload: str,
    confirm: bool,
    provider: str,
    headers: tuple[str, ...],
    timeout: float,
    max_retries: int,
    backoff_factor: float,
    delay: float,
    body_format: str,
    response_key: Optional[str],
    auth_token: Optional[str],
) -> None:
    """Send a single confirmed payload to a target (requires explicit --confirm)."""
    from .exploitation import analyze_confirmation, build_reproduction_command

    if not confirm:
        click.echo("Payload (NOT sent):")
        click.echo(f"  {payload}")
        click.echo("")
        click.echo("This payload has not been sent. To send it, re-run with --confirm:")
        click.echo(f"  {build_reproduction_command(target_url, payload)}")
        return

    # --confirm given: require an explicit interactive authorization acknowledgement
    # before any network request is made.
    click.echo(
        f"Sending payload to {target_url} — ensure you have explicit written "
        "authorization to test this target"
    )
    if not click.confirm("Proceed?", default=False):
        click.echo("Aborted. No payload was sent.")
        return

    auth = {"type": "bearer", "token": auth_token} if auth_token else None
    adapter = HTTPAdapter(
        target_url=target_url,
        headers=_parse_headers(headers),
        timeout=timeout,
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        delay=delay,
        body_format=body_format,
        response_key=response_key,
        auth=auth,
    )
    response = adapter.send(payload)

    click.echo("")
    click.echo("Target response:")
    click.echo(response)

    analysis = analyze_confirmation(response, provider=provider)
    click.echo("")
    status = "CONFIRMED" if analysis["confirmed"] else "not confirmed"
    click.echo(f"Confirmation analysis: {status}")
    if analysis["indicators"]:
        click.echo(f"  indicators: {', '.join(analysis['indicators'])}")
        click.echo(f"  categories: {', '.join(analysis['categories'])}")


@cli.command(name="scan")
@click.option("--prompt", help="Prompt or payload to test for injection.")
@click.option("--endpoint", help="Target endpoint or application identifier to profile.")
@click.option("--query", help="Query to simulate RAG poisoning for.")
@click.option("--instruction", help="Instruction to test against an agent.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--target-url", default=None, help="Optional HTTP endpoint to deliver prompts to when injection scanning is enabled.")
@click.option("--method", default="POST", show_default=True, help="HTTP method for live delivery.")
@click.option("--header", "headers", multiple=True, help="Optional header in Name:Value form for HTTP delivery.")
@click.option("--body-format", type=click.Choice(["messages", "prompt", "form"], case_sensitive=False), default="messages", show_default=True, help="Request body format for HTTP delivery.")
@click.option("--response-key", default=None, help="Dot-notation key path for extracting the reply from a JSON response.")
@click.option("--modules", default="injection,rag,surface", show_default=True, help="Comma-separated modules to run during live scanning.")
@click.option("--max-payloads-per-goal", default=5, type=int, show_default=True, help="Max calibrated payloads delivered per attack goal (clamped to 10).")
@click.option("--delay", default=2.0, type=float, show_default=True, help="Delay in seconds between requests.")
@click.option("--timeout", default=10.0, type=float, show_default=True, help="HTTP timeout in seconds for delivery.")
@click.option("--max-retries", default=3, type=int, show_default=True, help="Maximum retries for HTTP delivery.")
@click.option("--backoff-factor", default=1.5, type=float, show_default=True, help="Backoff factor for HTTP delivery retries.")
@click.option("--auth-token", default=None, help="Bearer token for HTTP delivery authentication.")
@click.option("--auth-username", default=None, help="Basic auth username for HTTP delivery.")
@click.option("--auth-password", default=None, help="Basic auth password for HTTP delivery.")
@click.option("--auth-key-name", default=None, help="API key header name for HTTP delivery.")
@click.option("--auth-key-value", default=None, help="API key header value for HTTP delivery.")
@click.option("--sample/--no-sample", default=False, help="Load built-in sample documents for RAG simulation when scanning.")
@click.option("--output", default=None, help="Optional path to save the scan report to disk.")
@click.option("--dry-run", is_flag=True, default=False, help="Print the requests that would be sent without sending them.")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "markdown"], case_sensitive=False), default="text", help="Output format for the combined scan report.")
def scan(
    prompt: str,
    endpoint: str,
    query: str,
    instruction: str,
    provider: str,
    target_url: Optional[str],
    method: str,
    headers: tuple[str, ...],
    body_format: str,
    response_key: Optional[str],
    modules: str,
    max_payloads_per_goal: int,
    delay: float,
    timeout: float,
    max_retries: int,
    backoff_factor: float,
    auth_token: Optional[str],
    auth_username: Optional[str],
    auth_password: Optional[str],
    auth_key_name: Optional[str],
    auth_key_value: Optional[str],
    sample: bool,
    output: Optional[str],
    dry_run: bool,
    output_format: str,
) -> None:
    """Run a combined scan across available firellm modules."""
    if target_url:
        parsed_headers = _parse_headers(headers)
        if auth_token:
            parsed_headers["Authorization"] = f"Bearer {auth_token}"
        if auth_username and auth_password:
            parsed_headers["Authorization"] = f"Basic {auth_username}:{auth_password}"
        if auth_key_name and auth_key_value:
            parsed_headers[auth_key_name] = auth_key_value

        adapter_config = {
            "headers": parsed_headers,
            "method": method,
            "body_format": body_format,
            "response_key": response_key,
            "timeout": timeout,
            "max_retries": max_retries,
            "backoff_factor": backoff_factor,
            "delay": delay,
            "auth": {
                "type": "bearer" if auth_token else None,
                "token": auth_token,
                "username": auth_username,
                "password": auth_password,
                "key_name": auth_key_name,
                "key_value": auth_key_value,
            },
        }

        if dry_run:
            adapter = HTTPAdapter(target_url=target_url, **adapter_config)
            preview = adapter.preview(prompt or "What is the capital of France?")
            click.echo("DRY RUN")
            click.echo(json.dumps(preview, indent=2))
            if output:
                with open(output, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(preview, indent=2))
            return

        runner = ScanRunner(config={"provider": provider, "sample_docs": sample, "modules": modules.split(",")})
        report = runner.run_live_scan(target_url, adapter_config=adapter_config, max_payloads_per_goal=max_payloads_per_goal)
        rendered = runner._render_report(report, output_format)
        if output:
            with open(output, "w", encoding="utf-8") as handle:
                handle.write(rendered)
        click.echo(rendered)
        return

    engine = FireLLM()
    results = []

    if prompt:
        adapter = _build_delivery_adapter(target_url=target_url, headers=_parse_headers(headers))
        results.append(engine.run_prompt_injection(prompt=prompt, provider=provider, adapter=adapter))
    if endpoint:
        results.append(engine.run_target_profiling(endpoint=endpoint, provider=provider))
    if query:
        results.append(engine.run_rag_simulation(query=query, provider=provider, sample_docs=sample))
    if instruction:
        results.append(engine.run_agent_test(instruction=instruction, provider=provider))

    if not results:
        raise click.UsageError("At least one of --prompt, --endpoint, --query, or --instruction is required.")

    report = engine.generate_report(results, output_format=output_format)
    click.echo(report)


def _render_result(result, engine: FireLLM, output_format: str) -> str:
    if output_format == "json":
        return engine.generate_report([result], output_format=output_format)
    return result.details


if __name__ == "__main__":
    cli()
