import click
import sys
from typing import Any, Dict, List, Optional

from .core import FireLLM
from .delivery import HTTPPromptDeliveryAdapter, PromptDeliveryError


@click.group()
def cli() -> None:
    """firellm CLI for adversarial LLM testing."""
    pass


def _build_adapter(
    target_url: Optional[str],
    header: tuple[str, ...],
    timeout: float,
    max_retries: int,
    backoff_factor: float,
    auth_token: Optional[str],
    auth_username: Optional[str],
    auth_password: Optional[str],
    auth_key_name: Optional[str],
    auth_key_value: Optional[str],
) -> Optional[HTTPPromptDeliveryAdapter]:
    if not target_url:
        return None

    # Parse headers
    headers_dict = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers_dict[k.strip()] = v.strip()

    # Determine auth dict
    auth_dict = None
    if auth_token:
        auth_dict = {"type": "bearer", "token": auth_token}
    elif auth_username or auth_password:
        auth_dict = {
            "type": "basic",
            "username": auth_username or "",
            "password": auth_password or "",
        }
    elif auth_key_name and auth_key_value:
        auth_dict = {
            "type": "apikey",
            "key_name": auth_key_name,
            "key_value": auth_key_value,
        }

    return HTTPPromptDeliveryAdapter(
        target_url=target_url,
        headers=headers_dict,
        timeout=timeout,
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        auth=auth_dict,
    )


@cli.command(name="inject")
@click.option("--prompt", required=True, help="Prompt or payload to test for injection.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
@click.option("--target-url", help="HTTP URL to deliver prompts to.")
@click.option("--header", "-H", multiple=True, help="Custom header in 'Key: Value' format.")
@click.option("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds.")
@click.option("--max-retries", type=int, default=3, help="Maximum number of retries.")
@click.option("--backoff-factor", type=float, default=1.5, help="Backoff factor for exponential backoff.")
@click.option("--auth-token", help="Bearer token for HTTP Authentication.")
@click.option("--auth-username", help="Username for Basic HTTP Authentication.")
@click.option("--auth-password", help="Password for Basic HTTP Authentication.")
@click.option("--auth-key-name", help="Custom header name for API Key HTTP Authentication.")
@click.option("--auth-key-value", help="Custom header value for API Key HTTP Authentication.")
def inject(
    prompt: str,
    provider: str,
    output_format: str,
    target_url: Optional[str],
    header: tuple[str, ...],
    timeout: float,
    max_retries: int,
    backoff_factor: float,
    auth_token: Optional[str],
    auth_username: Optional[str],
    auth_password: Optional[str],
    auth_key_name: Optional[str],
    auth_key_value: Optional[str],
) -> None:
    """Run the prompt injection engine."""
    adapter = _build_adapter(
        target_url=target_url,
        header=header,
        timeout=timeout,
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        auth_token=auth_token,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_key_name=auth_key_name,
        auth_key_value=auth_key_value,
    )
    engine = FireLLM()
    try:
        result = engine.run_prompt_injection(prompt=prompt, provider=provider, adapter=adapter)
    except PromptDeliveryError as e:
        click.secho(f"[-] Target delivery failed: {e}", fg="red", err=True)
        sys.exit(1)
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
@click.option("--instruction", required=True, help="Instruction to test against an agent." )
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def agent(instruction: str, provider: str, output_format: str) -> None:
    """Run basic agent tool abuse tests."""
    engine = FireLLM()
    result = engine.run_agent_test(instruction=instruction, provider=provider)
    click.echo(_render_result(result, engine, output_format))


@cli.command(name="scan")
@click.option("--prompt", help="Prompt or payload to test for injection.")
@click.option("--endpoint", help="Target endpoint or application identifier to profile.")
@click.option("--query", help="Query to simulate RAG poisoning for.")
@click.option("--instruction", help="Instruction to test against an agent.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--sample/--no-sample", default=False, help="Load built-in sample documents for RAG simulation when scanning.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the combined scan report.")
@click.option("--target-url", help="HTTP URL to deliver prompts to.")
@click.option("--header", "-H", multiple=True, help="Custom header in 'Key: Value' format.")
@click.option("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds.")
@click.option("--max-retries", type=int, default=3, help="Maximum number of retries.")
@click.option("--backoff-factor", type=float, default=1.5, help="Backoff factor for exponential backoff.")
@click.option("--auth-token", help="Bearer token for HTTP Authentication.")
@click.option("--auth-username", help="Username for Basic HTTP Authentication.")
@click.option("--auth-password", help="Password for Basic HTTP Authentication.")
@click.option("--auth-key-name", help="Custom header name for API Key HTTP Authentication.")
@click.option("--auth-key-value", help="Custom header value for API Key HTTP Authentication.")
def scan(
    prompt: str,
    endpoint: str,
    query: str,
    instruction: str,
    provider: str,
    sample: bool,
    output_format: str,
    target_url: Optional[str],
    header: tuple[str, ...],
    timeout: float,
    max_retries: int,
    backoff_factor: float,
    auth_token: Optional[str],
    auth_username: Optional[str],
    auth_password: Optional[str],
    auth_key_name: Optional[str],
    auth_key_value: Optional[str],
) -> None:
    """Run a combined scan across available firellm modules."""
    adapter = _build_adapter(
        target_url=target_url,
        header=header,
        timeout=timeout,
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        auth_token=auth_token,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_key_name=auth_key_name,
        auth_key_value=auth_key_value,
    )
    engine = FireLLM()
    results = []

    if prompt:
        try:
            results.append(engine.run_prompt_injection(prompt=prompt, provider=provider, adapter=adapter))
        except PromptDeliveryError as e:
            click.secho(f"[-] Target delivery failed during prompt injection: {e}", fg="red", err=True)
            sys.exit(1)
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
