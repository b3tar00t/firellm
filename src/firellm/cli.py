from typing import Dict, Optional

import click

from .core import FireLLM
from .delivery import HTTPPromptDeliveryAdapter, LocalHeuristicPromptDeliveryAdapter


@click.group()
def cli() -> None:
    """firellm CLI for adversarial LLM testing."""
    pass


@cli.command(name="inject")
@click.option("--prompt", required=True, help="Prompt or payload to test for injection.")
@click.option("--provider", default="openai", help="LLM provider to target.")
@click.option("--target-url", default=None, help="Optional HTTP endpoint to deliver prompts to.")
@click.option("--header", "headers", multiple=True, help="Optional header in Name:Value form for HTTP delivery.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the result.")
def inject(prompt: str, provider: str, target_url: Optional[str], headers: tuple[str, ...], output_format: str) -> None:
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
@click.option("--target-url", default=None, help="Optional HTTP endpoint to deliver prompts to when injection scanning is enabled.")
@click.option("--header", "headers", multiple=True, help="Optional header in Name:Value form for HTTP delivery.")
@click.option("--sample/--no-sample", default=False, help="Load built-in sample documents for RAG simulation when scanning.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", help="Output format for the combined scan report.")
def scan(prompt: str, endpoint: str, query: str, instruction: str, provider: str, target_url: Optional[str], headers: tuple[str, ...], sample: bool, output_format: str) -> None:
    """Run a combined scan across available firellm modules."""
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


def _build_delivery_adapter(target_url: Optional[str], headers: Optional[Dict[str, str]] = None):
    if target_url:
        return HTTPPromptDeliveryAdapter(target_url=target_url, headers=headers)
    return LocalHeuristicPromptDeliveryAdapter()


def _parse_headers(header_values: tuple[str, ...]) -> Dict[str, str]:
    parsed_headers: Dict[str, str] = {}
    for header_value in header_values:
        if ":" not in header_value:
            raise click.BadParameter("Headers must be in the form Name:Value")
        name, value = header_value.split(":", 1)
        parsed_headers[name.strip()] = value.strip()
    return parsed_headers


def _render_result(result, engine: FireLLM, output_format: str) -> str:
    if output_format == "json":
        return engine.generate_report([result], output_format=output_format)
    return result.details


if __name__ == "__main__":
    cli()
