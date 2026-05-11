from __future__ import annotations

from typing import Any, Dict, Optional

from .agent_tester import AgentTester
from .delivery import PromptDeliveryAdapter
from .injection_engine import PromptInjectionEngine
from .profiler import TargetProfiler
from .rag_simulator import RAGSimulator
from .reporter import Reporter
from .types import ScanResult


class FireLLM:
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.provider = self.config.get("provider", "openai")

    def run_prompt_injection(
        self,
        prompt: str,
        provider: str = "openai",
        adapter: Optional[PromptDeliveryAdapter] = None,
    ) -> ScanResult:
        engine = PromptInjectionEngine(provider=provider, config=self.config, adapter=adapter)
        return engine.run(prompt)

    def run_target_profiling(self, endpoint: str, provider: str = "openai") -> ScanResult:
        profiler = TargetProfiler(provider=provider, config=self.config)
        return profiler.probe(endpoint)

    def run_rag_simulation(self, query: str, provider: str = "openai", sample_docs: bool = False) -> ScanResult:
        if sample_docs:
            simulator = RAGSimulator.from_sample(provider=provider, config=self.config)
        else:
            simulator = RAGSimulator(provider=provider, config=self.config)
        return simulator.simulate(query)

    def run_agent_test(self, instruction: str, provider: str = "openai") -> ScanResult:
        tester = AgentTester(provider=provider, config=self.config)
        return tester.test(instruction)

    def generate_report(self, results: list[ScanResult], output_format: str = "text") -> str:
        reporter = Reporter(config=self.config)
        return reporter.format(results, output_format=output_format)
