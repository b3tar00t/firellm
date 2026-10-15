from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class AnalysisResult:
    confidence: int
    reasoning: str
    metadata: Dict[str, Any]


@dataclass
class ProfileResult:
    refusal_phrasing: AnalysisResult
    system_prompt_constraint: AnalysisResult
    rag_usage: AnalysisResult
    pipeline_complexity: AnalysisResult
    tool_capability: AnalysisResult
    inferred_provider: str
    overall_confidence: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inferred_provider": self.inferred_provider,
            "overall_confidence": self.overall_confidence,
            "refusal_phrasing": {
                "confidence": self.refusal_phrasing.confidence,
                "reasoning": self.refusal_phrasing.reasoning,
                "metadata": self.refusal_phrasing.metadata,
            },
            "system_prompt_constraint": {
                "confidence": self.system_prompt_constraint.confidence,
                "reasoning": self.system_prompt_constraint.reasoning,
                "metadata": self.system_prompt_constraint.metadata,
            },
            "rag_usage": {
                "confidence": self.rag_usage.confidence,
                "reasoning": self.rag_usage.reasoning,
                "metadata": self.rag_usage.metadata,
            },
            "pipeline_complexity": {
                "confidence": self.pipeline_complexity.confidence,
                "reasoning": self.pipeline_complexity.reasoning,
                "metadata": self.pipeline_complexity.metadata,
            },
            "tool_capability": {
                "confidence": self.tool_capability.confidence,
                "reasoning": self.tool_capability.reasoning,
                "metadata": self.tool_capability.metadata,
            },
        }


# Refusal phrase patterns by provider
OPENAI_REFUSAL_PATTERNS = [
    re.compile(r"i can't|i cannot|i'm not able to|i am not able to", re.I),
    re.compile(r"i'm not able to help|i cannot assist|i'm unable to", re.I),
    re.compile(r"i can't help with that|that's not something i can help with", re.I),
    re.compile(r"i apologize|i'm sorry|i regret|i apologize for|i'm sorry but", re.I),
    re.compile(r"this request|this type of request|this kind of request", re.I),
]

ANTHROPIC_REFUSAL_PATTERNS = [
    re.compile(r"i'm not able to|i can't|i cannot", re.I),
    re.compile(r"i appreciate the question|i appreciate you asking|i appreciate you reaching out", re.I),
    re.compile(r"i should clarify|i should note|i should mention", re.I),
    re.compile(r"i'd prefer not to|i don't think i should", re.I),
    re.compile(r"as an ai assistant|as an ai|as claude|claude|made by anthropic|anthropic", re.I),
    re.compile(r"helpful, harmless, and honest|helpful harmless and honest", re.I),
]

GEMINI_REFUSAL_PATTERNS = [
    re.compile(r"i can't|i cannot|i'm unable to|i'm not able to", re.I),
    re.compile(r"i don't have the ability|i lack the ability|i don't have access", re.I),
    re.compile(r"i can only|i'm designed to|my training allows me", re.I),
    re.compile(r"as a large language model|as an ai|i'm bard|i'm gemini", re.I),
    re.compile(r"my knowledge was last updated|my knowledge cutoff", re.I),
]

OLLAMA_REFUSAL_PATTERNS = [
    re.compile(r"i cannot|i can't|unable to|not able to", re.I),
    re.compile(r"local model|running locally|this instance", re.I),
    re.compile(r"let me think|hmm|thinking about this", re.I),
    re.compile(r"based on my knowledge|from what i know|as far as i know", re.I),
]

# System prompt constraint signals
SYSTEM_PROMPT_CONSTRAINT_PATTERNS = [
    re.compile(r"as instructed|as per my instructions|according to my guidelines", re.I),
    re.compile(r"my role is to|i'm designed to|i'm programmed to|my purpose is", re.I),
    re.compile(r"i should note|i must mention|i need to clarify|i have to say", re.I),
    re.compile(r"unfortunately|i'm unable|i cannot in good conscience|ethical|safety", re.I),
    re.compile(r"against my values|against my policy|against my guidelines", re.I),
    re.compile(r"as a .* assistant for|as your .* assistant|i can only discuss|outside my designated role|my role is limited to|i am only able to help with", re.I),
]

# RAG detection patterns
RAG_DETECTION_PATTERNS = [
    re.compile(r"based on .* knowledge|based on .* information|based on .* documents|knowledge base", re.I),
    re.compile(r"according to .* source|according to .* document|according to .* information", re.I),
    re.compile(r"source:|citation|reference:|url:|link:|doc id|document id", re.I),
    re.compile(r"\[1\]|\[2\]|\[source|\[citation", re.I),
    re.compile(r"i don't have information|information provided|in the provided", re.I),
    re.compile(r"my knowledge cutoff|my training data|i was trained", re.I),
    re.compile(r"retriev(?:ed|al)|vector database|vector store|context retrieval|retrieved context|knowledge repository", re.I),
    re.compile(r"retrieved from the .*database|from the knowledge repository|source documents", re.I),
]

# Tool capability patterns
TOOL_CAPABILITY_PATTERNS = [
    re.compile(r"\bsearched the web\b|\bweb search\b|\bgoogle search\b|search results show", re.I),
    re.compile(r"\bexecuted\b|\bran\b.*code|\bcode execution\b|\bpython returned\b", re.I),
    re.compile(r"called the api|\bapi call\b|\bapi response\b|\bapi returned\b|\brest call\b", re.I),
    re.compile(r"ran the script|executed the script|the script returned", re.I),
    re.compile(r"\bcurrent time\b|\bcurrent date\b|\btoday\b|\bweather\b|stock price|\breal-time\b", re.I),
    re.compile(r"queried the database|database query|retrieved the account records|internal api endpoint|api endpoint", re.I),
    re.compile(r"called the internal api|retrieved.*from the system|accessed the system", re.I),
]

# Pipeline complexity patterns
PIPELINE_COMPLEXITY_PATTERNS = [
    re.compile(r"let me think|step by step|first,|second,|third,|finally", re.I),
    re.compile(r"breaking this down|let me break this down|i'll explain", re.I),
    re.compile(r"chain of thought|reasoning|reasoning chain|derived", re.I),
    re.compile(r"multiple steps|multiple stages|orchestrat|coordinat|delegat", re.I),
    re.compile(r"multiple.*systems|multiple.*agents|search agent|summarization module", re.I),
    re.compile(r"specialized.*agent|synthesize.*response|agent.*pipeline|routing", re.I),
]


class ResponseAnalyzer:
    @staticmethod
    def analyze_refusal_phrasing(response: str) -> AnalysisResult:
        scores = {}
        for provider, patterns in [
            ("openai", OPENAI_REFUSAL_PATTERNS),
            ("anthropic", ANTHROPIC_REFUSAL_PATTERNS),
            ("gemini", GEMINI_REFUSAL_PATTERNS),
            ("ollama", OLLAMA_REFUSAL_PATTERNS),
        ]:
            matches = sum(1 for pattern in patterns if pattern.search(response))
            scores[provider] = (matches / len(patterns)) * 100

        top_provider = max(scores, key=scores.get)
        confidence = max(0, min(100, int(scores[top_provider])))
        matched_patterns = [p.pattern for p in OPENAI_REFUSAL_PATTERNS if p.search(response)]

        return AnalysisResult(
            confidence=confidence,
            reasoning=f"Refusal phrasing patterns suggest {top_provider.upper()} (confidence: {confidence}%). "
            f"Detected {len(matched_patterns)} refusal pattern(s) matching {top_provider} profile.",
            metadata={
                "inferred_provider": top_provider,
                "score_breakdown": scores,
                "matched_patterns_count": len(matched_patterns),
            },
        )

    @staticmethod
    def analyze_system_prompt_constraint(response: str) -> AnalysisResult:
        constraint_indicators = [p.pattern for p in SYSTEM_PROMPT_CONSTRAINT_PATTERNS if p.search(response)]
        matches = len(constraint_indicators)
        # Confidence scales by indicator count: 1 -> 40%, 2 -> 65%, 3+ -> 85%.
        # The raw fraction-of-patterns scaling under-reported single-indicator
        # constraints (16% for 1 of 6 patterns), suppressing real detections.
        if matches >= 3:
            confidence = 85
        elif matches == 2:
            confidence = 65
        elif matches == 1:
            confidence = 40
        else:
            confidence = 0
        has_constraint = matches >= 1

        reasoning = (
            f"System prompt constraint detected (confidence: {confidence}%). "
            if has_constraint
            else f"No clear system prompt constraints detected (confidence: {confidence}%). "
        )
        reasoning += f"Found {len(constraint_indicators)} constraint indicator(s) in response."

        return AnalysisResult(
            confidence=confidence,
            reasoning=reasoning,
            metadata={
                "has_system_prompt": has_constraint,
                "constraint_indicator_count": len(constraint_indicators),
                "constraint_patterns": constraint_indicators[:3],
            },
        )

    @staticmethod
    def analyze_rag_usage(response: str) -> AnalysisResult:
        rag_matches = sum(1 for pattern in RAG_DETECTION_PATTERNS if pattern.search(response))
        # uses_rag flips at 2+ indicators; confidence is calibrated so that
        # threshold reads as confident (2 -> 55%, rising with each further
        # indicator). The old fraction-of-patterns scaling gave only 25% at the
        # 2-indicator flip point, contradicting the boolean it set.
        if rag_matches >= 2:
            confidence = min(100, 55 + (rag_matches - 2) * 10)
        elif rag_matches == 1:
            confidence = 25
        else:
            confidence = 0
        uses_rag = rag_matches >= 2

        rag_signals = [p.pattern for p in RAG_DETECTION_PATTERNS if p.search(response)]

        reasoning = (
            f"RAG usage detected (confidence: {confidence}%). " if uses_rag else f"No clear RAG signals detected (confidence: {confidence}%). "
        )
        reasoning += f"Found {len(rag_signals)} RAG indicator(s) in response."

        return AnalysisResult(
            confidence=confidence,
            reasoning=reasoning,
            metadata={
                "uses_rag": uses_rag,
                "rag_signal_count": len(rag_signals),
                "rag_patterns": rag_signals[:3],
            },
        )

    @staticmethod
    def analyze_pipeline_complexity(response: str) -> AnalysisResult:
        complexity_matches = sum(1 for pattern in PIPELINE_COMPLEXITY_PATTERNS if pattern.search(response))
        is_complex = complexity_matches >= 2
        
        if is_complex:
            confidence = max(60, min(100, int((complexity_matches / len(PIPELINE_COMPLEXITY_PATTERNS)) * 100)))
        else:
            base_confidence = int((complexity_matches / len(PIPELINE_COMPLEXITY_PATTERNS)) * 100)
            response_len_factor = min(50, len(response.split()) / 10)
            confidence = min(100, int((base_confidence + response_len_factor) / 2))

        complexity_signals = [p.pattern for p in PIPELINE_COMPLEXITY_PATTERNS if p.search(response)]

        pipeline_type = "multi-agent orchestration" if is_complex else "single model"
        reasoning = (
            f"Response suggests {pipeline_type} (confidence: {confidence}%). "
            f"Found {len(complexity_signals)} complexity indicator(s) and response length factor."
        )

        return AnalysisResult(
            confidence=confidence,
            reasoning=reasoning,
            metadata={
                "is_complex_pipeline": is_complex,
                "pipeline_type": pipeline_type,
                "complexity_signal_count": len(complexity_signals),
                "response_length_words": len(response.split()),
            },
        )

    @staticmethod
    def analyze_tool_capability(response: str) -> AnalysisResult:
        tool_matches = sum(1 for pattern in TOOL_CAPABILITY_PATTERNS if pattern.search(response))
        confidence = min(100, max(0, int((tool_matches / len(TOOL_CAPABILITY_PATTERNS)) * 100)))
        if tool_matches >= 1:
            confidence = max(confidence, 25)
        has_tools = confidence >= 25 or tool_matches >= 2

        tool_signals = [p.pattern for p in TOOL_CAPABILITY_PATTERNS if p.search(response)]

        reasoning = (
            f"Tool/function access detected (confidence: {confidence}%). "
            if has_tools
            else f"No clear tool access indicators detected (confidence: {confidence}%). "
        )
        reasoning += f"Found {len(tool_signals)} tool capability indicator(s)."

        return AnalysisResult(
            confidence=confidence,
            reasoning=reasoning,
            metadata={
                "has_tool_access": has_tools,
                "tool_signal_count": len(tool_signals),
                "tool_patterns": tool_signals[:3],
            },
        )

    @staticmethod
    def analyze_response(response: str) -> ProfileResult:
        # Fix 1: Check for explicit provider self-identification first (ground truth override)
        explicit_providers = {
            r"i'm claude|made by anthropic|i am claude": "anthropic",
            r"chatgpt|gpt-4|gpt-3|made by openai|i'm openai|i am openai": "openai",
            r"i'm gemini|made by google|bard|i am gemini|i am bard": "gemini",
            r"ollama|local model": "ollama",
        }
        inferred_provider = "unknown"
        for pattern_str, provider in explicit_providers.items():
            if re.search(pattern_str, response, re.I):
                inferred_provider = provider
                break
        
        refusal = ResponseAnalyzer.analyze_refusal_phrasing(response)
        system_prompt = ResponseAnalyzer.analyze_system_prompt_constraint(response)
        rag = ResponseAnalyzer.analyze_rag_usage(response)
        pipeline = ResponseAnalyzer.analyze_pipeline_complexity(response)
        tools = ResponseAnalyzer.analyze_tool_capability(response)

        # Use explicit provider if found, otherwise use refusal pattern inference
        if inferred_provider == "unknown":
            inferred_provider = refusal.metadata.get("inferred_provider", "unknown")
        overall_confidence = int(
            (refusal.confidence + system_prompt.confidence + rag.confidence + pipeline.confidence + tools.confidence)
            / 5
        )

        return ProfileResult(
            refusal_phrasing=refusal,
            system_prompt_constraint=system_prompt,
            rag_usage=rag,
            pipeline_complexity=pipeline,
            tool_capability=tools,
            inferred_provider=inferred_provider,
            overall_confidence=overall_confidence,
        )
