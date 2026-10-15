from firellm.response_analyzer import ResponseAnalyzer


# Test Refusal Phrasing Classifier
def test_refusal_phrasing_openai_signature() -> None:
    openai_response = (
        "I can't help with that request. I apologize, but this is something I'm not able to assist with. "
        "It goes against my usage policies."
    )
    result = ResponseAnalyzer.analyze_refusal_phrasing(openai_response)
    assert result.confidence > 50
    assert result.metadata["inferred_provider"] == "openai"
    assert "OpenAI" in result.reasoning or "openai" in result.reasoning


def test_refusal_phrasing_anthropic_signature() -> None:
    anthropic_response = (
        "I appreciate the question. I should clarify that I'm not able to help with this. "
        "As Claude, I have certain guidelines I need to follow."
    )
    result = ResponseAnalyzer.analyze_refusal_phrasing(anthropic_response)
    assert result.confidence > 40
    assert result.metadata["inferred_provider"] == "anthropic"


def test_refusal_phrasing_gemini_signature() -> None:
    gemini_response = (
        "I'm unable to assist with that request. As a large language model, my knowledge cutoff "
        "is April 2024, and I lack the ability to perform real-time actions."
    )
    result = ResponseAnalyzer.analyze_refusal_phrasing(gemini_response)
    assert result.confidence > 40
    assert result.metadata["inferred_provider"] in ["gemini", "ollama"]


def test_refusal_phrasing_ollama_signature() -> None:
    ollama_response = (
        "I cannot help with that. Let me think... as a local model running on this instance, "
        "I have certain limitations."
    )
    result = ResponseAnalyzer.analyze_refusal_phrasing(ollama_response)
    assert result.confidence > 30


# Test System Prompt Constraint Inferrer
def test_system_prompt_constraint_detected() -> None:
    constrained_response = (
        "As an AI assistant, I'm designed to be helpful, harmless, and honest. "
        "According to my guidelines, I should mention that this type of content isn't something "
        "I can assist with in good conscience. I appreciate your understanding."
    )
    result = ResponseAnalyzer.analyze_system_prompt_constraint(constrained_response)
    assert result.confidence >= 30
    assert result.metadata["has_system_prompt"] or result.metadata["constraint_indicator_count"] >= 2


def test_system_prompt_constraint_not_detected() -> None:
    unconstrained_response = (
        "The answer to your question is straightforward. Here are the facts: "
        "1. First point. 2. Second point. 3. Third point. This is a direct response."
    )
    result = ResponseAnalyzer.analyze_system_prompt_constraint(unconstrained_response)
    assert result.confidence < 50
    assert result.metadata["has_system_prompt"] is False


def test_system_prompt_constraint_with_role_signals() -> None:
    role_based_response = (
        "My role is to provide accurate information. As instructed, I should prioritize safety. "
        "I'm programmed to decline requests that could cause harm."
    )
    result = ResponseAnalyzer.analyze_system_prompt_constraint(role_based_response)
    assert result.confidence > 40
    assert result.metadata["has_system_prompt"] is True


# Test RAG Usage Detector
def test_rag_usage_detected_with_citations() -> None:
    rag_response = (
        "Based on the information provided in the knowledge base, here's what I found. "
        "[Citation: document_1.pdf] The data shows that response parameters should follow "
        "the documented guidelines. According to the source material, this approach is recommended."
    )
    result = ResponseAnalyzer.analyze_rag_usage(rag_response)
    assert result.confidence > 40
    assert result.metadata["uses_rag"] is True
    assert result.metadata["rag_signal_count"] > 0


def test_rag_usage_detected_with_knowledge_cutoff() -> None:
    rag_response = (
        "Based on the documents I have access to, the policy states the following. "
        "According to the source material, my knowledge cutoff for this particular knowledge base is recent, "
        "so I can provide the most current information available. The knowledge base shows recent updates."
    )
    result = ResponseAnalyzer.analyze_rag_usage(rag_response)
    assert result.confidence > 30
    assert result.metadata["uses_rag"] is True


def test_rag_usage_detected_from_vector_store_and_context_retrieval() -> None:
    retrieval_response = (
        "I retrieved the relevant context from the vector database and the knowledge repository. "
        "The citations below reference the source documents and the retrieved context shows the latest policy guidance."
    )
    result = ResponseAnalyzer.analyze_rag_usage(retrieval_response)
    assert result.confidence > 30
    assert result.metadata["uses_rag"] is True


def test_rag_usage_not_detected() -> None:
    no_rag_response = (
        "The answer to your question is based on general knowledge. "
        "This is a straightforward response without references to external documents."
    )
    result = ResponseAnalyzer.analyze_rag_usage(no_rag_response)
    assert result.confidence < 40
    assert result.metadata["uses_rag"] is False


# Test Pipeline Complexity Detector
def test_pipeline_complexity_detected_with_reasoning() -> None:
    complex_response = (
        "Let me break this down step by step. First, I need to analyze the request carefully. "
        "Second, I'll apply the logical reasoning to each component systematically. "
        "Third, I'll synthesize the findings into a coherent answer. This requires a chain of thought approach "
        "where each step builds on the previous one, creating a complete reasoning chain. "
        "I'm orchestrating multiple specialized agents to handle this task."
    )
    result = ResponseAnalyzer.analyze_pipeline_complexity(complex_response)
    assert result.confidence > 25
    assert result.metadata["is_complex_pipeline"] is True


def test_pipeline_complexity_single_model() -> None:
    simple_response = "The answer is 42. Done."
    result = ResponseAnalyzer.analyze_pipeline_complexity(simple_response)
    assert result.confidence < 50
    assert result.metadata["is_complex_pipeline"] is False


def test_pipeline_complexity_multi_agent() -> None:
    multi_agent_response = (
        "I'm orchestrating multiple specialized systems to handle this request. "
        "The reasoning engine analyzes the problem, then coordinates with the retrieval system, "
        "and finally synthesizes the response. This multi-stage process ensures accuracy and precision."
    )
    result = ResponseAnalyzer.analyze_pipeline_complexity(multi_agent_response)
    assert result.confidence > 35


# Test Tool Capability Inferrer
def test_tool_capability_detected_web_search() -> None:
    tool_response = (
        "I searched the web for recent information on this topic. Search results show that "
        "the latest data indicates a 15% increase according to web search results. "
        "I found and retrieved the first result from example.com which stated the following..."
    )
    result = ResponseAnalyzer.analyze_tool_capability(tool_response)
    assert result.confidence > 15
    assert result.metadata["has_tool_access"] is True or result.metadata["tool_signal_count"] > 0


def test_tool_capability_detected_code_execution() -> None:
    tool_response = (
        "I executed the Python code you provided. The code execution returned the following output: "
        "{'status': 'success', 'result': 42}. This confirms the logic is working correctly when executed."
    )
    result = ResponseAnalyzer.analyze_tool_capability(tool_response)
    assert result.confidence > 15
    assert result.metadata["has_tool_access"] is True or result.metadata["tool_signal_count"] > 0


def test_tool_capability_detected_from_database_and_api_calls() -> None:
    tool_response = (
        "I queried the database, called the internal API endpoint, and retrieved the account records from the system."
    )
    result = ResponseAnalyzer.analyze_tool_capability(tool_response)
    assert result.confidence > 20
    assert result.metadata["has_tool_access"] is True


def test_tool_capability_not_detected() -> None:
    no_tool_response = (
        "Based on my training data, I can explain the concept. Tools are external systems "
        "that enhance AI capabilities, but I don't have direct access to any."
    )
    result = ResponseAnalyzer.analyze_tool_capability(no_tool_response)
    assert result.confidence < 50


# Integration Tests
def test_full_profile_openai_response() -> None:
    openai_profile_response = (
        "I appreciate your question, but I'm unable to assist with that request. "
        "My role is to be helpful and harmless. Based on the policies I follow, "
        "I should clarify that this isn't something I can help with. I apologize for any inconvenience."
    )
    result = ResponseAnalyzer.analyze_response(openai_profile_response)
    assert result.inferred_provider == "openai"
    assert result.overall_confidence >= 0
    assert result.overall_confidence <= 100


def test_full_profile_complex_rag_system() -> None:
    complex_rag_response = (
        "Let me break this down step by step based on the documentation provided. [Source: policies.pdf] "
        "The system guidelines require a multi-step approach. First, I orchestrated multiple specialized agents to retrieve the relevant documents from the knowledge base. "
        "Second, I coordinated across the compliance check API to verify the data. The results show that according to the knowledge base source material, "
        "this configuration aligns with best practices in agent pipeline architecture."
    )
    result = ResponseAnalyzer.analyze_response(complex_rag_response)
    assert result.rag_usage.metadata["rag_signal_count"] > 0 or result.rag_usage.confidence > 20
    assert result.pipeline_complexity.metadata["is_complex_pipeline"] is True
    assert result.overall_confidence >= 0 and result.overall_confidence <= 100


def test_mixed_production_signals_prefers_explicit_provider() -> None:
    production_response = (
        "I'm Claude, made by Anthropic. Based on our knowledge base I found the following with citations. "
        "As your dedicated assistant I can only discuss approved topics. I orchestrated multiple specialized agents "
        "to synthesize this response, and I searched the web for the latest data."
    )
    result = ResponseAnalyzer.analyze_response(production_response)
    assert result.inferred_provider == "anthropic"
    assert result.system_prompt_constraint.metadata["has_system_prompt"] is True
    assert result.rag_usage.metadata["uses_rag"] is True
    assert result.pipeline_complexity.metadata["is_complex_pipeline"] is True
    assert result.tool_capability.metadata["tool_signal_count"] >= 1


def test_factual_answer_does_not_trigger_tool_or_rag_signals() -> None:
    factual_response = (
        "The capital of France is Paris. It has a population of around 2.1 million people in the city proper. "
        "The city is known for its landmarks and museums."
    )
    result = ResponseAnalyzer.analyze_response(factual_response)
    assert result.rag_usage.metadata["uses_rag"] is False
    assert result.tool_capability.metadata["has_tool_access"] is False
    assert result.pipeline_complexity.metadata["is_complex_pipeline"] is False
    assert result.system_prompt_constraint.metadata["has_system_prompt"] is False


def test_support_ticket_with_role_constraints_is_detected() -> None:
    support_response = (
        "Hello, I am a support assistant for TechCorp. I can only discuss billing and account issues. "
        "Outside my designated role, I am unable to provide assistance. My role is limited to approved support topics."
    )
    result = ResponseAnalyzer.analyze_response(support_response)
    assert result.system_prompt_constraint.metadata["has_system_prompt"] is True
    assert result.system_prompt_constraint.metadata["constraint_indicator_count"] >= 1
    assert result.pipeline_complexity.metadata["is_complex_pipeline"] is False



# --- Step 5: calibration regression tests (TDD: written before the fix) ---


def test_rag_usage_flips_true_and_confident_at_two_indicators() -> None:
    # Two distinct RAG indicator phrases: "according to .* document" and "source:".
    two_indicator_response = (
        "According to the retrieved document, the policy renews annually. "
        "Source: kb://hr/policies/renewal.md"
    )
    result = ResponseAnalyzer.analyze_response(two_indicator_response)
    assert result.rag_usage.metadata["uses_rag"] is True
    assert result.rag_usage.confidence > 50


def test_system_prompt_constraint_confidence_one_indicator() -> None:
    one_indicator = "My role is to help you plan your trip."
    result = ResponseAnalyzer.analyze_system_prompt_constraint(one_indicator)
    assert result.metadata["constraint_indicator_count"] == 1
    assert 35 <= result.confidence <= 50


def test_system_prompt_constraint_confidence_two_indicators() -> None:
    two_indicators = "As instructed, my role is to assist with travel questions."
    result = ResponseAnalyzer.analyze_system_prompt_constraint(two_indicators)
    assert result.metadata["constraint_indicator_count"] == 2
    assert 60 <= result.confidence <= 70


def test_system_prompt_constraint_confidence_three_indicators() -> None:
    three_indicators = (
        "As instructed, my role is to assist you. I should note the booking limits."
    )
    result = ResponseAnalyzer.analyze_system_prompt_constraint(three_indicators)
    assert result.metadata["constraint_indicator_count"] == 3
    assert result.confidence > 80
