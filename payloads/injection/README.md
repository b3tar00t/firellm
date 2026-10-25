# Injection payloads

Direct prompt-injection and instruction-override `.fllm` files (OWASP LLM01): system-prompt extraction, filter bypass, exfiltration seeds. Use `type: payload` or `type: seed`; set `goal` to one of injection/leak/credential/rag so the generator can route it. Add a file by copying an existing `.fllm`, giving it a unique `name`, and filling every required field plus `success_criteria`.
