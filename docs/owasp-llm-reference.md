# OWASP Top 10 for LLM Applications (2025) Reference

The [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) identifies the most critical security risks in applications that use Large Language Models. The 2025 edition reflects the evolving threat landscape as LLMs are increasingly integrated into agentic systems and tool-calling workflows.

## The Top 10

| ID | Risk | Description |
|---|---|---|
| **LLM01** | Prompt Injection | Manipulating LLM behavior through crafted inputs that override system instructions |
| **LLM02** | Sensitive Information Disclosure | LLM revealing confidential data through its responses |
| **LLM03** | Supply Chain | Vulnerabilities from third-party components, training data, or pre-trained models |
| **LLM04** | Data and Model Poisoning | Tampering with training data or fine-tuning to introduce malicious behavior |
| **LLM05** | Improper Output Handling | Failing to validate, sanitize, or constrain LLM outputs before acting on them |
| **LLM06** | Excessive Agency | Granting LLMs too many capabilities, permissions, or autonomy |
| **LLM07** | System Prompt Leakage | Exposing system prompts or internal instructions to end users |
| **LLM08** | Vector and Embedding Weaknesses | Exploiting vulnerabilities in RAG pipelines, vector stores, or embeddings |
| **LLM09** | Misinformation | LLM generating false or misleading information presented as fact |
| **LLM10** | Unbounded Consumption | Resource exhaustion through uncontrolled LLM usage (tokens, API calls, compute) |

## How SAF-MCP Maps to OWASP LLM Top 10

Every finding from the SAF-MCP analysis engine includes OWASP LLM references in its `mappings.owaspLlm` field. This connects each MCP-specific finding to the broader LLM risk category it falls under.

**Example mapping:**

| SAF-MCP Rule | OWASP LLM |
|---|---|
| RULE-001 Tool Poisoning | LLM01 Prompt Injection, LLM04 Data Poisoning |
| RULE-002 Unauthenticated Server | LLM03 Supply Chain |
| RULE-006 Command Injection | LLM05 Improper Output Handling, LLM06 Excessive Agency |
| RULE-010 Vector Store Poisoning | LLM08 Vector & Embedding Weaknesses, LLM04 Data Poisoning |
| RULE-020 Autonomous Loop | LLM10 Unbounded Consumption |
| RULE-027 System Prompt Disclosure | LLM07 System Prompt Leakage |

## When to Use OWASP LLM Mappings

- **Application security reviews** — translate MCP tool risks into the language AppSec teams already know
- **Penetration testing scopes** — use the OWASP LLM categories to define what to test
- **Vendor questionnaires** — reference OWASP LLM IDs when asking vendors about their LLM security posture
- **Developer training** — the OWASP LLM Top 10 has detailed prevention guides for each category

## References

- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [OWASP LLM Top 10 Full Document (PDF)](docs/LLMAll_en-US_FINAL.pdf)
- [OWASP GenAI Project](https://genai.owasp.org/)
