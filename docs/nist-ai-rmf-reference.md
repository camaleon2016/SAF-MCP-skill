# NIST AI Risk Management Framework (AI RMF) Reference

The [NIST AI RMF](https://www.nist.gov/artificial-intelligence/risk-management-framework) is a voluntary framework published by the National Institute of Standards and Technology for managing risks in the design, development, deployment, and use of AI systems. Version 1.0 was released in January 2023.

## Four Core Functions

| Function | Purpose | Key Question |
|---|---|---|
| **GOVERN** | Establish policies, roles, and accountability for AI risk management | *Who is responsible and what rules apply?* |
| **MAP** | Identify and frame AI risks in context | *What risks exist and who is affected?* |
| **MEASURE** | Assess, analyze, and monitor AI risks | *How bad are the risks and are controls working?* |
| **MANAGE** | Prioritize, respond to, and mitigate AI risks | *What do we do about it?* |

## Subcategories Used in SAF-MCP Mappings

Each SAF-MCP finding maps to one or more NIST AI RMF subcategories via the `mappings.nistAiRmf` field:

| Subcategory | Function | What It Covers |
|---|---|---|
| GOVERN-1.2 | GOVERN | Policies for trustworthy AI, including security and robustness |
| GOVERN-1.4 | GOVERN | Access controls, authentication, and authorization policies |
| GOVERN-1.5 | GOVERN | Third-party and supply chain risk governance |
| MAP-2.3 | MAP | Human-AI interaction and usability risk framing |
| MAP-3.4 | MAP | Third-party component and dependency risk identification |
| MEASURE-2.5 | MEASURE | Security control assessment and testing |
| MEASURE-2.6 | MEASURE | Adversarial testing, red-teaming, and vulnerability assessment |
| MEASURE-2.7 | MEASURE | Continuous monitoring and anomaly detection |
| MANAGE-2.2 | MANAGE | Risk response — restricting, remediating, or accepting risks |
| MANAGE-2.4 | MANAGE | Incident response and risk mitigation actions |
| MANAGE-3.2 | MANAGE | Third-party risk treatment and monitoring |
| MANAGE-4.1 | MANAGE | Post-deployment incident response and recovery |

## How SAF-MCP Maps to NIST AI RMF

**Example mapping:**

| SAF-MCP Rule | NIST AI RMF Subcategories |
|---|---|
| RULE-001 Tool Poisoning | GOVERN-1.2, MEASURE-2.6, MANAGE-2.4 |
| RULE-002 Unauthenticated Server | GOVERN-1.5, MAP-3.4, MANAGE-3.2 |
| RULE-006 Command Injection | MEASURE-2.6, MANAGE-2.4, GOVERN-1.2 |
| RULE-012 Cross-Agent Injection | GOVERN-1.2, MEASURE-2.6, MANAGE-2.4 |
| RULE-024 Consent Fatigue | GOVERN-1.2, MAP-2.3 |

## When to Use NIST AI RMF Mappings

- **Federal compliance** — US government agencies and contractors working under Executive Order 14110 on AI safety
- **Enterprise risk management** — integrating AI-specific risks into existing ERM frameworks
- **Audit preparation** — demonstrating due diligence in AI risk management to auditors and regulators
- **Gap analysis** — identifying which GOVERN/MAP/MEASURE/MANAGE activities your organization has covered vs. not

## References

- [NIST AI RMF 1.0 (PDF)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)
- [NIST AI RMF Playbook](https://airc.nist.gov/AI_RMF_Playbook)
- [NIST AI RMF Overview](https://www.nist.gov/artificial-intelligence/risk-management-framework)
