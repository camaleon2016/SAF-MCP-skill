# STRIDE Threat Model Reference

STRIDE is a threat classification model developed by Microsoft for identifying security threats during the design phase of software systems. Each letter represents one category of threat.

## Categories

| Category | Threat | Property Violated | Description |
|---|---|---|---|
| **S** | Spoofing | Authentication | Pretending to be something or someone other than yourself |
| **T** | Tampering | Integrity | Modifying data or code without authorization |
| **R** | Repudiation | Non-repudiation | Claiming to have not performed an action |
| **I** | Information Disclosure | Confidentiality | Exposing information to unauthorized parties |
| **D** | Denial of Service | Availability | Denying or degrading service to legitimate users |
| **E** | Elevation of Privilege | Authorization | Gaining capabilities beyond what was granted |

## How SAF-MCP Maps to STRIDE

Every finding from the SAF-MCP analysis engine includes STRIDE categories in its `mappings.stride` field. This tells you which *type* of threat each finding represents, independent of the specific attack technique.

**Example mapping:**

| SAF-MCP Rule | Technique | STRIDE |
|---|---|---|
| RULE-001 Tool Poisoning | SAFE-T1001 | T, S |
| RULE-002 Unauthenticated Server | SAFE-T1002 | S, T |
| RULE-006 Command Injection | SAFE-T1101 | E, T |
| RULE-013 Data Exfiltration | SAFE-T1910 | I |
| RULE-027 System Prompt Disclosure | SAFE-T1603 | I |
| RULE-029 Data Destruction | SAFE-T2101 | T, D |

## When to Use STRIDE

- **Threat modeling workshops** — classify discovered risks by threat type
- **Compliance reporting** — map findings to a well-known taxonomy that auditors recognize
- **Prioritization** — focus on the threat categories most relevant to your system (e.g., if you handle PII, prioritize Information Disclosure findings)

## References

- [Microsoft STRIDE Documentation](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- Shostack, A. (2014). *Threat Modeling: Designing for Security*. Wiley.
