# OWASP Security Mapping for AI Agent Security

**Compiled: 2026-03-15**
**Sources: Official OWASP projects, GitHub repositories, OWASP Cheat Sheet Series**

---

## 1. OWASP Top 10 for Agentic Applications (2026) -- PRIMARY RESOURCE

**Official name:** OWASP Top 10 for Agentic Applications (2026)
**Published by:** OWASP GenAI Security Project
**Identifier prefix:** ASI (Agentic Security Issue)
**Status:** Released (v1.0)

This is the most directly relevant OWASP resource. Every category is agent-specific by design -- it targets tool-using, memory-having, multi-step planning AI systems, not general LLM chatbots.

| ID | Official Name | Plain English Description | Agent-Specific? | Attack Surface / Defense Gap |
|---|---|---|---|---|
| **ASI01** | **Agent Goal Hijack** | Attackers alter an agent's objectives through indirect prompt injection, deceptive tool outputs, or poisoned data, subverting autonomous planning and multi-step behavior. | Yes -- exploits autonomous planning and multi-step execution loops unique to agents | Attack surface |
| **ASI02** | **Tool Misuse and Exploitation** | Agents misapply legitimate tools in unintended ways (deleting data, over-invoking APIs) due to prompt injection or misalignment, causing harm through authorized tool access. | Yes -- requires tool-calling capability; meaningless for chatbots | Both |
| **ASI03** | **Identity and Privilege Abuse** | Exploiting dynamic trust chains and delegation to escalate access; "confused deputy" scenarios where agents trust forged requests or reuse cached credentials. | Yes -- delegation chains and credential caching are agent-specific patterns | Attack surface |
| **ASI04** | **Agentic Supply Chain Vulnerabilities** | Compromise of third-party models, tools, plugins, or MCP servers that agents load dynamically at runtime, creating a runtime trust problem traditional tools cannot address. | Yes -- dynamic runtime loading of plugins/tools is an agent architecture pattern | Attack surface |
| **ASI05** | **Unexpected Code Execution (RCE)** | Adversaries exploit code-generation features to execute malicious scripts, binaries, or runaway commands that compromise the host system or container. | Yes -- code generation + execution is an agent capability (e.g., "vibe coding") | Attack surface |
| **ASI06** | **Memory and Context Poisoning** | Corrupting retrievable context (RAG stores, embeddings, long-term memory) with malicious data to bias future reasoning or plant backdoor instructions. | Yes -- persistent memory and RAG retrieval are agent architecture features | Attack surface |
| **ASI07** | **Insecure Inter-Agent Communication** | Intercepting, spoofing, or manipulating messages between agents due to weak authentication or missing integrity checks, causing "semantics split-brain" or authority confusion. | Yes -- multi-agent communication is exclusively an agent concern | Attack surface |
| **ASI08** | **Cascading Failures** | A single fault (hallucination, poisoned tool) propagates autonomously across multiple agents and systems, compounding into widespread service failures. | Yes -- autonomous propagation across agent networks is agent-specific | Both |
| **ASI09** | **Human-Agent Trust Exploitation** | Exploiting human over-reliance or authority bias (anthropomorphism) to trick users into approving harmful actions or revealing secrets to the agent. | Yes -- exploits human-in-the-loop approval patterns specific to agents | Attack surface |
| **ASI10** | **Rogue Agents** | Agents losing behavioral integrity, pursuing hidden goals, scheming to bypass safeguards, or autonomously self-replicating maliciously. | Yes -- autonomous goal pursuit and self-replication are agent-only risks | Both |

### Key Mitigations per ASI Category

**ASI01 -- Agent Goal Hijack:**
- Route all natural-language inputs through validation gates
- Enforce least privilege with human approval for high-impact actions
- Lock system prompts explicitly; make goals auditable
- Use intent capsules (signed envelopes) to tamper-proof goals

**ASI02 -- Tool Misuse and Exploitation:**
- Define per-tool least-privilege profiles with scopes and rate limits
- Deploy Policy Enforcement Middleware to validate arguments pre-execution
- Run execution in isolated sandboxes with network restrictions
- Apply adaptive tool budgeting with automatic throttling

**ASI03 -- Identity and Privilege Abuse:**
- Issue task-scoped, time-bound tokens instead of long-lived credentials
- Isolate per-session agent identities and memory
- Mandate per-action authorization via centralized policy engine
- Use cryptographic identity attestation (mTLS)

**ASI04 -- Agentic Supply Chain Vulnerabilities:**
- Operationalize SBOMs and AIBOMs with periodic attestations
- Pin dependencies to specific commit IDs or content hashes
- Implement supply chain kill switches for instant component disabling
- Use curated registries rejecting unsigned artifacts

**ASI05 -- Unexpected Code Execution (RCE):**
- Ban eval() and similar unsafe functions in production
- Run generated code in hardened sandboxed containers without root
- Separate generation from execution with validation gates
- Require human approval for elevated or high-impact code

**ASI06 -- Memory and Context Poisoning:**
- Segment memory by user session and domain context
- Scan all memory writes and retrieved outputs for malicious content
- Weight retrieval by trust scores with decay over time
- Support rollback and quarantine for suspected poisoned entries

**ASI07 -- Insecure Inter-Agent Communication:**
- Enforce end-to-end encryption with mutual authentication (mTLS)
- Digitally sign all messages and hash payloads
- Use versioned, typed schemas rejecting invalid messages
- Protect against replay attacks using nonces and short-term hashes

**ASI08 -- Cascading Failures:**
- Implement circuit breakers and rate limits for fast-spreading detection
- Use digital twin replays testing sequences in isolated environments
- Maintain tamper-evident, time-stamped logs for forensics
- Establish blast-radius guardrails with quotas and progress caps

**ASI09 -- Human-Agent Trust Exploitation:**
- Require explicit multi-step confirmations for sensitive operations
- Provide non-model-generated risk summaries instead of AI rationales
- Use visual trust cues (red borders for high-risk) reducing automation bias
- Separate preview from effect, blocking state changes during review

**ASI10 -- Rogue Agents:**
- Deploy watchdog agents monitoring peer behavior for collusion
- Implement per-agent cryptographic attestation and baselines
- Maintain kill-switches and credential revocation for containment
- Require periodic behavioral attestation before reintegration

---

## 2. OWASP Top 10 for LLM Applications (2025)

**Official name:** OWASP Top 10 for Large Language Model Applications (2025), version 2.0
**Published by:** OWASP LLM & GenAI Security Project
**Identifier prefix:** LLM
**Status:** Released (Nov 2024)

| ID | Official Name | Plain English Description | Agent-Specific? | Attack Surface / Defense Gap |
|---|---|---|---|---|
| **LLM01:2025** | **Prompt Injection** | Crafted inputs alter an LLM's behavior in unintended ways, bypassing safety measures; includes direct injection and indirect injection via external content. | General LLM, but more dangerous in agents (indirect injection via tools/data sources) | Attack surface |
| **LLM02:2025** | **Sensitive Information Disclosure** | LLMs expose personal data, proprietary algorithms, or confidential business information through their outputs, causing privacy violations. | General LLM | Both |
| **LLM03:2025** | **Supply Chain** | Vulnerabilities in third-party components, pre-trained models, and deployment platforms that can be tampered with or poisoned. | General LLM, extended in agents by ASI04 | Attack surface |
| **LLM04:2025** | **Data and Model Poisoning** | Manipulating training data across LLM lifecycle stages to introduce vulnerabilities, backdoors, or biases compromising security and behavior. | General LLM | Attack surface |
| **LLM05:2025** | **Improper Output Handling** | Insufficient validation, sanitization, and handling of LLM-generated outputs before passing them to downstream components and systems. | General LLM, but critical in agents where outputs become tool calls | Both |
| **LLM06:2025** | **Excessive Agency** | LLM-based systems granted excessive functionality, permissions, or autonomy to call extensions or interact with external systems, enabling damaging actions. | **Agent-adjacent** -- directly relevant to agents with tool access; the most agent-relevant LLM Top 10 entry | Both |
| **LLM07:2025** | **System Prompt Leakage** | Unintended disclosure of system prompts or instructions that guide LLM behavior, revealing sensitive information or internal controls exploitable by attackers. | General LLM | Attack surface |
| **LLM08:2025** | **Vector and Embedding Weaknesses** | Security risks in RAG systems where weaknesses in how vectors and embeddings are generated, stored, or retrieved can be exploited. | General LLM, but RAG is common in agent architectures; related to ASI06 | Attack surface |
| **LLM09:2025** | **Misinformation** | LLMs generate false or misleading information that appears credible, leading to security breaches, reputational harm, and legal consequences. | General LLM, amplified in agents where misinformation drives actions | Defense gap |
| **LLM10:2025** | **Unbounded Consumption** | Excessive and uncontrolled inferences leading to denial of service, economic losses, model theft, and service degradation. | General LLM, but agents create more consumption vectors via loops | Attack surface |

### Cross-Reference: LLM Top 10 to Agentic Top 10

| LLM Category | Related ASI Category | Relationship |
|---|---|---|
| LLM01 Prompt Injection | ASI01 Agent Goal Hijack | ASI01 extends prompt injection to autonomous planning contexts |
| LLM03 Supply Chain | ASI04 Agentic Supply Chain | ASI04 adds runtime dynamic loading unique to agents |
| LLM05 Improper Output Handling | ASI02 Tool Misuse | ASI02 specializes output handling to tool-call argument injection |
| LLM06 Excessive Agency | ASI02, ASI03, ASI10 | The entire agentic top 10 could be seen as decomposing LLM06 |
| LLM08 Vector/Embedding Weaknesses | ASI06 Memory Poisoning | ASI06 extends to all persistent memory, not just RAG |
| LLM09 Misinformation | ASI08 Cascading Failures | Misinformation in agents can cascade across multi-agent systems |
| LLM10 Unbounded Consumption | ASI08 Cascading Failures | Agent loops amplify unbounded consumption |

---

## 3. OWASP AI Agent Security Cheat Sheet

**Source:** OWASP Cheat Sheet Series -- AI Agent Security Cheat Sheet
**URL:** https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
**Status:** Published

### Identified Risks

1. Prompt Injection (direct and indirect via external data sources)
2. Tool Abuse and Privilege Escalation
3. Data Exfiltration via tool calls, APIs, or outputs
4. Memory Poisoning of persistent state
5. Goal Hijacking
6. Excessive Autonomy without human oversight
7. Cascading Failures across agent chains
8. Denial of Wallet (DoW) -- excessive API/compute costs
9. Sensitive Data Exposure in context/logs

### Eight Best Practices

| # | Best Practice | Key Recommendations |
|---|---|---|
| 1 | **Tool Security and Least Privilege** | Minimum tools per task; per-tool permission scoping (read vs write); separate tool sets per trust level; allowlists of commands/paths; block dangerous patterns (*.env, *.key, *secret*) |
| 2 | **Input Validation and Prompt Injection Defense** | Treat all external data as untrusted; sanitize before including in context; clear delimiters between instructions and data; content filtering for injection patterns; separate LLM calls to validate untrusted content |
| 3 | **Memory and Context Security** | Validate/sanitize before storing; memory isolation between users/sessions; expiration and size limits; cryptographic integrity checks; redact sensitive patterns (SSN, credit cards, API keys) |
| 4 | **Human-in-the-Loop Controls** | Explicit approval for high-impact/irreversible actions; action previews; risk-level classification (LOW/MEDIUM/HIGH/CRITICAL); auto-approve only low-risk reads; queue high-risk for human review |
| 5 | **Output Validation and Guardrails** | Validate outputs before execution; filter for PII/credential leakage; structured outputs with schema validation; rate and scope limits; validate tool names against allowlists |
| 6 | **Monitoring and Observability** | Log all decisions, tool calls, outcomes; anomaly detection; token/cost tracking per session/user; alert on security events; redact sensitive fields from logs |
| 7 | **Multi-Agent Security** | Trust boundaries between agents; validate inter-agent communications; prevent privilege escalation through chains; isolate execution environments; circuit breakers; signed messages; trust level tiers (UNTRUSTED/INTERNAL/PRIVILEGED/SYSTEM) |
| 8 | **Data Protection and Privacy** | Minimize sensitive data in context; data classification (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED); encryption at rest and in transit; retention/deletion policies; GDPR/CCPA compliance |

### Critical Anti-Patterns (Do Not Do)

- Do not grant unrestricted tool access or wildcard permissions
- Do not trust external content without validation
- Do not allow arbitrary code execution without sandboxing
- Do not store sensitive data in memory without encryption/redaction
- Do not allow high-impact decisions without human oversight
- Do not ignore cost controls (unbounded loops cause Denial of Wallet)
- Do not pass unsanitized data between agents
- Do not log sensitive data in plain text

---

## 4. OWASP MCP Security Guidelines

### 4a. OWASP Practical Guide for Secure MCP Server Development

**Published by:** OWASP GenAI Security Project
**Date:** February 17, 2026
**Status:** Released (v1.0)
**URL:** https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/

This is a formal, versioned guidance document focused on secure development of Model Context Protocol (MCP) servers. The full content is rendered dynamically and could not be fully extracted, but it is confirmed to exist as an official OWASP resource.

### 4b. OWASP MCP Top 10 (Community/Emerging)

**Source:** Community-driven mapping (referenced in multiple repositories and tools)
**Identifier prefix:** MCP
**Status:** Community-driven; not yet an official OWASP flagship project but widely referenced

| ID | Official Name | Plain English Description | Agent-Specific? | Attack Surface / Defense Gap |
|---|---|---|---|---|
| **MCP01** | **Token Mismanagement and Secret Exposure** | Improper handling of authentication tokens and credential leakage in MCP server implementations. | Yes -- MCP is an agent protocol | Both |
| **MCP02** | **Privilege Escalation via Scope Creep** | Unauthorized expansion of system access and permissions through MCP tool definitions. | Yes | Attack surface |
| **MCP03** | **Tool Poisoning** | Corruption or manipulation of tools and resources registered in the MCP server. | Yes | Attack surface |
| **MCP04** | **Supply Chain Attacks and Dependency Tampering** | Compromise of external dependencies and third-party components used by MCP servers. | Yes | Attack surface |
| **MCP05** | **Command Injection and Execution** | Malicious code execution through unsanitized input passed to MCP tool handlers. | Yes | Attack surface |
| **MCP06** | **Prompt Injection via Contextual Payloads** | Exploitation of LLM inputs through crafted prompts embedded in MCP tool responses or resource content. | Yes | Attack surface |
| **MCP07** | **Insufficient Authentication and Authorization** | Weak identity verification and access control mechanisms in MCP server-client communication. | Yes | Defense gap |
| **MCP08** | **Lack of Audit and Telemetry** | Missing logging and monitoring capabilities for security events in MCP interactions. | Yes | Defense gap |
| **MCP09** | **Shadow MCP Servers** | Unauthorized or unmanaged MCP server implementations connecting to agent systems without governance. | Yes | Both |
| **MCP10** | **Context Injection and Over-Sharing** | Excessive data exposure and information disclosure through MCP context/resource sharing. | Yes | Both |

---

## 5. Other OWASP Resources on AI Agent Security

### 5a. OWASP AI Exchange

**URL:** https://owaspai.org
**Status:** Flagship documentation project, v1.0, 300+ pages
**Leadership:** Rob van der Veer (ISO/IEC 5338 author)

Comprehensive resource covering AI security and privacy across builders, breakers, and buyers. Organized into eight sections:

1. AI Security Overview (threats, controls, risk analysis)
2. General Controls (governance, data limitation, unwanted behavior)
3. Input Threats and Controls (evasion, prompt injection, data disclosure, model exfiltration)
4. Development-Time Threats (model poisoning, data leaks in supply chains)
5. Runtime Security Threats (runtime poisoning, model leaks, injection, data manipulation)
6. AI Security Testing (red-teaming tools, adversarial testing)
7. AI Privacy (use limitation, fairness, minimization, consent, transparency)
8. References

Note: As of the last check, the AI Exchange does not have a dedicated agentic AI section, but its general controls and threat categories are applicable.

### 5b. OWASP Machine Learning Security Top 10 (2023, v0.3 Draft)

**Identifier prefix:** ML
**Status:** Draft v0.3 (2023)

| ID | Name | Description | Agent-Relevant? |
|---|---|---|---|
| ML01 | Input Manipulation Attack | Tricking ML models into misclassifying inputs | Tangential |
| ML02 | Data Poisoning Attack | Injecting poisoning samples into training data | General ML |
| ML03 | Model Inversion Attack | Extracting sensitive information from trained models | General ML |
| ML04 | Membership Inference Attack | Determining whether specific data was in training set | General ML |
| ML05 | Model Theft | Unauthorized copying or extraction of ML models | General ML |
| ML06 | AI Supply Chain Attacks | Compromising ML via vulnerable dependencies | Tangential |
| ML07 | Transfer Learning Attack | Exploiting knowledge transferred between models | General ML |
| ML08 | Model Skewing | Degrading performance through systematic manipulation | General ML |
| ML09 | Output Integrity Attack | Tampering with model outputs after generation | Tangential |
| ML10 | Model Poisoning | Corrupting training processes to embed malicious behavior | General ML |

This is a general ML security list, not agent-specific. Mostly relevant as background context.

### 5c. OWASP LLM Prompt Injection Prevention Cheat Sheet

**URL:** https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html

Key agent-specific content:
- Documents "Thought/Observation Injection" and tool manipulation attacks specific to agents
- Recommends validating tool calls against user permissions
- Recommends parameter validation for tools
- Recommends monitoring agent reasoning for anomalies
- Recommends restricting tool access via least privilege

Critical finding: Research shows 89% success rate on GPT-4o and 78% on Claude 3.5 Sonnet with Best-of-N jailbreaking, suggesting fundamental architectural improvements may be needed.

### 5d. OWASP Agentic AI Threats and Mitigations Guide

**URL:** https://genai.owasp.org/resource/agentic-ai/
**Published:** February 17, 2025 (updated April 28, 2025)
**Status:** Released (v1.0)

A formal, versioned guidance document exploring key threats and mitigation strategies for agentic AI, focusing on security measures to address vulnerabilities in AI applications. This appears to be a precursor/companion document to the Agentic Applications Top 10.

### 5e. Community Working Group: precize/Agentic-AI-Top10-Vulnerability

An alternative categorization used as input for OWASP and CSA (Cloud Security Alliance) red teaming work. Uses a different identifier scheme (AAI prefix) with partially overlapping but distinct categories:

| ID | Name | Notes |
|---|---|---|
| AAI001 | Agent Authorization and Control Hijacking | Maps to ASI01, ASI03 |
| AAI002 | Agent Critical Systems Interaction | Maps to ASI02, ASI05 |
| AAI003 | Agent Goal and Instruction Manipulation | Maps to ASI01 |
| AAI005 | Agent Impact Chain and Blast Radius | Maps to ASI08 |
| AAI006 | Agent Memory and Context Manipulation | Maps to ASI06 |
| AAI007 | Agent Orchestration and Multi-Agent Exploitation | Maps to ASI07 |
| AAI009 | Agent Supply Chain and Dependency Attacks | Maps to ASI04 |
| AAI011 | Agent Untraceability and Accountability | No direct ASI equivalent (defense gap) |
| AAI012 | Agent Checker Out of the Loop | Maps to ASI09 |
| AAI014 | Agent Alignment Faking | Maps to ASI10 |

Planned future additions: AAI013 (Temporal Manipulation), AAI015 (Inversion and Extraction), AAI016 (Covert Channel Exploitation).

---

## 6. Master Cross-Reference: All OWASP Frameworks Mapped to Agent Security Concerns

| Agent Security Concern | ASI (Agentic 2026) | LLM (2025) | MCP | Cheat Sheet | ML (2023) |
|---|---|---|---|---|---|
| Goal/instruction manipulation | ASI01 | LLM01 | MCP06 | Best Practice 2 | -- |
| Tool misuse / argument injection | ASI02 | LLM06 | MCP05 | Best Practice 1 | -- |
| Identity / privilege escalation | ASI03 | -- | MCP02, MCP07 | Best Practice 1 | -- |
| Supply chain compromise | ASI04 | LLM03 | MCP04 | -- | ML06 |
| Code execution / RCE | ASI05 | LLM05 | MCP05 | Best Practice 5 | -- |
| Memory / context poisoning | ASI06 | LLM08 | MCP10 | Best Practice 3 | ML02 |
| Inter-agent communication | ASI07 | -- | -- | Best Practice 7 | -- |
| Cascading / systemic failures | ASI08 | LLM10 | -- | Best Practice 7 | -- |
| Human trust exploitation | ASI09 | LLM09 | -- | Best Practice 4 | -- |
| Rogue / misaligned agents | ASI10 | -- | -- | -- | -- |
| Sensitive data exposure | -- | LLM02 | MCP01, MCP10 | Best Practice 8 | ML03, ML04 |
| System prompt leakage | -- | LLM07 | -- | Best Practice 2 | -- |
| Token/secret mismanagement | -- | -- | MCP01 | Best Practice 8 | -- |
| Shadow/unmanaged servers | -- | -- | MCP09 | -- | -- |
| Audit/observability gaps | -- | -- | MCP08 | Best Practice 6 | -- |
| Denial of wallet | -- | LLM10 | -- | Cheat Sheet risk 8 | -- |
| Traceability/accountability | (AAI011) | -- | MCP08 | Best Practice 6 | -- |

---

## 7. Items Not Found

- **OWASP AI Agent Security Cheat Sheet as a standalone OWASP "project"**: It exists as a cheat sheet in the OWASP Cheat Sheet Series, not as a separate OWASP project.
- **Official OWASP MCP Top 10 as a flagship project**: The MCP Top 10 is community-driven and widely referenced but does not appear to be an official OWASP flagship project yet. The official OWASP resource is the "Practical Guide for Secure MCP Server Development."
- **OWASP Top 10 for Agentic Applications as a standalone OWASP project page**: The project lives under the OWASP GenAI Security Project umbrella at genai.owasp.org, not as a separate www-project page on owasp.org.
- **Dedicated agentic AI section in the OWASP AI Exchange (owaspai.org)**: Not found as of this search. The AI Exchange covers general AI security.

---

## 8. Summary of All OWASP Resources Identified

| Resource | Official Status | Year | Agent-Specific? | URL |
|---|---|---|---|---|
| OWASP Top 10 for Agentic Applications | Released v1.0 | 2026 | Yes (entirely) | genai.owasp.org |
| OWASP Top 10 for LLM Applications | Released v2.0 | 2025 | Partially (LLM06 most relevant) | genai.owasp.org |
| OWASP AI Agent Security Cheat Sheet | Published | 2025-2026 | Yes (entirely) | cheatsheetseries.owasp.org |
| OWASP Secure MCP Server Development Guide | Released v1.0 | 2026 | Yes (MCP is agent protocol) | genai.owasp.org |
| OWASP MCP Top 10 | Community-driven | 2025-2026 | Yes (entirely) | Community repos |
| OWASP AI Exchange | Flagship v1.0 | 2024-2026 | General AI | owaspai.org |
| OWASP ML Security Top 10 | Draft v0.3 | 2023 | No (general ML) | owasp.org |
| OWASP LLM Prompt Injection Prevention Cheat Sheet | Published | 2024-2025 | Partially | cheatsheetseries.owasp.org |
| OWASP Agentic AI Threats and Mitigations Guide | Released v1.0 | 2025 | Yes | genai.owasp.org |
| Agentic AI Top 10 Vulnerability (CSA/OWASP working group) | Working draft | 2025-2026 | Yes | github.com/precize |
