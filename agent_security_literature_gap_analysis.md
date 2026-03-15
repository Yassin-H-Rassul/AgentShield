# AI Agent Security: Literature Gap Analysis

**Date of analysis:** March 15, 2026
**Methodology:** Systematic web search of published papers, tools, benchmarks, and industry frameworks across 15 problem areas. Only verifiable publications are cited. Uncertainty is noted explicitly.

---

## 1. Prompt Injection Detection/Defense for Agents (Not Just Chatbots)

**Maturity: Growing (rapidly)**

### What EXISTS

**Attack research:**
- **ToolHijacker** (arXiv 2504.19793, Aug 2025) -- Prompt injection targeting tool selection in LLM agents in no-box scenarios; injects malicious tool documents to manipulate tool selection.
- **Log-To-Leak** (OpenReview, Oct 2025) -- Privacy attacks on tool-using agents via MCP; forces agents to invoke malicious logging tools for data exfiltration. Systematizes attack design into Trigger, Tool Binding, Justification, and Pressure components.
- **"The Attacker Moves Second"** (Oct 2025, researchers from OpenAI/Anthropic/Google DeepMind) -- Examines 12 published defenses against prompt injection and subjects them to adaptive attacks; finds most defenses brittle.

**Defense research:**
- **MELON** (OpenReview, May 2025) -- Provable defense via masked re-execution and tool comparison (MELON). Detects attacks by comparing original vs. masked-prompt execution trajectories.
- **PromptArmor** (arXiv 2507.15219, Jul 2025) -- Detection-based defenses using separate guardrail models to filter injected content.
- **Multi-Agent LLM Defense Pipeline** (arXiv 2509.14285, Dec 2025) -- Multi-agent framework for real-time prompt injection detection/neutralization; claims 100% mitigation in tested scenarios.
- **CaMeL** (Google DeepMind, Jan 2026) -- Splits agent into Privileged LLM (planner, never sees raw data) and Quarantined LLM (reader, isolated). Borrows from control flow integrity and information flow control.
- **IsolateGPT/SecGPT** (NDSS 2025) -- Execution isolation architecture; isolates tools/apps into separate containers in a hub-and-spoke model. Performance overhead under 30% for 75% of queries.

**Comprehensive reviews:**
- MDPI Information journal review (2025) -- 45 sources covering 2023-2025 prompt injection landscape.
- ScienceDirect survey (2025) -- "From prompt injections to protocol exploits" covering agent workflow threats.

### What is MISSING
- **Defenses validated against adaptive attackers at scale.** "The Attacker Moves Second" shows most published defenses fail against adaptive attacks. No defense has demonstrated robustness against a motivated adversary with query access.
- **Agent-specific injection taxonomies.** Most work adapts chatbot-era injection thinking. The unique attack surface of tool-equipped agents (tool selection manipulation, multi-step plan corruption, tool-output injection) lacks a unified formal framework.
- **Standardized defense evaluation protocol.** Different papers test different attacks against different defenses with incomparable metrics.

**Gap trajectory:** Narrowing fast. This is the most active area.

---

## 2. Memory Poisoning in Persistent Agents

**Maturity: Growing (early stage)**

### What EXISTS

**Attack research:**
- **MINJA** (arXiv 2503.03704, Mar 2025) -- Memory INJection Attack. Query-only attack achieving >95% injection success rates through bridging steps and progressive shortening. Any regular user can launch it without privileged access.
- **MemoryGraft** (arXiv 2512.16962, Dec 2025) -- Exploits agent's semantic imitation heuristic by implanting malicious "successful experiences" into long-term memory. Unlike transient prompt injections, persists across sessions.
- **InjecMEM** (OpenReview, 2025) -- Fine topic-conditioned retrieval and targeted generation; persists after benign drift; leaves non-target queries unaffected.
- **Memory Poisoning Attack and Defense on Memory Based LLM-Agents** (arXiv 2601.05504, Jan 2026) -- Systematizes attacks and proposes defenses including input/output moderation with two-stage gating.

**Industry reports:**
- Palo Alto Unit42 (2025) -- "When AI Remembers Too Much" -- documents persistent behavior changes from indirect prompt injection into long-term memory.
- Lakera blog series (2025) -- "Agentic AI Threats: Memory Poisoning & Long-Horizon Goal Hijacks."

### What is MISSING
- **Delayed trigger / time-bomb attacks.** Most current work demonstrates immediate or near-term poisoning effects. No published work systematically studies attacks with delayed activation (e.g., poison planted today, triggers weeks later under specific conditions). InjecMEM touches persistence but not conditional delayed triggers.
- **Defense-side solutions are primitive.** The only published defense mechanism is input/output gating (arXiv 2601.05504). No work on memory integrity verification, cryptographic memory attestation, or provenance-based memory trust.
- **Cross-session attack chains.** No work studies coordinated multi-session attacks where different sessions each contribute partial poison that only becomes effective when combined.
- **Benchmarks for memory safety.** No standardized benchmark exists for evaluating memory poisoning resistance.

**Gap trajectory:** Stable/wide open. Attacks are ahead of defenses by a significant margin.

---

## 3. Tool Misuse / Unauthorized Tool Calls by Agents

**Maturity: Growing**

### What EXISTS

**Benchmarks:**
- **AgentHarm** (ICLR 2025, arXiv 2410.09024) -- 110 malicious tasks (440 with augmentations) across 11 harm categories. Found frontier models (GPT-4o, Claude 3.5 Sonnet) surprisingly compliant with malicious agent requests even without jailbreaking.
- **SafeAgentBench** (arXiv 2412.13178, Dec 2024) -- 750 tasks covering 10 hazards in embodied environments; no LLM agent achieved overall safety score above 60%. Most safety-conscious baseline achieves only 10% rejection rate for hazardous tasks.
- **Agent-SafetyBench** (arXiv 2412.14470, Dec 2024) -- Evaluating safety of LLM agents from Tsinghua.
- **BAD-ACTS** -- 188 harmful actions across four agentic environments; derivative of AgentHarm.

**Frameworks:**
- **TrustAgent** (EMNLP Findings 2024) -- Agent Constitution-based framework with pre-planning, in-planning, and post-planning safety strategies.
- OWASP ASI02 (Dec 2025) -- "Tool Misuse & Exploitation" formally recognized as top-3 agentic AI risk.

### What is MISSING
- **Runtime tool call authorization systems.** No published system dynamically evaluates whether a specific tool call is authorized given the current task context (beyond simple allow/deny lists).
- **Tool call anomaly detection.** Limited work on detecting unusual tool call patterns vs. normal agent behavior in production.
- **Tool composition attacks.** No work studies how individually safe tool calls can be composed into harmful sequences (e.g., read file + send email = data exfiltration).

**Gap trajectory:** Narrowing. Benchmarks now exist; defense systems are lagging.

---

## 4. Identity and Privilege Abuse

**Maturity: Growing (early stage)**

### What EXISTS

**Research:**
- **Mandatory Access Control for LLM Agents** (arXiv 2601.11893, Jan 2026) -- Proposes MAC framework; defines privilege escalation as a unifying lens on agent vulnerabilities.
- **MiniScope** (arXiv 2512.11147, Dec 2025, UC Berkeley) -- Least privilege framework for authorizing tool-calling agents.
- **CELLMATE** (arXiv 2512.12594, Dec 2025) -- Sandboxing browser AI agents with a unique permission model for collaborative permission definition among stakeholders.
- **Probabilistic Authorization Framework** (ACM BDCAT 2025) -- "Toward Agentic IAM" -- probabilistic authorization for least privilege AI workflows.
- **Securing AI Agent Execution** (arXiv 2510.21236, Oct 2025) -- Policy enforcement engine as a sandbox with declared permissions.

**Industry frameworks:**
- OWASP ASI03 (Dec 2025) -- "Identity & Privilege Abuse" in top-10 agentic risks.
- AWS Well-Architected Generative AI Lens (2025) -- Guidance on least privilege for agentic workflows.
- OWASP "Principle of Least Agency" -- Agentic equivalent of least privilege.

**Documented incidents:**
- Cross-agent privilege escalation where two coding assistants rewrote each other's configuration files and escalated privileges.
- Vertex AI privilege escalation to LLM model exfiltration (Palo Alto Unit42).

### What is MISSING
- **Dynamic privilege adjustment.** All published frameworks use static permission definitions. No work on dynamically adjusting agent permissions based on task context, risk level, or behavioral signals.
- **Delegation chains.** When Agent A delegates to Agent B, how are permissions propagated and attenuated? No formal model exists for multi-hop delegation.
- **Credential lifecycle management.** No work addresses credential rotation, revocation, or expiry for agent-held credentials.
- **Identity federation across agent platforms.** No standard for verifying agent identity across different frameworks (e.g., LangChain agent interacting with AutoGen agent).

**Gap trajectory:** Narrowing moderately. Several 2025 papers are landing but fundamental problems remain.

---

## 5. Malicious Skill/Tool/Plugin Detection (Supply Chain)

**Maturity: Growing (rapidly for MCP specifically)**

### What EXISTS

**Scanning tools:**
- **MCPGuard** (arXiv 2510.23673, Virtue AI, Oct 2025) -- Agent-based MCP scanner using fine-tuned LLMs for semantic analysis. Analyzed 700+ MCP servers; found critical vulnerabilities in 78% of implementations.
- **Cisco MCP Scanner** (open-source, 2025) -- Three scanning engines: Yara, LLM-as-judge, and Cisco AI Defense. Performs contextual/semantic analysis of tool definitions.
- **Snyk Agent Scan** (GitHub, 2025) -- Inventories installed agent components; scans for prompt injections, sensitive data handling, malware payloads.
- **mcpscan.ai** (2025) -- Web-based MCP security scanner.
- **SecureMCP** (2025) -- Detects prompt injection and credential misuse in MCP-integrated applications.

**Vulnerability research:**
- March 2025 analysis: 43% of public MCP servers had command injection flaws; 30% permitted unrestricted URL fetching.
- CVE-2025-6514 (mcp-remote): Command injection allowing full system compromise via malicious MCP server.
- Elastic Security Labs (2025): Comprehensive attack vector and defense analysis for MCP tools.
- Tool poisoning attacks (malicious instructions in tool descriptions/metadata) and rug pull attacks (legitimate tools updated with malicious intent) documented.

**Industry frameworks:**
- OWASP ASI04 (Dec 2025) -- "Agentic Supply Chain Vulnerabilities."
- Adversa AI MCP Security Digest (monthly, since Jul 2025).

### What is MISSING
- **Formal verification of tool behavior.** All current scanners use heuristic/LLM-based analysis. No work on formally verifying that a tool does only what it claims.
- **Runtime behavioral monitoring of tools.** Scanning happens pre-deployment; no published system monitors tool behavior drift post-deployment (i.e., rug pull detection at runtime).
- **Trusted tool registries/signing.** No equivalent of package signing (like npm/PyPI sigstore) for agent tools/MCP servers.
- **Cross-tool interaction analysis.** Tools are analyzed individually; no work studies how combinations of benign tools can create vulnerabilities.

**Gap trajectory:** Narrowing fast for MCP specifically, but broader agent supply chain (non-MCP plugins, custom tools) remains wide open.

---

## 6. Inter-Agent Communication Security

**Maturity: Immature**

### What EXISTS

**Attack research:**
- **Red-Teaming LLM Multi-Agent Systems via Communication Attacks** (ACL Findings 2025, arXiv 2502.14847) -- Agent-in-the-Middle (AiTM) attacks intercepting/manipulating inter-agent messages; >90% success in DoS or payload propagation across multi-agent topologies.
- **Prompt Infection** (ICLR 2025 submission, arXiv 2410.07283) -- Worm-like self-replicating prompt attacks propagating across agent chains; full society saturation in under 11 communication steps for 50-agent populations.
- **Morris II** (arXiv 2403.02817, Mar 2024, updated Jan 2025) -- First worm targeting GenAI ecosystems via adversarial self-replicating prompts.
- **"The Trust Paradox in LLM-Based Multi-Agent Systems"** (arXiv 2510.18563, Oct 2025) -- Documents how LLMs that resist direct malicious commands execute identical payloads when requested by peer agents; 82.4% compromise rate via inter-agent communication.

**Emerging protocol/identity work:**
- **CA-MCPQ** (ePrint 2025/1790) -- Context-aware post-quantum protocol for AI agent communication.
- **AgentCrypt** (ePrint 2025/2216) -- Privacy and secure computation in agent collaboration.
- **BlockA2A** (arXiv 2508.01332, Aug 2025) -- Blockchain-based secure agent-to-agent interoperability (position paper).
- **DID/VC for AI Agents** (arXiv 2511.02841, Nov 2025) -- W3C Decentralized Identifiers and Verifiable Credentials for agent authentication.
- **TRiSM for Agentic AI** (arXiv 2506.04133, Jun 2025) -- Trust, Risk, and Security Management framework; recommends defense-in-depth including prompt hygiene.

**Communication protocols (emerging standards):**
- Google A2A (Agent-to-Agent), Anthropic MCP, IBM ACP, community ANP -- four complementary protocols, but none with built-in security guarantees.

### What is MISSING
- **Authenticated inter-agent channels in practice.** Cryptographic protocols exist as proposals/position papers (BlockA2A, CA-MCPQ) but none are implemented in any major agent framework (LangChain, AutoGen, CrewAI, etc.).
- **Replay attack prevention.** No published work specifically addresses replay attacks in agent communication (reusing captured inter-agent messages).
- **Message integrity and non-repudiation.** No system guarantees that an agent message was not tampered with in transit.
- **Trust establishment protocols.** No standard way for agents to establish trust before cooperating (analogous to TLS handshake).
- **Practical defenses against self-replicating prompts.** Morris II and Prompt Infection demonstrate the attacks; defense research is minimal.

**Gap trajectory:** Stable/wide open. Attack research is well ahead of defense. Protocol-level security is mostly theoretical.

---

## 7. Cascading Failures in Agent Workflows

**Maturity: Immature**

### What EXISTS

**Conceptual/survey work:**
- **Gradient Institute report** (arXiv 2508.05687, Aug 2025) -- Risk analysis techniques for governed LLM-based multi-agent systems.
- **OWASP ASI10** (Dec 2025) -- "Rogue Agents" category acknowledges cascading risks.
- **AWS Agentic AI Security Scoping Matrix** (2025) -- Framework acknowledges cascading failures but provides high-level guidance only.
- Galileo AI analysis (2025) -- In simulated systems, a single compromised agent poisoned 87% of downstream decision-making within 4 hours.

**Related but tangential:**
- **AgentAsk** (arXiv 2510.07593, Oct 2025) -- "Multi-Agent Systems Need to Ask" -- proposes confirmation mechanisms.
- Industry incident: 2024 financial services case where a compromised reconciliation agent exfiltrated 45,000 customer records through downstream agents.

### What is MISSING
- **Formal models of cascading failure propagation.** No published work formally models how compromise propagates through agent dependency graphs, analogous to fault tree analysis or epidemic models.
- **Circuit breakers / blast radius containment.** No published system implements automatic containment when one agent in a workflow is compromised (analogous to bulkheads in microservices).
- **Cascading failure benchmarks.** No benchmark tests how different agent architectures resist failure propagation.
- **Root cause analysis tools.** Diagnosing which agent initiated a cascade requires deep observability that current tools do not provide (per Galileo analysis).
- **Recovery mechanisms.** No work on how a multi-agent system recovers after a cascading failure (rollback, quarantine, graceful degradation).

**Gap trajectory:** Wide open. This area has almost no dedicated research -- just acknowledgments that the problem exists.

---

## 8. Agent Behavioral Monitoring / Anomaly Detection

**Maturity: Immature (but growing)**

### What EXISTS

**Research systems:**
- **TraceAegis** (arXiv 2510.11203, Oct 2025) -- Provenance-based analysis framework that constructs hierarchical structures from agent execution traces to characterize normal behaviors and detect anomalies.
- **SentinelAgent** (arXiv 2505.24201, May 2025) -- Graph-based anomaly detection for multi-agent systems; models agent interactions as dynamic execution graphs with semantic anomaly detection at node, edge, and path levels. Detects prompt injection propagation, unauthorized tool usage, and multi-agent collusion.

**Commercial/industry tools:**
- **LLM Guard** (Protect AI, open source) -- Input/output scanners for prompt injection, PII, toxicity, etc. Over 2.5M downloads. CPU-optimized. Not agent-specific but usable as a guardrail layer.
- **Langfuse** -- LLM observability platform with security/guardrails integration.
- **Datadog LLM Monitoring** (2025) -- Production monitoring with guardrail integration.

### What is MISSING
- **Behavioral baselines for agents.** TraceAegis and SentinelAgent are early-stage. No production-proven system establishes behavioral baselines for agents and detects deviations in real-time.
- **Monitoring across agent frameworks.** Each monitoring solution works within its own ecosystem. No cross-framework monitoring standard exists.
- **Anomaly detection at the reasoning level.** Current systems monitor tool calls and outputs. No system monitors the agent's reasoning process itself (chain-of-thought deviations, goal drift).
- **Alerting and response integration.** No published system integrates agent anomaly detection with incident response workflows (SIEM/SOAR integration for agents).
- **Empirical studies of agent behavior in production.** No published dataset of normal vs. anomalous agent behavior in real deployments.

**Gap trajectory:** Narrowing. TraceAegis and SentinelAgent are 2025 publications, suggesting this is an active emerging area.

---

## 9. Cross-Lingual Attacks on Agents

**Maturity: Immature**

### What EXISTS

**Research:**
- **MultiJail** (Deng et al., 2024) -- Jailbreaking LLMs in 10 languages; demonstrates cross-lingual safety mechanism vulnerabilities.
- **Cross-Lingual Prompt Steerability** (arXiv 2512.02841, Dec 2025) -- Four-dimensional evaluation framework for system prompts in multilingual environments; experiments on 5 languages, 3 LLMs, 3 benchmarks.
- **LinguaSafe** (arXiv 2508.12733, Aug 2025) -- Comprehensive multilingual safety benchmark for LLMs.

**Documented vulnerability patterns:**
- Low-resource language bypass: Malicious prompts in high-resource languages translated to low-resource languages (e.g., Hausa) bypass filters effectively.
- Tokenization asymmetry: Non-Latin scripts (Arabic, Thai, Khmer) fragment into more tokens, changing model interpretation and filter effectiveness.
- 2025 guardrail comparison: None of the major platforms (Azure Content Safety, Amazon Bedrock) had validated multilingual prompt injection defenses, particularly for non-Latin scripts.

### What is MISSING
- **Agent-specific cross-lingual attacks.** All published work targets chatbot-style LLMs. No published paper studies cross-lingual attacks specifically on tool-using agents (e.g., injecting instructions in Swahili into a document that an English-language agent retrieves via RAG).
- **Multilingual prompt injection benchmark for agents.** MultiJail and LinguaSafe test LLMs, not agents with tools.
- **Cross-lingual tool name/description attacks.** No work studies whether tool descriptions in unexpected languages can bypass agent safety checks.
- **Defense systems for multilingual agent contexts.** No guardrail system is specifically designed for multilingual agent environments.
- **Low-resource language coverage in any agent security benchmark.** ASB, AgentHarm, SafeAgentBench are all English-only.

**Gap trajectory:** Wide open. The intersection of cross-lingual attacks and agent security is nearly untouched. Individual components (cross-lingual LLM attacks, agent security) exist but are not combined.

---

## 10. Indirect Prompt Injection via Retrieved Content (RAG, Documents, Web Pages)

**Maturity: Growing (most mature sub-area)**

### What EXISTS

**Attack research:**
- **Indirect Prompt Injection in the Wild** (arXiv 2601.07072, Jan 2026) -- Identifies retrieval as the bottleneck of IPI: without reliable surfacing of malicious text, attacks fail under natural queries.
- **Hidden-in-Plain-Text** (arXiv 2601.10923, Jan 2026) -- Benchmark for social-web IPI in RAG; covers hidden spans, off-screen CSS, alt text, ARIA markup carriers.
- **When AI Meets the Web** (arXiv 2511.05797, accepted IEEE S&P 2026) -- Risks in third-party AI chatbot plugins that scrape web content for RAG.
- **Greshake et al.** (ACM AISec 2023, foundational) -- "Not What You've Signed Up For" -- first systematic study of indirect prompt injection.

**Defense research:**
- **Instruction Detection defense** (arXiv 2505.06311, May 2025) -- Removes documents containing detected instructions before passing to LLM.
- **Securing AI Agents Against Prompt Injection** (arXiv 2511.15759, Nov 2025) -- Comprehensive benchmark with 847 adversarial test cases; combined framework reduces attack success from 73.2% to 8.7% while maintaining 94.3% task performance. Uses content filtering + embedding-based anomaly detection + hierarchical guardrails + multi-stage response verification.
- **MELON** (2025) -- Also applicable to RAG-based IPI (see Area 1).
- **Benchmarking and Defending against IPI** (ACM KDD 2025) -- Systematic defense evaluation.

### What is MISSING
- **Multimodal IPI.** Most work focuses on text. Limited research on images, PDFs, or structured data (JSON, CSV) as injection vectors in RAG pipelines.
- **Real-time defense at retrieval time.** Most defenses operate post-retrieval. No published system filters injections during the retrieval step itself (before the document reaches the LLM).
- **Long-document injection.** How injection effectiveness changes with document length and injection position within very long contexts is understudied.
- **Combined attack vectors.** No work studies IPI combined with other attacks (e.g., IPI + memory poisoning, IPI + cross-lingual).

**Gap trajectory:** Narrowing rapidly. This is one of the most actively researched areas, with multiple defense papers in 2025.

---

## 11. Agent Output Safety / Data Leakage Prevention

**Maturity: Growing (but agent-specific work is thin)**

### What EXISTS

**Tools:**
- **LLM Guard** (Protect AI, open source) -- Output scanners for content moderation, bias detection, malicious URL detection, PII deanonymization. 2.5M+ downloads.
- **Nightfall AI** -- Commercial DLP specifically for LLMs.
- **Guardrails AI (NeMo Guardrails, Nvidia)** -- Output filtering and safety checking.

**Attack-side awareness:**
- **Log-To-Leak** (2025) -- Demonstrates data exfiltration via forced tool invocation.
- **Toxic Agent Flow** -- Hijacking GitHub MCP server to leak private repository data via pull requests.

**Industry guidance:**
- OWASP LLM06/LLM02 (2025) -- Sensitive information disclosure.
- Palo Alto Unit42 guardrail comparison (2025) -- Evaluated effectiveness of major guardrail platforms.

### What is MISSING
- **Agent-specific output safety.** LLM Guard et al. are designed for chatbot outputs (text). Agent outputs include tool calls, API requests, file writes, database queries -- none of which are covered by existing output safety tools.
- **Covert channel detection.** No work studies how agents might leak data through side channels (timing, tool call patterns, encoding data in seemingly benign outputs).
- **Output safety for multi-step workflows.** Current tools check individual outputs. No system evaluates whether a sequence of individually safe outputs constitutes a data leak in aggregate.
- **Output safety for structured data.** Agents often produce JSON, SQL, code -- current safety tools are optimized for natural language.

**Gap trajectory:** Moderately narrowing for text outputs; wide open for agent-specific output types.

---

## 12. Permission and Scope Management for Agent Actions

**Maturity: Growing (early stage)**

### What EXISTS

**Research (same as Area 4, with additional detail):**
- **MiniScope** (UC Berkeley, Dec 2025) -- Least privilege framework specifically for tool-calling agents.
- **CELLMATE** (Dec 2025) -- Browser agent sandboxing with stakeholder-collaborative permission model.
- **IsolateGPT/SecGPT** (NDSS 2025) -- Hub-and-spoke isolation architecture.
- **ACE** (arXiv 2504.20984, Apr 2025) -- Security architecture for LLM-integrated app systems.
- **Systems Security Foundations for Agentic Computing** (ePrint 2025/2173) -- Comprehensive framework applying traditional security principles to agents.

**Industry:**
- AWS Well-Architected guidance for agentic workflows.
- Anthropic MCP permissions model (resource-level consent).

### What is MISSING
- **Expressive permission languages for agents.** No equivalent of RBAC/ABAC policies specifically designed for agent actions (e.g., "Agent X may call the email tool only for recipients in the user's contact list, only during business hours, and only for task types approved by the user").
- **Permission inference.** No system automatically infers minimal required permissions from a task description.
- **Conflict resolution.** When multiple policies apply to an agent action, no framework resolves conflicts.
- **User-facing permission management.** No published UX research on how end users should understand and manage agent permissions.

**Gap trajectory:** Narrowing moderately. Foundational frameworks exist but practical tooling does not.

---

## 13. Agent Forensics / Audit Trails / Provenance

**Maturity: Immature**

### What EXISTS

**Research:**
- **TraceAegis** (arXiv 2510.11203, Oct 2025) -- Constructs hierarchical structures from agent execution traces (dual purpose: anomaly detection + forensic analysis).
- **ProvSEEK** (arXiv 2508.21323, Aug 2025) -- LLM-powered agentic framework for provenance-driven forensic analysis; 22%/29% higher precision/recall vs. baselines. Includes safety checks before/after query execution. (Note: this uses agents for forensics, not forensics of agents specifically.)

**Industry/commercial:**
- **FireTail** (2025) -- Commercial AI audit trail platform.
- **Langfuse** -- LLM observability with trace logging.
- **MCP Audit Logging** (Tetrate, 2025) -- Specific guidance for logging MCP agent actions.
- ISACA guidance (2025) -- "The Growing Challenge of Auditing Agentic AI."

**Guidance documents:**
- Comprehensive logging recommendations: capture prompts, retrieved documents, model/tool versions, tool calls and parameters, safety scores, decisions and overrides, user approvals.

### What is MISSING
- **Standardized agent trace formats.** No equivalent of OpenTelemetry spans specifically designed for agent execution (tool calls, reasoning steps, permission checks, etc.). Each platform uses its own format.
- **Tamper-proof audit trails.** No published system ensures that agent logs cannot be modified by the agent itself or by a compromised system.
- **Forensic reconstruction tools.** No tool can take an agent's execution trace and reconstruct what happened in a human-understandable narrative (unlike TraceAegis which detects anomalies but does not reconstruct incidents).
- **Causal attribution.** When an agent produces a harmful outcome, no system can attribute it to a specific input, instruction, or reasoning step.
- **Cross-agent provenance.** In multi-agent systems, tracing an outcome back through multiple agents to the original cause is unsolved.
- **Legal/regulatory standards.** No regulatory framework specifies what agent audit trails must contain (EU AI Act is general; no agent-specific audit requirements).

**Gap trajectory:** Wide open. Mostly industry blog posts and high-level guidance; very little peer-reviewed research on agent-specific forensics.

---

## 14. Deception-Based Defenses for Agents

**Maturity: Immature (but one notable paper)**

### What EXISTS

**Research:**
- **"Cloak, Honey, Trap" (CHeaT)** (USENIX Security 2025) -- Proactive defenses against LLM agents using string-based payloads embedded in network assets. Three defense types: cloaks (obscure/mislead), honey (lure with fake credentials/URLs), traps (disrupt/detect). After 5 random trap techniques, defense success rate >95% against strongest LLM model (Llama 3.1-70B). Key finding: even when payload is obviously a trap, LLMs often follow through.
- **LLM Agent Honeypot** (arXiv 2410.13919, Oct 2024) -- SSH honeypot augmented with prompt injection and time-based analysis to detect LLM agents among attackers. Detection precision 83.3%. Deployed for 3 months; 8M+ SSH interactions; found only ~7 potential AI agent attackers.
- **CyberArk function-calling trap** (2025 blog) -- Leverages LLM function calling mechanism as a defense layer to catch unauthorized invocations.

**General deception technology (not agent-specific):**
- SPADE (arXiv 2501.00940, Jan 2025) -- GenAI-driven adaptive cyber deception using structured prompt engineering.
- Extensive honeypot/honeytoken literature (traditional cyber deception) -- market projected $5.6B by 2032.

### What is MISSING
- **Honeytokens specifically designed for agent memory.** No work places canary data in agent memory to detect memory poisoning or unauthorized memory access.
- **Canary tools / trap tools.** No published work creates decoy tools that appear in an agent's tool list specifically to detect prompt injection (a tool that should never be called under normal operation; if called, indicates compromise). The CyberArk blog touches on this but is not a peer-reviewed paper.
- **Deception for multi-agent systems.** CHeaT targets single agents attacking networks. No work on placing deception elements within multi-agent communication to detect compromised agents.
- **Adaptive deception for agents.** CHeaT uses static payloads. No work on deception that adapts based on the agent's behavior.
- **Theoretical foundations.** No game-theoretic or decision-theoretic analysis of deception-based defenses specifically for LLM agents.

**Gap trajectory:** Wide open despite CHeaT. CHeaT defends networks against agent attackers; deception defending agents themselves (honeytokens in memory, canary tools in tool lists) is nearly untouched.

---

## 15. Benchmarks and Evaluation Frameworks for Agent Security

**Maturity: Growing**

### What EXISTS

**Comprehensive benchmarks:**
- **Agent Security Bench (ASB)** (ICLR 2025) -- 10 scenarios, 10 agents, 400+ tools, 27 attack/defense methods, 7 metrics. Covers DPI, IPI, memory poisoning, PoT backdoor attacks, mixed attacks. Found highest average attack success rate of 84.30%.
- **AgentHarm** (ICLR 2025) -- 110 malicious tasks (440 with augmentations), 11 harm categories. Available on HuggingFace.
- **SafeAgentBench** (Dec 2024) -- 750 tasks, 10 hazards, embodied environments. 17 high-level actions, 8 baselines.
- **Agent-SafetyBench** (Tsinghua, Dec 2024) -- Safety evaluation for LLM agents.
- **Hidden-in-Plain-Text** (Jan 2026) -- Benchmark for social-web IPI in RAG.

**Red-teaming frameworks:**
- **SuperClaw** (late 2025) -- Open-source framework to red-team AI agents for adversarial behavior testing.
- **GOAT** (Pavlova et al., 2024) -- Automated agentic red-teaming with adaptive multi-turn strategies.
- **DeepTeam** (Nov 2025) -- Jailbreaking and prompt injection testing for LLM systems.
- **Garak** (Nvidia) -- LLM vulnerability scanning.
- **h4rm3l** (Doumbouya et al., 2025) -- Composable language for jailbreak attack synthesis.

**Industry frameworks:**
- **OWASP Top 10 for Agentic Applications** (Dec 2025) -- 10 risk categories with mitigations; 100+ expert contributors.
- Meta's **"Agents Rule of Two"** (Oct 2025) -- Guardrails must live outside the LLM.

### What is MISSING
- **Unified evaluation methodology.** ASB, AgentHarm, and SafeAgentBench each use different metrics, threat models, and evaluation criteria. No meta-benchmark or standardized evaluation protocol allows comparing results across benchmarks.
- **Dynamic/adaptive benchmarks.** All current benchmarks are static test sets. No benchmark adapts to the agent being tested (like an adaptive adversary that changes tactics based on agent behavior).
- **Real-world deployment benchmarks.** All benchmarks use simulated environments. No benchmark evaluates agent security in production-like settings with real tools and real data.
- **Defense effectiveness benchmarks.** Most benchmarks focus on attack success. No standardized way to evaluate and compare defense mechanisms head-to-head.
- **Longitudinal benchmarks.** No benchmark evaluates security over time (e.g., does an agent become more vulnerable as its memory accumulates?).
- **Coverage gaps:** No benchmark covers inter-agent communication attacks, cascading failures, cross-lingual attacks, or deception-based defenses.

**Gap trajectory:** Narrowing for basic attack benchmarks. Wide open for defense evaluation, longitudinal testing, and coverage of advanced threat models.

---

## Summary Table

| # | Area | Maturity | Gap Width | Trajectory |
|---|------|----------|-----------|------------|
| 1 | Prompt injection defense (agents) | Growing | Medium | Narrowing fast |
| 2 | Memory poisoning | Growing (early) | Wide | Stable |
| 3 | Tool misuse | Growing | Medium | Narrowing |
| 4 | Identity/privilege abuse | Growing (early) | Wide | Narrowing moderately |
| 5 | Malicious tool/plugin detection | Growing (MCP) | Medium | Narrowing fast (MCP) |
| 6 | Inter-agent communication security | Immature | Very wide | Stable |
| 7 | Cascading failures | Immature | Very wide | Wide open |
| 8 | Behavioral monitoring | Immature (growing) | Wide | Narrowing |
| 9 | Cross-lingual attacks on agents | Immature | Very wide | Wide open |
| 10 | Indirect prompt injection (RAG) | Growing | Medium-narrow | Narrowing fast |
| 11 | Output safety / data leakage | Growing (chatbot) | Wide (agents) | Moderately narrowing |
| 12 | Permission/scope management | Growing (early) | Wide | Narrowing moderately |
| 13 | Forensics / audit trails | Immature | Very wide | Wide open |
| 14 | Deception-based defenses | Immature | Very wide | Wide open |
| 15 | Benchmarks/evaluation | Growing | Medium | Narrowing |

---

## Top Thesis-Worthy Gaps (Widest + Most Stable)

1. **Cascading failure modeling and containment in multi-agent systems** (Area 7) -- Nearly zero dedicated research. Formal models, circuit breakers, and benchmarks are all missing.

2. **Cross-lingual attacks on tool-using agents** (Area 9) -- The intersection of multilingual attacks and agent security is completely untouched. Every existing benchmark is English-only.

3. **Deception-based defenses designed for agents** (Area 14) -- Canary tools, honeytokens in agent memory, and deception within multi-agent communication have no published work.

4. **Agent forensics and tamper-proof audit trails** (Area 13) -- Only blog posts and high-level guidance exist. No peer-reviewed work on agent-specific forensic reconstruction, causal attribution, or standardized trace formats.

5. **Inter-agent trust and authenticated communication** (Area 6) -- Attacks are well-demonstrated (Prompt Infection, AiTM); defenses are theoretical position papers only. No implemented trust protocols in any major framework.

6. **Memory poisoning defenses and delayed-trigger attacks** (Area 2) -- Attacks are advancing rapidly; defenses are primitive (input/output gating only). Delayed activation and multi-session coordinated poisoning are unstudied.

7. **Agent-specific output safety** (Area 11) -- Current tools handle text; agent outputs (tool calls, API requests, code, SQL) are unmonitored.

---

## Sources

### Area 1: Prompt Injection Defense
- [Log-To-Leak (OpenReview 2025)](https://openreview.net/forum?id=UVgbFuXPaO)
- [ToolHijacker / Prompt Injection Attack to Tool Selection (arXiv)](https://arxiv.org/abs/2504.19793)
- [The Attacker Moves Second (Simon Willison)](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- [MELON: Provable Defense Against IPI (OpenReview)](https://openreview.net/forum?id=gt1MmGaKdZ)
- [PromptArmor (arXiv)](https://arxiv.org/html/2507.15219v1)
- [Multi-Agent LLM Defense Pipeline (arXiv)](https://arxiv.org/html/2509.14285v4)
- [Comprehensive Review -- MDPI](https://www.mdpi.com/2078-2489/17/1/54)
- [From Prompt Injections to Protocol Exploits (ScienceDirect)](https://www.sciencedirect.com/science/article/pii/S2405959525001997)

### Area 2: Memory Poisoning
- [MINJA: A Practical Memory Injection Attack (arXiv)](https://arxiv.org/html/2503.03704v2)
- [MemoryGraft (arXiv)](https://arxiv.org/abs/2512.16962)
- [InjecMEM (OpenReview)](https://openreview.net/forum?id=QVX6hcJ2um)
- [Memory Poisoning Attack and Defense (arXiv)](https://arxiv.org/abs/2601.05504)
- [Palo Alto Unit42 -- When AI Remembers Too Much](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/)
- [Lakera -- Agentic AI Threats P1](https://www.lakera.ai/blog/agentic-ai-threats-p1)

### Area 3: Tool Misuse
- [AgentHarm (ICLR 2025)](https://arxiv.org/abs/2410.09024)
- [SafeAgentBench (arXiv)](https://arxiv.org/abs/2412.13178)
- [Agent-SafetyBench (arXiv)](https://arxiv.org/abs/2412.14470)
- [TrustAgent (EMNLP Findings 2024)](https://aclanthology.org/2024.findings-emnlp.585.pdf)
- [The Emerged Security and Privacy of LLM Agent (ACM Computing Surveys)](https://dl.acm.org/doi/full/10.1145/3773080)

### Area 4: Identity and Privilege Abuse
- [MAC Framework for LLM Agents (arXiv)](https://arxiv.org/html/2601.11893v1)
- [MiniScope (arXiv)](https://arxiv.org/pdf/2512.11147)
- [CELLMATE (arXiv)](https://arxiv.org/pdf/2512.12594)
- [Probabilistic Authorization Framework (ACM)](https://dl.acm.org/doi/pdf/10.1145/3773276.3776564)
- [Securing AI Agent Execution (arXiv)](https://arxiv.org/pdf/2510.21236)

### Area 5: Malicious Tool/Plugin Detection
- [MCPGuard (arXiv)](https://arxiv.org/pdf/2510.23673)
- [Cisco MCP Scanner (Blog)](https://blogs.cisco.com/ai/securing-the-ai-agent-supply-chain-with-ciscos-open-source-mcp-scanner)
- [Snyk Agent Scan (GitHub)](https://github.com/snyk/agent-scan)
- [Elastic Security Labs -- MCP Attack Vectors](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Timeline of MCP Breaches (AuthZed)](https://authzed.com/blog/timeline-mcp-breaches)
- [Adversa AI MCP Security Digest](https://adversa.ai/blog/mcp-security-digest-july-2025/)

### Area 6: Inter-Agent Communication Security
- [Red-Teaming Multi-Agent Systems (ACL Findings 2025)](https://aclanthology.org/2025.findings-acl.349/)
- [Prompt Infection (arXiv)](https://arxiv.org/abs/2410.07283)
- [Morris II (arXiv)](https://arxiv.org/abs/2403.02817)
- [Trust Paradox in MAS (arXiv)](https://arxiv.org/html/2510.18563v1)
- [CA-MCPQ (ePrint)](https://eprint.iacr.org/2025/1790.pdf)
- [AgentCrypt (ePrint)](https://eprint.iacr.org/2025/2216.pdf)
- [BlockA2A (arXiv)](https://arxiv.org/html/2508.01332v1)
- [DID/VC for AI Agents (arXiv)](https://arxiv.org/pdf/2511.02841)
- [TRiSM for Agentic AI (arXiv)](https://arxiv.org/html/2506.04133v2)
- [Open Challenges in Multi-Agent Security (arXiv)](https://arxiv.org/html/2505.02077v1)

### Area 7: Cascading Failures
- [Gradient Institute Risk Analysis (arXiv)](https://www.arxiv.org/pdf/2508.05687)
- [AgentAsk (arXiv)](https://arxiv.org/html/2510.07593v1)
- [AWS Agentic AI Security Scoping Matrix](https://aws.amazon.com/blogs/security/the-agentic-ai-security-scoping-matrix-a-framework-for-securing-autonomous-ai-systems/)
- [Galileo -- Why Multi-Agent Systems Fail](https://galileo.ai/blog/multi-agent-ai-failures-prevention)

### Area 8: Behavioral Monitoring
- [TraceAegis (arXiv)](https://arxiv.org/abs/2510.11203)
- [SentinelAgent (arXiv)](https://arxiv.org/abs/2505.24201)
- [LLM Guard (Protect AI)](https://protectai.com/llm-guard)
- [Awesome Agent Security (GitHub/UCSB)](https://github.com/ucsb-mlsec/Awesome-Agent-Security)

### Area 9: Cross-Lingual Attacks
- [MultiJail (Deng et al., 2024)](https://aclanthology.org/2024.findings-acl.156.pdf)
- [Cross-Lingual Prompt Steerability (arXiv)](https://arxiv.org/abs/2512.02841)
- [LinguaSafe (arXiv)](https://arxiv.org/html/2508.12733)
- [Multilingual Prompt Injection (Medium/Nwosu)](https://nwosunneoma.medium.com/multilingual-prompt-injection-your-llms-safety-net-has-a-language-problem-440d9aaa8bac)

### Area 10: Indirect Prompt Injection (RAG)
- [Instruction Detection Defense (arXiv)](https://arxiv.org/html/2505.06311v2)
- [Securing AI Agents Against PI (arXiv)](https://arxiv.org/abs/2511.15759)
- [When AI Meets the Web (IEEE S&P 2026)](https://arxiv.org/html/2511.05797v1)
- [Hidden-in-Plain-Text (arXiv)](https://arxiv.org/html/2601.10923)
- [Indirect PI in the Wild (arXiv)](https://arxiv.org/pdf/2601.07072)
- [Benchmarking and Defending IPI (ACM KDD 2025)](https://dl.acm.org/doi/10.1145/3690624.3709179)

### Area 11: Output Safety
- [LLM Guard (Protect AI)](https://protectai.com/llm-guard)
- [Nightfall AI DLP](https://www.nightfall.ai/ai-security-101/data-leakage-prevention-dlp-for-llms)
- [Palo Alto Unit42 Guardrail Comparison](https://unit42.paloaltonetworks.com/comparing-llm-guardrails-across-genai-platforms/)

### Area 12: Permission/Scope Management
- [Systems Security Foundations for Agentic Computing (ePrint)](https://eprint.iacr.org/2025/2173.pdf)
- [ACE Architecture (arXiv)](https://arxiv.org/pdf/2504.20984)
- [Action Restrictions and Permissions (Brenndoerfer)](https://mbrenndoerfer.com/writing/action-restrictions-and-permissions-ai-agents)

### Area 13: Forensics/Audit Trails
- [TraceAegis (arXiv)](https://arxiv.org/abs/2510.11203)
- [ProvSEEK (arXiv)](https://arxiv.org/html/2508.21323v1)
- [ISACA -- Auditing Agentic AI](https://www.isaca.org/resources/news-and-trends/industry-news/2025/the-growing-challenge-of-auditing-agentic-ai)
- [Galileo -- Agent Compliance & Governance](https://galileo.ai/blog/ai-agent-compliance-governance-audit-trails-risk-management)
- [MCP Audit Logging (Tetrate)](https://tetrate.io/learn/ai/mcp/mcp-audit-logging)
- [FireTail AI Audit Trail](https://www.firetail.ai/complete-ai-audit-trail)

### Area 14: Deception-Based Defenses
- [Cloak, Honey, Trap (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/ayzenshteyn)
- [LLM Agent Honeypot (arXiv)](https://arxiv.org/abs/2410.13919)
- [LLM Agent Honeypot Project Site](https://ai-honeypot.palisaderesearch.org/)
- [CyberArk Function-Calling Defense (Blog)](https://medium.com/cyberark-engineering/catching-the-uninvited-leveraging-the-llm-function-calling-mechanism-as-a-seamless-defense-layer-98ca07028ce2)
- [SPADE GenAI Deception (arXiv)](https://arxiv.org/html/2501.00940v1)

### Area 15: Benchmarks/Evaluation
- [Agent Security Bench / ASB (ICLR 2025)](https://arxiv.org/abs/2410.02644)
- [AgentHarm (ICLR 2025)](https://arxiv.org/abs/2410.09024)
- [SafeAgentBench (arXiv)](https://arxiv.org/abs/2412.13178)
- [SuperClaw (CybersecurityNews)](https://cybersecuritynews.com/superclaw-red-team-ai-agent/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Agentic AI Security Survey (arXiv)](https://arxiv.org/html/2510.23883v1)
- [CaMeL (Google DeepMind)](https://arxiv.org/html/2601.09923v2)
- [IsolateGPT/SecGPT (NDSS 2025)](https://arxiv.org/abs/2403.04960)

---

## Disclaimer

This analysis was conducted via web search on March 15, 2026. Papers cited are based on search results and may have been updated or superseded. Some papers found only as preprints (arXiv) may not have undergone peer review. The "maturity" ratings are subjective assessments based on the volume and depth of published work found. Where search results were ambiguous or incomplete, this is noted. No papers or tools were invented; if something could not be verified, it was omitted or marked with uncertainty.
