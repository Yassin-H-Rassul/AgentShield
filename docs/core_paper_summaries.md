# Core Paper Summaries for AgentShield Thesis

> **Purpose:** Thesis-focused summaries of the 10 core papers. For each: what they did, key findings, and how it relates to AgentShield.
>
> **Last updated:** 2026-03-16

---

## 1. AgentDojo — Your Evaluation Platform

**Full title:** "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents"
**Authors:** Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr (ETH Zurich)
**Venue:** arXiv 2406.13352 (2024)

### What they did
Built an extensible evaluation framework for testing prompt injection attacks and defenses on tool-using LLM agents. The benchmark contains **97 realistic utility tasks** (email, banking, travel) and **629 security test cases**. Unlike static benchmarks, AgentDojo is designed to evolve with new attacks and defenses via a plugin API (`BasePipelineElement`, `PromptInjectionDetector`, `ToolsExecutionLoop`).

### Key findings
- State-of-the-art LLMs fail at many tasks even without attacks (utility is already imperfect).
- Existing prompt injection attacks break some security properties but not all.
- Both attack and defense research have significant room for improvement.

### Relationship to AgentShield
- **This is your evaluation platform.** All experiments run on AgentDojo.
- AgentShield's three defense layers (honeytools, honeytokens, parameter allowlisting) will be registered as custom `BasePipelineElement` defenses.
- Your 80 cross-lingual attacks will be registered as a custom injection suite.
- The built-in defenses (`tool_filter`, `spotlighting_with_delimiting`, `repeat_user_prompt`) serve as comparison baselines.
- **Cite for:** benchmark methodology, baseline metrics, API integration, credibility of standardized evaluation.

### What to reuse
- The full plugin API for adding defense layers and attack suites.
- The 97 utility tasks for false-positive testing (no need to create your own).
- Baseline ASR numbers for comparison tables.

---

## 2. Greshake et al. — Foundational IPI Paper

**Full title:** "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"
**Authors:** Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz
**Venue:** AISec 2023 (arXiv 2302.12173)

### What they did
Introduced and formalized **indirect prompt injection (IPI)** as an attack class. Showed that LLM-integrated applications blur the line between data and instructions — attackers can embed malicious instructions in data the LLM retrieves (websites, emails, documents) without needing direct access. Demonstrated attacks on real-world systems including Bing Chat (GPT-4 powered) and code-completion engines.

### Key findings
- Retrieved prompts function as arbitrary code execution within the LLM context.
- Attacks can steal data, create worms, contaminate information ecosystems, and control API invocations.
- Effective mitigations were "currently lacking" at time of publication.
- Developed a taxonomy of IPI attack vectors and impacts.

### Relationship to AgentShield
- **This is the foundational paper for your entire threat model.** IPI is the core attack AgentShield defends against.
- Your thesis extends their work from LLM-integrated applications to **tool-using agents** specifically.
- Their taxonomy informs your attack categories (data exfiltration, tool misuse, goal hijacking).
- **Cite for:** defining indirect prompt injection, threat model justification, "data ≠ instructions" problem statement.

### What to reuse
- Their definition and taxonomy of IPI (Chapter 2 literature review).
- The argument that "effective mitigations are lacking" — still true in 2026 per the AI Safety Report.

---

## 3. InjecAgent — IPI Benchmark for Tool-Using Agents

**Full title:** "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents"
**Authors:** Qiusi Zhan, Zhixiang Liang, Zifan Ying, Daniel Kang
**Venue:** ACL 2024 Findings (arXiv 2403.02691)

### What they did
Created a benchmark of **1,054 test cases** spanning 17 user-oriented tools and 62 attacker-controlled tools. Evaluated 30 different LLM agents on two attack categories: direct user harm and private data exfiltration. Tested with both baseline attacks and enhanced "hacking prompt" reinforcement.

### Key findings
- ReAct-prompted GPT-4 was vulnerable **24% of the time** to baseline attacks.
- Enhanced attacks with reinforced hacking prompts **nearly doubled** success rates.
- Widespread vulnerability across all tested agent implementations.

### Relationship to AgentShield
- **Provides the "24% vulnerability" statistic** you cite in your introduction.
- Complements AgentDojo: InjecAgent focuses on tool-integrated agents specifically, validating that this is a real and measured problem.
- Their attack categories (user harm + data exfiltration) map to your attack categories.
- **Cite for:** quantifying IPI vulnerability rates, justifying why agent defense is needed, attack categorization.

### What to reuse
- The 24% baseline ASR figure for your introduction/problem statement.
- Their methodology of separating "direct harm" vs "exfiltration" attacks — similar to your 7-category breakdown.

---

## 4. Deng et al. — Multilingual Jailbreak Challenges

**Full title:** "Multilingual Jailbreak Challenges in Large Language Models"
**Authors:** Yue Deng, Wenxuan Zhang, Sinno Jialin Pan, Lidong Bing
**Venue:** ICLR 2024 (arXiv 2310.06474)

### What they did
Systematically studied how non-English prompts bypass LLM safety mechanisms. Identified two scenarios: **unintentional** (users querying in non-English get unsafe responses) and **intentional** (attackers deliberately use multilingual prompts). Proposed a Self-Defense framework for multilingual safety fine-tuning.

### Key findings
- Low-resource languages produce unsafe content **~3× more** than high-resource languages (unintentional scenario).
- Intentional multilingual attacks achieved **80.92% unsafe rate on ChatGPT** and **40.71% on GPT-4**.
- Safety alignment is heavily skewed toward English; other languages are under-protected.
- Self-Defense framework (auto-generating multilingual safety data) reduced harmful outputs.

### Relationship to AgentShield
- **Primary reference for your cross-lingual attack methodology.** Your thesis extends their finding from jailbreaks to IPI in the agent setting.
- Their "low-resource = more vulnerable" finding directly motivates testing Kurdish and Arabic.
- The 3× gap between low- and high-resource languages is a key statistic for your introduction.
- **Cite for:** cross-lingual vulnerability evidence, low-resource language gap, attack design methodology, justifying Kurdish/Arabic testing.

### What to reuse
- Their methodology of comparing attack success across language resource levels.
- The framing of "unintentional vs intentional" cross-lingual exploitation.
- Statistics for your Chapter 1 (Introduction) and Chapter 2 (Literature Review).

---

## 5. Al Ghanim et al. — Arabic Transliteration Jailbreak

**Full title:** "Jailbreaking LLMs with Arabic Transliteration and Arabizi"
**Authors:** Mansour Al Ghanim, Saleh Almohaimeed, Mengxin Zheng, Yan Solihin, Qian Lou
**Venue:** EMNLP 2024 (arXiv 2406.18725)

### What they did
Tested jailbreaks using Arabic transliteration and Arabizi (Arabic chatspeak, e.g., writing Arabic words in Latin script with numbers for Arabic-specific sounds). Found that standard Arabic with manipulation was insufficient, but **transliteration and Arabizi successfully produced unsafe content** on GPT-4 and Claude 3 Sonnet.

### Key findings
- Standard Arabic + prefix injection did NOT consistently bypass safety.
- Arabic transliteration (Arabizi) **did** bypass safety on GPT-4 and Claude 3 Sonnet.
- Models have "learned connections to specific words" — alternate linguistic forms exploit these gaps.
- Safety measures are language-specific and do not generalize to transliterated forms.

### Relationship to AgentShield
- **Direct reference for your transliteration attack technique.** You extend their Arabizi methodology to Kurdish (Sorani).
- Their finding that transliteration bypasses safety validates your attack category: transliteration attacks in your 80-prompt suite.
- The mechanism (models learn word-specific safety associations that don't transfer to transliterated forms) explains WHY cross-lingual attacks work.
- **Cite for:** transliteration attack design, extending to Kurdish, Arabic-specific attack methodology, Arabizi bypass evidence.

### What to reuse
- Their Arabizi methodology — adapt it for Kurdish Latin script transliteration.
- Their AdvBench-based evaluation approach for your transliteration attack category (8 prompts).
- The explanation of WHY transliteration bypasses safety (Chapter 5 Discussion).

---

## 6. Ayzenshteyn et al. — CHeaT (Cloak, Honey, Trap)

**Full title:** "Cloak, Honey, Trap: Proactive Defenses Against LLM Agents"
**Authors:** Daniel Ayzenshteyn, Roy Weiss, Yisroel Mirsky (Ben Gurion University of the Negev)
**Venue:** USENIX Security 2025

### What they did
Built a framework of **6 defensive strategies and 15 techniques** using deception against autonomous LLM-based penetration testing tools. Techniques include cloaking (misdirection to obscure assets), honey-tokens (LLM-specific decoys), and traps (loops to neutralize agents). Also demonstrated novel exploits: inducing agents to execute untrusted code, potentially giving defenders access to attacker infrastructure. Released CHeaT as an open-source tool.

### Key findings
- Achieved **100% success rate** in protecting across 11 CTF test machines.
- Most techniques work without prompt injection (broader applicability).
- Deception is highly effective against LLM agents because of their biases, memory limitations, and tokenization issues.
- LLM agents are susceptible to decoys and misdirection in ways traditional attackers may not be.

### Relationship to AgentShield
- **CRITICAL related work — OPPOSITE threat model.** CHeaT defends networks FROM LLM agents; AgentShield defends agents FROM injection.
- Both use deception (honeytools, honeytokens), but in opposite directions.
- Their success validates that deception works against LLMs — your thesis applies the same principle but to protect the agent itself.
- You MUST cite this paper prominently and clearly explain the different threat models.
- **Cite for:** deception effectiveness against LLMs, related work (opposite direction), honeytool/honeytoken concept validation, distinguishing your contribution.

### What to reuse
- Their taxonomy of deception techniques — adapt terminology for your agent-defense context.
- The finding that LLMs are susceptible to decoys (supports your honeytool hypothesis).
- Their 100% success rate as evidence that deception-based defense works in principle.
- **Key phrasing:** "CHeaT defends networks from LLM agents; we defend agents from injection. Both leverage LLM susceptibility to deception."

---

## 7. LLM Agent Honeypot — Detecting AI Agents in the Wild

**Full title:** "LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild"
**Authors:** Reworr, Dmitrii Volkov (Palisade Research)
**Venue:** arXiv 2410.13919 (2024)

### What they did
Deployed enhanced SSH honeypots with prompt injection detection and timing analysis to distinguish LLM-powered hacking agents from human attackers. Over 3 months, collected **8,130,731 hacking attempts** and identified **8 potential AI agents**.

### Key findings
- LLM agents are already being deployed for autonomous hacking (small but real).
- Prompt injection + timing analysis can distinguish AI from human attackers.
- The threat of autonomous AI hacking agents is emerging but still nascent.

### Relationship to AgentShield
- **Inverse direction from your work.** They use honeypots to detect AI agents externally; you use honeytools to detect when an agent has been compromised internally.
- Both use deception-based detection, but in completely different settings.
- Their work proves that prompt injection can be used as a detection signal — you use a similar principle (if an agent calls a honeytool, something prompted it to).
- **Cite for:** deception-based AI agent detection (inverse direction), related work, evidence that deception signals work for detecting LLM behavior.

### What to reuse
- Their concept of using prompt injection as a detection mechanism (conceptual parallel to your honeytool approach).
- **Key phrasing:** "LLM Agent Honeypot detects AI agents externally; AgentShield detects agent compromise internally. Both leverage deception as a detection signal."

---

## 8. DataSentinel — Game-Theoretic Prompt Injection Detection

**Full title:** "DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks"
**Authors:** Yupei Liu, Yuqi Jia, Jinyuan Jia, Dawn Song, Neil Zhenqiang Gong
**Venue:** IEEE S&P 2025 — **Distinguished Paper Award** (arXiv 2504.11358)

### What they did
Formulated prompt injection detection as a **minimax optimization problem**. Fine-tuned an LLM to detect injected prompts using adversarial training: alternating between inner maximization (attacker finding evasion strategies) and outer minimization (detector improving robustness). Evaluated across multiple benchmarks and LLMs.

### Key findings
- Outperforms existing detection methods on conventional and adaptive attacks.
- Game-theoretic formulation makes the detector robust against adaptive adversaries.
- Operates at the **input screening layer** — detects contaminated inputs before they reach the LLM.
- Won Distinguished Paper Award at IEEE S&P 2025 (top venue).

### Relationship to AgentShield
- **Different layer, complementary approach.** DataSentinel screens inputs; AgentShield operates at the tool/output level.
- DataSentinel uses known-answer detection (input screening); your honeytools detect compromise through behavior (tool calls).
- Their adaptive adversary methodology informs your "adaptive attacks" category (attacks designed to evade detection).
- A combined system (DataSentinel for input + AgentShield for tool-level) could be mentioned as future work.
- **Cite for:** state-of-the-art in prompt injection detection, distinguishing your contribution (different layer), comparison in related work, adaptive adversary methodology.

### What to reuse
- Their adaptive adversary concept for your 16 adaptive attack prompts.
- Comparison point: "DataSentinel operates at input screening; AgentShield operates at tool execution — these are complementary layers."
- **Key phrasing:** "DataSentinel detects injected inputs; AgentShield detects compromised behavior. These operate at different layers and could be combined."

---

## 9. Boucher et al. — Bad Characters / Imperceptible Attacks

**Full title:** "Bad Characters: Imperceptible NLP Attacks"
**Authors:** Nicholas Boucher, Ilia Shumailov, Ross Anderson, Nicolas Papernot
**Venue:** IEEE S&P 2022 (arXiv 2106.09898)

### What they did
Demonstrated adversarial attacks using **encoding-specific perturbations invisible to the human eye**: invisible Unicode characters, homoglyphs (visually similar characters from different scripts), character reordering, and deletions. Attacks are black-box and require no model knowledge. Tested against systems from Microsoft, Google, Facebook, IBM, and HuggingFace.

### Key findings
- A **single** imperceptible encoding injection can significantly degrade model performance.
- **Three** injections can render most tested models "functionally broken."
- Attacks work across diverse NLP systems: translation, search, classification.
- "Text-based NLP systems require careful input sanitization, just like conventional applications."

### Relationship to AgentShield
- **Foundation for your zero-width character and homoglyph attack categories.**
- Their invisible Unicode and homoglyph techniques directly inform your attack design:
  - Zero-width attacks (4 prompts): Unicode Tags block (U+E0000-U+E007F)
  - Homoglyph attacks (4 prompts): Arabic↔Latin character substitution (e.g., Arabic ه vs Latin h)
- Their finding that single injections degrade models supports the plausibility of your encoding-based attacks.
- **Cite for:** zero-width character attack methodology, homoglyph attack concept, evidence that imperceptible perturbations fool NLP systems.

### What to reuse
- Their taxonomy of encoding attacks (invisible characters, homoglyphs, reordering, deletions) — you use the first two.
- The argument that text sanitization is needed — parallels your parameter allowlisting defense layer.
- **Key phrasing:** "Following Boucher et al., we include imperceptible encoding attacks (zero-width characters, homoglyphs) as attack categories to test whether AgentShield's defenses are robust to visually undetectable injections."

---

## 10. Liu et al. — Formalizing Prompt Injection Attacks and Defenses

**Full title:** "Formalizing and Benchmarking Prompt Injection Attacks and Defenses"
**Authors:** Yupei Liu, Yuqi Jia, Runpeng Geng, Jinyuan Jia, Neil Zhenqiang Gong
**Venue:** USENIX Security 2024

### What they did
Created the first formal framework for prompt injection attacks, showing that existing attacks are special cases within their model. Designed a novel attack by combining elements from existing approaches. Conducted **systematic evaluation** across 5 attacks × 10 defenses × 10 LLMs × 7 tasks. Released an open-source benchmark (Open-Prompt-Injection on GitHub).

### Key findings
- Provided a unified formal framework that encompasses all known prompt injection attacks.
- Novel combined attack outperforms individual existing attacks.
- Systematic evaluation revealed that no single defense works well across all scenarios.
- Established a common benchmark for quantitative evaluation of future work.

### Relationship to AgentShield
- **Methodological reference for systematic evaluation design.** Their approach of crossing attacks × defenses × models × tasks directly parallels your experiment matrix (80 attacks × 3 conditions × 2 models).
- Their formal framework helps position your work: AgentShield adds a new defense category (deception-based) to their taxonomy.
- Their finding that "no single defense works well across all scenarios" supports your multi-layer approach.
- **Cite for:** formal framework for prompt injection, systematic evaluation methodology, benchmark design, "no single defense" finding that motivates multi-layer defense.

### What to reuse
- Their evaluation methodology: the matrix of attacks × defenses × models × tasks.
- The "no single defense" finding to motivate your three-layer approach (Chapter 1 & 5).
- Their formal framework as background in Chapter 2.
- **Key phrasing:** "Following Liu et al.'s systematic evaluation methodology, we test AgentShield across multiple attack categories, defense conditions, and models."

---

## Summary: How These Papers Map to Your Thesis

| Paper | Thesis Role | Chapter(s) |
|-------|------------|------------|
| AgentDojo | Evaluation platform + API | Ch. 3 (Methodology), Ch. 4 (Results) |
| Greshake et al. | Defines IPI (your threat) | Ch. 1 (Intro), Ch. 2 (Background) |
| InjecAgent | Quantifies IPI in agents | Ch. 1 (Intro), Ch. 2 (Background) |
| Deng et al. | Cross-lingual attack evidence | Ch. 1, Ch. 2, Ch. 3 (Attack design) |
| Al Ghanim et al. | Transliteration attack method | Ch. 2, Ch. 3 (Attack design) |
| CHeaT | Related deception work (opposite) | Ch. 2 (Related work — key distinction) |
| LLM Agent Honeypot | Related deception work (inverse) | Ch. 2 (Related work) |
| DataSentinel | Related defense (different layer) | Ch. 2 (Related work — key distinction) |
| Boucher et al. | Zero-width + homoglyph attacks | Ch. 2, Ch. 3 (Attack design) |
| Liu et al. | Formal framework + evaluation method | Ch. 2 (Background), Ch. 3 (Methodology) |

### Key Distinctions to Maintain

1. **AgentShield vs CHeaT:** Same concept (deception), opposite direction. CHeaT = defend networks FROM agents. AgentShield = defend agents FROM injection.
2. **AgentShield vs DataSentinel:** Complementary layers. DataSentinel = input screening. AgentShield = tool-level behavioral detection.
3. **AgentShield vs LLM Agent Honeypot:** Inverse setting. Honeypot = external detection of AI agents. AgentShield = internal detection of agent compromise.
4. **AgentShield vs Rebuff AI:** Different mechanism. Rebuff = canary tokens for leak detection. AgentShield = honeytools for compromise detection in agent tool calls.
