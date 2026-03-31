# arXiv Submission — Agent Control Protocol

## Files

- `main.tex` — LaTeX source (complete paper)
- `references.bib` — BibTeX bibliography (13 entries)
- `SUBMIT.md` — This file

## Compile locally (verify before submitting)

Requires: TeX Live, MiKTeX, or MacTeX.

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

Output: `main.pdf` (~18-20 pages)

## arXiv submission steps

1. **Create account**: https://arxiv.org/register
   - Requires institutional email or endorsement
   - First submission to cs.CR may need endorsement from an existing arXiv author

2. **Submit**:
   - Go to https://arxiv.org/submit
   - Upload: zip file containing `main.tex` + `references.bib`
   - arXiv will compile automatically

3. **Metadata**:
   - **Title**: Agent Control Protocol: Admission Control for Agent Actions
   - **Authors**: Marcelo Fernandez (TraslaIA)
   - **Primary category**: cs.CR (Cryptography and Security)
   - **Secondary category**: cs.AI (Artificial Intelligence)
   - **Comments**: 20 pages. DOI: 10.5281/zenodo.XXXXXXX (update after Zenodo v1.22 upload). Specification repository: https://github.com/chelof100/acp-framework-en
   - **MSC class**: (leave blank for cs papers)
   - **Report number**: TraslaIA-ACP-2026-001 (optional)

4. **Abstract** (plain text, paste this):

```
Autonomous agents can produce harmful behavioral patterns from individually
valid requests---a threat class that per-request policy evaluation cannot
address, because stateless engines evaluate each request in isolation and cannot
enforce properties that depend on execution history.
We present ACP, a temporal admission control protocol that enforces behavioral
properties over execution traces by combining static risk scoring with stateful
signals (anomaly accumulation, cooldown) through a LedgerQuerier abstraction
separating decision logic from state management.
We demonstrate that this structural separation has measurable security
consequences: under a 500-request workload where every request is individually
valid (RS=35), a stateless engine with identical scoring approves all 500 requests,
while ACP limits autonomous execution to 2 out of 500 (0.4%), escalating after
3 actions and enforcing denial after 11---isolating the structural gap between
stateless and stateful admission.
We identify a bounded state-mixing vulnerability in ACP-RISK-2.0: agents
executing high-frequency benign operations in one context can inadvertently
elevate risk scores in unrelated high-value contexts due to agent-level
rate aggregation---producing false denials that a stateless engine would
never generate (Experiment 6).
We introduce ACP-RISK-3.0, which eliminates this cross-context interference
by scoping rate-based anomaly signals to the interaction context via
PatternKey(agentID, capability, resource), while preserving enforcement:
repeated behavior within a single context continues to trigger denial at the
same threshold (Experiment 7).
Decision evaluation runs at 767--921 ns (p50); throughput reaches 920,000 req/s
under moderate concurrency, degrading predictably with backend latency without
protocol changes.
Safety and liveness properties are model-checked via TLC-runnable TLA+
(9 invariants + 4 temporal properties, 0 violations across 5,684,342 states)
and validated at runtime by 73 signed conformance test vectors.

Specification and implementation: https://github.com/chelof100/acp-framework-en
```

## Notes on endorsement

arXiv cs.CR requires endorsement for first-time submitters.
Options:
- Ask a colleague who has submitted to cs.CR before
- Submit to cs.AI first (sometimes easier for first submission)
- Contact arXiv directly: help@arxiv.org

## After acceptance

- arXiv assigns an ID in format: 2026.XXXXX [cs.CR]
- Add arXiv ID to paper/draft/ACP-Whitepaper-v1.0.md references
- Add arXiv link to README.md in the repo
- Add arXiv link to agentcontrolprotocol.xyz/specification.html
