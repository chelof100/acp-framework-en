# arXiv Submission — Agent Control Protocol

## Files

- `main.tex` — LaTeX source (complete paper)
- `references.bib` — BibTeX bibliography (10 entries)
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
   - **Comments**: 20 pages. Specification repository: https://github.com/chelof100/acp-framework-en
   - **MSC class**: (leave blank for cs papers)
   - **Report number**: TraslaIA-ACP-2026-001 (optional)

4. **Abstract** (plain text, paste this):

```
Agent Control Protocol (ACP) is a formal technical specification for governance of
autonomous agents in B2B institutional environments. ACP is the admission control
layer between agent intent and system state mutation: before any agent action reaches
execution, it must pass a cryptographic admission check that validates identity,
capability scope, delegation chain, and policy compliance simultaneously.

ACP defines the mechanisms of cryptographic identity, capability-based authorization,
deterministic risk evaluation, verifiable chained delegation, transitive revocation,
and immutable auditing that a system must implement for autonomous agents to operate
under explicit institutional control. ACP operates as an additional layer on top of
RBAC and Zero Trust, without replacing them.

The v1.11 specification comprises 36 technical documents organized into five conformance
levels (L1-L5). It includes a Go reference implementation of 22 packages covering all
L1-L4 capabilities, 42 signed conformance test vectors (Ed25519 + SHA-256), and an
OpenAPI 3.1.0 specification for all HTTP endpoints. It defines more than 62 verifiable
requirements, 12 prohibited behaviors, and the mechanisms for interoperability between
institutions.

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
