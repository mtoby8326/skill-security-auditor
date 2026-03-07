---
name: skill-security-auditor
description: "Analyze and score the security of OpenClaw skills across 6 dimensions (permission scope, network exposure, code execution risk, data handling, supply chain trust, transparency). Produces a 0-100 score with A/B/C/D/F grade, detailed findings, and actionable recommendations. Use when you want to evaluate whether a skill is safe to install or how to improve your own skill's security posture."
version: 0.1.0
homepage: https://github.com/mtoby8326/skill-security-auditor
allowed-tools: []
---

# Skill Security Auditor

Multi-dimension security scoring engine for OpenClaw skills.

## Usage

### Audit a single skill
```
python scripts/audit_skill.py <skill_path>
```

### Batch audit all skills in a directory
```
python scripts/audit_skill.py --scan-dir <skills_directory>
```

### JSON output (for programmatic consumption)
```
python scripts/audit_skill.py <skill_path> --json
python scripts/audit_skill.py --scan-dir <dir> --json
```

## Scoring Dimensions

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| Permission Scope | 25% | Tool permissions declared in frontmatter |
| Network Exposure | 20% | External URLs, API calls, network libraries |
| Code Execution | 20% | eval/exec, subprocess, privilege escalation |
| Data Handling | 15% | Hardcoded secrets, credential patterns, exfiltration risk |
| Supply Chain | 10% | Provenance tracking, homepage, directory structure |
| Transparency | 10% | Description quality, safety docs, code readability |

## Grade Scale

- **A (90-100)**: Safe — minimal risk, well-documented
- **B (75-89)**: Low Risk — generally safe with minor concerns
- **C (60-74)**: Medium Risk — review findings before use
- **D (40-59)**: High Risk — significant security concerns
- **F (< 40)**: Dangerous — do not install without thorough review

## Safety Rules

- This tool is **read-only** — it never executes or modifies scanned skill code.
- No network access required — all analysis is local.
- No external dependencies — stdlib-only Python.
- Credential patterns detected in scans are **never** included in output verbatim.

## Trigger Phrases

- "audit this skill's security"
- "check skill security score"
- "evaluate skill safety"
- "scan skills for security issues"
- "skill security report"
- "检查skill安全性"
- "skill安全评分"
