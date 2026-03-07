# Skill Security Auditor

Multi-dimension security scoring engine for [OpenClaw](https://openclaw.ai) skills.

Analyzes skill directories and produces a **0-100 composite score** across 6 security dimensions, with letter grades (A–F), detailed findings, and actionable improvement recommendations.

## Quick Start

```bash
# Audit a single skill
python scripts/audit_skill.py ~/.openclaw/skills/my-skill

# Batch audit all installed skills
python scripts/audit_skill.py --scan-dir ~/.openclaw/skills

# JSON output for CI/CD integration
python scripts/audit_skill.py ~/.openclaw/skills/my-skill --json
```

## Scoring Dimensions

1. **Permission Scope** (25 pts) — Declared tool permissions, binary requirements
2. **Network Exposure** (20 pts) — External URLs, network commands, API libraries
3. **Code Execution** (20 pts) — eval/exec, subprocess, privilege escalation, obfuscation
4. **Data Handling** (15 pts) — Hardcoded credentials, exfiltration risk patterns
5. **Supply Chain** (10 pts) — Provenance tracking, homepage, directory structure
6. **Transparency** (10 pts) — Description quality, safety documentation, code readability

See [references/scoring.md](references/scoring.md) for detailed scoring rules.

## Grades

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Safe |
| B | 75-89 | Low Risk |
| C | 60-74 | Medium Risk |
| D | 40-59 | High Risk |
| F | < 40 | Dangerous |

## Requirements

- Python 3.8+
- Zero external dependencies (stdlib only)

## Design Principles

- **Read-only**: Never executes or modifies scanned code
- **Offline**: No network access needed
- **Zero-dependency**: Python stdlib only
- **Safe output**: Never leaks detected credentials into reports

## Project Structure

```
skill-security-auditor/
├── SKILL.md              # OpenClaw skill definition
├── README.md             # This file
├── .gitignore
├── scripts/
│   └── audit_skill.py    # Core audit engine
├── tests/
│   └── test_audit.py     # Comprehensive test suite
└── references/
    └── scoring.md        # Detailed scoring documentation
```

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Or without pytest
python -m unittest tests.test_audit -v
```

## License

MIT
