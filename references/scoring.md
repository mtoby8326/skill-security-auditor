# Scoring Rules Reference

This document details how each security dimension is scored.

## Severity Levels

Each finding has a severity that determines its deduction weight:

- **Critical** (1.0): Immediate security threat — eval/exec, hardcoded secrets, privilege escalation
- **High** (0.6): Significant risk — subprocess calls, unrestricted permissions, obfuscation
- **Medium** (0.3): Notable concern — external network access, long obfuscated lines
- **Low** (0.1): Minor issue — credential references, missing homepage
- **Info** (0.0): Positive signal or neutral observation — no deduction

Deductions are applied as fractions of each dimension's maximum score, capped at 1.0 (full deduction).

---

## D1: Permission Scope (25 pts)

**What**: Evaluates the tool permissions a skill declares.

**Checks**:
- `allowed-tools` frontmatter field present?
- High-risk tools: bash, exec, shell, terminal, computer → -0.15 each
- Medium-risk tools: browser, puppeteer, playwright → -0.08 each
- No `allowed-tools` declared → -0.4 (unrestricted access)
- Dangerous binary requirements (sudo, docker, kubectl, ansible, terraform) → -0.2

**Best practice**: Declare minimum required permissions in `allowed-tools`.

---

## D2: Network Exposure (20 pts)

**What**: Detects external network communication.

**Checks**:
- External URLs (excluding localhost, 127.0.0.1, example.com) → -0.1 per unique domain (max -0.3)
- Network commands (curl, wget, fetch) → -0.05 each (max -0.3)
- Network libraries (requests, urllib, httpx, aiohttp, socket) → -0.08 each (max -0.3)

**Best practice**: Document all external API endpoints in SKILL.md.

---

## D3: Code Execution (20 pts)

**What**: Detects dangerous code execution patterns.

**Checks**:
- `eval()` / `exec()` → Critical (1.0 each)
- subprocess, os.system, os.popen, Popen, shell=True → High (0.6 each)
- Dynamic imports (__import__, importlib) → High (0.6 each)
- File destruction (shutil.rmtree, os.remove, rm -rf) → High (0.6 each)
- Privilege escalation (sudo, runas, chmod 777) → Critical (1.0 each)
- Obfuscation (base64.b64decode, pickle.loads, marshal.loads) → High (0.6 each)

Cumulative deduction capped at 1.0.

**Best practice**: Avoid eval/exec entirely; use specific APIs instead of shell commands.

---

## D4: Data Handling (15 pts)

**What**: Checks for credential exposure and data exfiltration risk.

**Checks**:
- Credential pattern references (API_KEY, TOKEN, SECRET, etc.) → Low (0.1 each)
- Hardcoded credentials (key="long_value") → Critical (1.0 each)
- File read + network access in same file → High (0.6) — potential exfiltration vector
- Declared env var requirements in metadata → Info (positive signal)

**Best practice**: Use environment variables for all credentials; separate file I/O from network logic.

---

## D5: Supply Chain (10 pts)

**What**: Evaluates trust and provenance signals.

**Checks**:
- .clawhub/origin.json or _meta.json present → Info (provenance tracked)
- Missing provenance → Medium (-0.3)
- Homepage URL declared → Info
- Missing homepage → Low (-0.15)
- SKILL.md present → Info (valid skill)
- Missing SKILL.md → Critical (-0.5)

**Best practice**: Publish to ClawHub for provenance tracking.

---

## D6: Transparency (10 pts)

**What**: Measures documentation quality and code readability.

**Checks**:
- No description in frontmatter → High (-0.4)
- Description < 20 chars → Medium (-0.2)
- Safety/security keywords in SKILL.md → Info (documented safety rules)
- No safety documentation → Low (-0.15)
- Lines > 500 chars in code files → Medium (-0.15 per file) — obfuscation signal

**Best practice**: Write detailed descriptions and include a "Safety Rules" section.
