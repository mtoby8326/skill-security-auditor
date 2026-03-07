# Roadmap — Skill Security Auditor

## Current: v0.2.0 (Released 2026-03-07)

Context-aware scanning, finding deduplication, false positive fixes, new detections.

### Key Metrics
- 110 tests passing
- Notion: C/61.5 → B/86.5 (doc penalty paradox resolved)
- Weather-CN: 11 → 6 findings
- Obsidian: stable at B/84.0

---

## v0.3.0 — System Robustness

**Goal**: Make the auditor production-ready with defensive scanning and user control.

### Features
- **`.auditignore` support**: Gitignore-like syntax to mark known-safe patterns
  - Per-skill `.auditignore` file
  - Pattern format: `# dimension:pattern` (e.g., `network:api.weather.com`)
- **Scan safety limits**:
  - Max file size: 1MB per file
  - Max directory depth: 10 levels
  - Max file count: 500 per skill
  - Graceful warnings when limits hit
- **Incremental scan cache**:
  - Cache based on file mtime in `.audit_cache.json`
  - Only rescan changed files
  - `--no-cache` to force full scan
- **Output de-noise**:
  - Default: top-N critical findings per dimension
  - `--verbose` for full output (current behavior)
  - `--quiet` for score + grade only
- **New detections**:
  - SSRF: user-controlled URLs passed to network libraries
  - Environment variable injection: `os.environ[x] = y` with user input
  - Symlink attacks: `os.symlink`, `Path.symlink_to`
  - JS prototype pollution: `__proto__`, `constructor.prototype`

---

## v0.4.0 — Scoring Model Optimization

**Goal**: More accurate, fair scoring with graduated severity.

### Features
- **Weight rebalance**:
  - Permission Scope: 25% → 20% (platform sandbox is first defense)
  - Supply Chain: 10% → 15% (provenance is critical trust signal)
  - Others unchanged
- **Graduated severity**:
  - Replace flat `min(1.0, sum)` with: `count_factor = min(1.0, base * (1 + 0.1 * (count - 1)))`
  - 1 subprocess call < 5 subprocess calls < 10 subprocess calls
- **Context-aware scoring**:
  - `subprocess.run(["git", "status"])` → lower risk than `subprocess.run(user_input)`
  - Distinguish GET vs POST network requests
  - Read-only file ops vs destructive ops
- **ReDoS detection**:
  - Flag regex patterns with catastrophic backtracking potential

---

## v0.5.0 — Platform Capabilities

**Goal**: Extensible, configurable, CI/CD-ready.

### Features
- **Plugin architecture**:
  - Dimension scorers register to a `ScorerRegistry`
  - Third-party custom dimensions via `entry_points` or drop-in `.py` files
  - Hook system: `pre_scan`, `post_score`, `pre_report`
- **Configurable security policy**:
  - `audit_policy.json`: weights, thresholds, enabled/disabled checks
  - Organization-level policy templates
  - `--policy <path>` CLI flag
- **Historical comparison**:
  - `--diff <previous_result.json>` mode
  - Shows improved/degraded dimensions, new/resolved findings
  - Trend tracking across versions
- **CI/CD integration**:
  - Exit codes: A/B = 0, C = 1, D/F = 2
  - `--fail-under <score>` flag
  - SARIF output format for GitHub Security tab
  - GitHub Action wrapper

---

## Expert Review Summary (2026-03-07)

### Security Expert Findings
- **P0 (Resolved v0.2.0)**: Doc penalty paradox — good docs led to lower scores
- **P1 (Resolved v0.2.0)**: False positives — re.compile, standalone TOKEN, bare unlink
- **P2 (Partial)**: Detection gaps — path traversal/yaml.load/cmd injection added; SSRF/symlink/env injection planned for v0.3.0
- **P3 (Planned v0.4.0)**: Severity gradient — 1 eval and 10 evals score identically

### Systems Expert Findings
- **S0 (Resolved v0.2.0)**: Negative feedback loop broken by context-aware scanning
- **S1 (Planned v0.4.0)**: Weight rebalancing — Supply Chain underweighted
- **S2 (Planned v0.3.0-v0.5.0)**: Missing capabilities — auditignore, scan limits, cache, plugins, diff mode
