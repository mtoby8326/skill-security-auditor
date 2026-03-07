#!/usr/bin/env python3
"""Skill Security Auditor — multi-dimension security scoring for OpenClaw skills.

Usage:
    python audit_skill.py <skill_path>                # Audit single skill
    python audit_skill.py --scan-dir <skills_dir>     # Batch audit all skills
    python audit_skill.py <skill_path> --json          # JSON output
    python audit_skill.py --scan-dir <dir> --json      # Batch JSON output

Scoring: 6 dimensions → 0-100 composite score → A/B/C/D/F grade.

Stdlib-only. Read-only analysis — never executes scanned code.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VERSION = "0.2.0"

# Dimension weights (must sum to 100)
WEIGHTS = {
    'permission_scope':  25,
    'network_exposure':  20,
    'code_execution':    20,
    'data_handling':     15,
    'supply_chain':      10,
    'transparency':      10,
}

GRADE_THRESHOLDS = [
    (90, 'A', 'Safe'),
    (75, 'B', 'Low Risk'),
    (60, 'C', 'Medium Risk'),
    (40, 'D', 'High Risk'),
    (0,  'F', 'Dangerous'),
]

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# Network patterns
NET_URL = re.compile(r'https?://[^\s\'">\)]+', re.IGNORECASE)
NET_CMD = re.compile(r'\b(curl|wget|httpie)\b|(?<!\w)fetch(?!\w)', re.IGNORECASE)
NET_LIB = re.compile(
    r'\b(requests\.|urllib\.|httpx\.|aiohttp\.|socket\.connect'
    r'|urlopen|http\.client)\b')

# Dangerous execution
EXEC_EVAL = re.compile(r'\b(eval|exec)\s*\(', re.IGNORECASE)
EXEC_SUBPROCESS = re.compile(
    r'\b(subprocess\.|os\.system|os\.popen|Popen|shell=True'
    r'|child_process|spawn|execSync)\b')
EXEC_DYNAMIC = re.compile(
    r'\b(__import__|importlib\.import_module)\b'
    r'|(?<!re\.)\bcompile\s*\(')

# File destruction — require qualified names for unlink/rmdir
FILE_DESTROY = re.compile(
    r'\b(shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir'
    r'|Path\([^)]*\)\.unlink|Path\([^)]*\)\.rmdir)\b'
    r'|rm\s+(-rf?|--force)'
    r'|del\s+/[fqs]'
    r'|Remove-Item\s.*-Recurse', re.IGNORECASE)

# Privilege escalation — tighten net user/localgroup to command context
PRIV_ESC = re.compile(
    r'\bsudo\s|\brunas\s|\bchmod\s+[0-7]*7[0-7]*|\bchmod\s+777'
    r'|(?:^|;|&&|\|)\s*net\s+user\s'
    r'|(?:^|;|&&|\|)\s*net\s+localgroup', re.IGNORECASE | re.MULTILINE)

# Credential patterns — require compound form (prefix + KEY/TOKEN/SECRET)
CRED_PATTERN = re.compile(
    r'\b(API[_\-]?KEY|ACCESS[_\-]?KEY|PRIVATE[_\-]?KEY'
    r'|AUTH[_\-]?TOKEN|API[_\-]?TOKEN|API[_\-]?SECRET'
    r'|[A-Z_]+_TOKEN|[A-Z_]+_SECRET|[A-Z_]+_PASSWORD'
    r'|PASSPHRASE|BEARER)\b', re.IGNORECASE)
CRED_HARDCODE = re.compile(
    r'''(?:api[_-]?key|token|secret|password)\s*[:=]\s*['"][^'"]{8,}['"]''',
    re.IGNORECASE)

# Data exfiltration risk: reading files then sending to network
FILE_READ = re.compile(
    r'\b(open\(|read_text\b|read_bytes\b|readlines\b|Path\([^)]*\)\.read)')

# Obfuscation signals
OBFUSCATION = re.compile(
    r'\b(base64\.b64decode|codecs\.decode|zlib\.decompress'
    r'|marshal\.loads|pickle\.loads)\b')

# --- v0.2.0 new patterns ---
# Path traversal
PATH_TRAVERSAL = re.compile(r'\.\.[\\/]')

# Unsafe deserialization
UNSAFE_YAML = re.compile(r'\byaml\.load\s*\(')
SAFE_YAML = re.compile(r'\byaml\.safe_load\b|Loader\s*=')

# Command injection template: f-string / .format() near subprocess patterns
CMD_INJECTION = re.compile(
    r'(?:subprocess\.\w+|os\.system|os\.popen|Popen)\s*\(\s*f["\']'
    r'|(?:subprocess\.\w+|os\.system|os\.popen|Popen)\s*\([^)]*\.format\s*\(')


# ---------------------------------------------------------------------------
# YAML frontmatter parser (minimal, no pyyaml needed)
# ---------------------------------------------------------------------------
def parse_frontmatter(text):
    """Parse YAML frontmatter from SKILL.md.

    Returns (frontmatter_dict, body_text).
    """
    if not text.startswith('---'):
        return {}, text

    end = text.find('---', 3)
    if end == -1:
        return {}, text

    yaml_block = text[3:end].strip()
    body = text[end + 3:].strip()

    fm = {}
    current_key = None
    for line in yaml_block.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        # Simple key: value parsing
        if ':' in stripped and not stripped.startswith('-'):
            key, _, val = stripped.partition(':')
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            fm[key] = val
            current_key = key
        elif stripped.startswith('-') and current_key:
            # List item — append to current key
            item = stripped.lstrip('- ').strip().strip('"').strip("'")
            if isinstance(fm.get(current_key), list):
                fm[current_key].append(item)
            else:
                fm[current_key] = [fm.get(current_key, ''), item]

    return fm, body


def parse_metadata(fm):
    """Extract metadata.openclaw from frontmatter if present."""
    raw = fm.get('metadata', '')
    if not raw:
        return {}
    # Try JSON parse (inline metadata)
    try:
        meta = json.loads(raw)
        return meta.get('openclaw', meta.get('clawdbot', {}))
    except (json.JSONDecodeError, AttributeError):
        return {}


# ---------------------------------------------------------------------------
# File scanner
# ---------------------------------------------------------------------------
SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.sh', '.bash', '.ps1', '.bat', '.cmd',
    '.rb', '.pl', '.lua', '.go', '.rs', '.md', '.txt', '.json', '.yaml', '.yml',
}


def scan_files(skill_path):
    """Read all text files in a skill directory.

    Returns list of (relative_path, content).
    """
    results = []
    skill_dir = Path(skill_path)

    for fpath in skill_dir.rglob('*'):
        if not fpath.is_file():
            continue
        if fpath.name.startswith('.') and fpath.name not in ('.env',):
            # Still scan .clawhub/origin.json etc
            if '.clawhub' not in str(fpath):
                continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS and fpath.name == 'SKILL.md':
            pass  # always scan SKILL.md
        elif fpath.suffix.lower() not in SCAN_EXTENSIONS:
            continue

        try:
            content = fpath.read_text(encoding='utf-8', errors='replace')
            rel = str(fpath.relative_to(skill_dir))
            results.append((rel, content))
        except OSError:
            continue

    return results


# ---------------------------------------------------------------------------
# Dimension scorers
# ---------------------------------------------------------------------------
class Finding:
    """A single security finding."""
    __slots__ = ('dimension', 'severity', 'message', 'file', 'line')

    def __init__(self, dimension, severity, message, file='', line=0):
        self.dimension = dimension
        self.severity = severity  # 'critical', 'high', 'medium', 'low', 'info'
        self.message = message
        self.file = file
        self.line = line

    def to_dict(self):
        d = {
            'dimension': self.dimension,
            'severity': self.severity,
            'message': self.message,
        }
        if self.file:
            d['file'] = self.file
        if self.line:
            d['line'] = self.line
        return d


SEVERITY_DEDUCT = {
    'critical': 1.0,
    'high': 0.6,
    'medium': 0.3,
    'low': 0.1,
    'info': 0.0,
}


# Context severity downgrade map: (original_severity, context) -> new_severity
_CONTEXT_DOWNGRADE = {
    ('critical', 'doc'):     'low',
    ('critical', 'comment'): 'low',
    ('high',     'doc'):     'info',
    ('high',     'comment'): 'info',
    ('medium',   'doc'):     'info',
    ('medium',   'comment'): 'info',
    ('low',      'doc'):     'info',
    ('low',      'comment'): 'info',
}


def classify_lines(filepath, content):
    """Classify each line as 'code', 'comment', or 'doc'.

    Returns dict mapping line_number -> context_type.
    """
    lines = content.split('\n')
    result = {}

    # SKILL.md: body after frontmatter is documentation
    if filepath.endswith('SKILL.md'):
        fm_count = 0
        for i, line in enumerate(lines, 1):
            if line.strip() == '---':
                fm_count += 1
            if fm_count < 2:
                result[i] = 'meta'
            elif line.strip() == '---' and fm_count == 2:
                result[i] = 'meta'
            else:
                result[i] = 'doc'
        return result

    ext = os.path.splitext(filepath)[1].lower()

    # Python: # comments and triple-quoted docstrings
    if ext == '.py':
        in_docstring = False
        ds_char = None
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if in_docstring:
                result[i] = 'comment'
                if ds_char in stripped:
                    in_docstring = False
                continue
            if stripped.startswith('"""') or stripped.startswith("'''"):
                char = stripped[:3]
                if stripped.count(char) >= 2 and len(stripped) > 3:
                    result[i] = 'comment'  # single-line docstring
                else:
                    in_docstring = True
                    ds_char = char
                    result[i] = 'comment'
                continue
            if stripped.startswith('#'):
                result[i] = 'comment'
            else:
                result[i] = 'code'
        return result

    # JS / TS: // and /* */
    if ext in ('.js', '.ts'):
        in_block = False
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if in_block:
                result[i] = 'comment'
                if '*/' in stripped:
                    in_block = False
                continue
            if stripped.startswith('/*'):
                in_block = True
                if '*/' in stripped:
                    in_block = False
                result[i] = 'comment'
                continue
            if stripped.startswith('//'):
                result[i] = 'comment'
            else:
                result[i] = 'code'
        return result

    # Shell / PowerShell: # comments
    if ext in ('.sh', '.bash', '.ps1'):
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('#'):
                result[i] = 'comment'
            else:
                result[i] = 'code'
        return result

    # Markdown (.md but not SKILL.md): treat as doc
    if ext == '.md':
        for i in range(1, len(lines) + 1):
            result[i] = 'doc'
        return result

    # Default: all code
    for i in range(1, len(lines) + 1):
        result[i] = 'code'
    return result


def _find_in_content(pattern, files, dimension, severity, message_tpl,
                     context_maps=None):
    """Search pattern across files, return findings.

    If context_maps is provided (dict[filepath -> context_map]),
    severity is downgraded for matches in comments/docs.
    """
    findings = []
    for fpath, content in files:
        ctx_map = context_maps.get(fpath, {}) if context_maps else {}
        for i, line_text in enumerate(content.split('\n'), 1):
            for m in pattern.finditer(line_text):
                actual_sev = severity
                ctx = ctx_map.get(i, 'code')
                suffix = ''

                if ctx != 'code':
                    actual_sev = _CONTEXT_DOWNGRADE.get(
                        (severity, ctx), severity)
                    suffix = f' [in {ctx}]'

                msg = message_tpl.format(match=m.group()) + suffix
                findings.append(Finding(
                    dimension, actual_sev, msg, fpath, i))
    return findings


def _deduplicate_findings(findings):
    """Merge duplicate findings: same dimension + base message + file.

    Returns deduplicated list. Merged entries get '(xN)' suffix.
    """
    import re as _re
    groups = {}
    for f in findings:
        # Strip line-specific info and context suffix for grouping
        base_msg = _re.sub(r'\s*\[in (?:doc|comment|meta)\]$', '', f.message)
        base_msg = _re.sub(r': .+$', '', base_msg)  # normalize match detail
        key = (f.dimension, f.severity, base_msg, f.file)
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    result = []
    for key, group in groups.items():
        rep = group[0]
        if len(group) > 1:
            # Keep representative, add count
            new_msg = rep.message
            # Remove existing match detail for cleaner aggregation
            new_msg = _re.sub(r'\s*\[in (?:doc|comment|meta)\]$', '', new_msg)
            new_msg += f' (x{len(group)})'
            result.append(Finding(
                rep.dimension, rep.severity, new_msg, rep.file, rep.line))
        else:
            result.append(rep)
    return result


def score_permission_scope(fm, metadata, files):
    """D1: Permission Scope — what tools does the skill request?"""
    findings = []
    max_score = WEIGHTS['permission_scope']

    has_allowed_key = 'allowed-tools' in fm
    allowed = fm.get('allowed-tools', '')
    if isinstance(allowed, str):
        allowed = [t.strip().strip('"').strip("'")
                   for t in allowed.strip('[]').split(',') if t.strip()]

    # High-risk tools
    HIGH_RISK_TOOLS = {'bash', 'exec', 'shell', 'terminal', 'computer'}
    MEDIUM_RISK_TOOLS = {'browser', 'puppeteer', 'playwright'}
    LOW_RISK_TOOLS = {'file', 'read', 'write', 'grep', 'glob'}

    if not allowed and not has_allowed_key:
        # No allowed-tools declared at all = unrestricted = risky
        findings.append(Finding(
            'permission_scope', 'high',
            'No allowed-tools declared — skill has unrestricted tool access'))
        deduct = 0.4
    elif not allowed and has_allowed_key:
        # Explicitly declared empty = no tools needed = best case
        findings.append(Finding(
            'permission_scope', 'info',
            'Explicitly declared no tool requirements (allowed-tools: [])'))
        deduct = 0.0
    else:
        deduct = 0.0
        declared = {t.lower() for t in allowed}

        high = declared & HIGH_RISK_TOOLS
        med = declared & MEDIUM_RISK_TOOLS

        if high:
            findings.append(Finding(
                'permission_scope', 'medium',
                f'High-risk tools declared: {", ".join(sorted(high))}'))
            deduct += 0.15 * len(high)

        if med:
            findings.append(Finding(
                'permission_scope', 'low',
                f'Medium-risk tools declared: {", ".join(sorted(med))}'))
            deduct += 0.08 * len(med)

        low_only = declared - HIGH_RISK_TOOLS - MEDIUM_RISK_TOOLS
        if low_only and not high and not med:
            findings.append(Finding(
                'permission_scope', 'info',
                f'Only low-risk tools: {", ".join(sorted(low_only))}'))

    # Check requires.bins in metadata
    req_bins = metadata.get('requires', {})
    if isinstance(req_bins, dict):
        bins = req_bins.get('bins', [])
        if bins:
            dangerous_bins = {'sudo', 'docker', 'kubectl', 'ansible', 'terraform'}
            found_danger = set(b.lower() for b in bins) & dangerous_bins
            if found_danger:
                findings.append(Finding(
                    'permission_scope', 'high',
                    f'Dangerous binary requirements: {", ".join(sorted(found_danger))}'))
                deduct += 0.2

    score = max(0.0, 1.0 - deduct)
    return round(score * max_score, 1), findings


def score_network_exposure(fm, metadata, files, context_maps=None):
    """D2: Network Exposure — external URLs, API calls, network libraries."""
    findings = []
    max_score = WEIGHTS['network_exposure']

    urls = set()
    url_in_code = set()  # only count URLs from code context for scoring
    net_cmds = []
    net_libs = []

    for fpath, content in files:
        ctx_map = context_maps.get(fpath, {}) if context_maps else {}
        for i, line_text in enumerate(content.split('\n'), 1):
            ctx = ctx_map.get(i, 'code')
            for m in NET_URL.finditer(line_text):
                url = m.group()
                if any(safe in url.lower() for safe in
                       ['localhost', '127.0.0.1', 'example.com', '::1']):
                    continue
                urls.add(url[:80])
                if ctx == 'code':
                    url_in_code.add(url[:80])

        net_cmds.extend(
            _find_in_content(NET_CMD, [(fpath, content)],
                             'network_exposure', 'medium',
                             'Network command: {match}',
                             context_maps))
        net_libs.extend(
            _find_in_content(NET_LIB, [(fpath, content)],
                             'network_exposure', 'medium',
                             'Network library usage: {match}',
                             context_maps))

    findings.extend(_deduplicate_findings(net_cmds))
    findings.extend(_deduplicate_findings(net_libs))

    # Extract unique domains — only from code context for scoring
    code_domains = set()
    all_domains = set()
    for url in urls:
        try:
            host = url.split('//')[1].split('/')[0].split(':')[0]
            all_domains.add(host)
        except IndexError:
            pass
    for url in url_in_code:
        try:
            host = url.split('//')[1].split('/')[0].split(':')[0]
            code_domains.add(host)
        except IndexError:
            pass

    if all_domains:
        findings.append(Finding(
            'network_exposure',
            'medium' if len(code_domains) <= 2 else 'high',
            f'External domains contacted ({len(all_domains)}): '
            f'{", ".join(sorted(list(all_domains)[:5]))}'))

    # Score based on code-context findings only
    code_cmds = [f for f in net_cmds if '[in' not in f.message]
    code_libs = [f for f in net_libs if '[in' not in f.message]
    deduct = 0.0
    deduct += min(0.3, len(code_domains) * 0.1)
    deduct += min(0.3, len(code_cmds) * 0.05)
    deduct += min(0.3, len(code_libs) * 0.08)

    if not urls and not net_cmds and not net_libs:
        findings.append(Finding(
            'network_exposure', 'info',
            'No network calls detected — offline skill'))

    score = max(0.0, 1.0 - deduct)
    return round(score * max_score, 1), findings


def score_code_execution(fm, metadata, files, context_maps=None):
    """D3: Code Execution Risk — dangerous functions, file ops, privilege escalation."""
    findings = []
    max_score = WEIGHTS['code_execution']

    evals = _find_in_content(EXEC_EVAL, files,
                             'code_execution', 'critical',
                             'Dynamic code execution: {match}',
                             context_maps)
    subprocs = _find_in_content(EXEC_SUBPROCESS, files,
                                'code_execution', 'high',
                                'Subprocess / system call: {match}',
                                context_maps)
    dynamics = _find_in_content(EXEC_DYNAMIC, files,
                                'code_execution', 'high',
                                'Dynamic import: {match}',
                                context_maps)
    destroys = _find_in_content(FILE_DESTROY, files,
                                'code_execution', 'high',
                                'File destruction operation: {match}',
                                context_maps)
    privs = _find_in_content(PRIV_ESC, files,
                             'code_execution', 'critical',
                             'Privilege escalation: {match}',
                             context_maps)
    obfs = _find_in_content(OBFUSCATION, files,
                            'code_execution', 'high',
                            'Obfuscation / decode pattern: {match}',
                            context_maps)

    # v0.2.0: new patterns
    # Path traversal
    traversals = _find_in_content(PATH_TRAVERSAL, files,
                                  'code_execution', 'medium',
                                  'Path traversal pattern: {match}',
                                  context_maps)
    # Unsafe yaml deserialization
    unsafe_yaml = []
    for fpath, content in files:
        ctx_map = context_maps.get(fpath, {}) if context_maps else {}
        for i, line_text in enumerate(content.split('\n'), 1):
            if UNSAFE_YAML.search(line_text) and not SAFE_YAML.search(line_text):
                ctx = ctx_map.get(i, 'code')
                sev = 'high'
                suffix = ''
                if ctx != 'code':
                    sev = _CONTEXT_DOWNGRADE.get(('high', ctx), 'high')
                    suffix = f' [in {ctx}]'
                unsafe_yaml.append(Finding(
                    'code_execution', sev,
                    f'Unsafe YAML deserialization: yaml.load() without SafeLoader{suffix}',
                    fpath, i))
    # Command injection
    cmd_injects = _find_in_content(CMD_INJECTION, files,
                                   'code_execution', 'high',
                                   'Command injection risk: {match}',
                                   context_maps)

    all_findings = (evals + subprocs + dynamics + destroys + privs + obfs
                    + traversals + unsafe_yaml + cmd_injects)
    findings.extend(_deduplicate_findings(all_findings))

    if not all_findings:
        findings.append(Finding(
            'code_execution', 'info',
            'No dangerous execution patterns detected'))

    deduct = sum(SEVERITY_DEDUCT.get(f.severity, 0) for f in all_findings)
    deduct = min(1.0, deduct)

    score = max(0.0, 1.0 - deduct)
    return round(score * max_score, 1), findings


def score_data_handling(fm, metadata, files, context_maps=None):
    """D4: Data Handling — credentials, hardcoded secrets, exfiltration risk."""
    findings = []
    max_score = WEIGHTS['data_handling']

    cred_refs = _find_in_content(CRED_PATTERN, files,
                                 'data_handling', 'low',
                                 'Credential reference: {match}',
                                 context_maps)
    hardcodes = _find_in_content(CRED_HARDCODE, files,
                                 'data_handling', 'critical',
                                 'Possible hardcoded credential: {match}',
                                 context_maps)

    findings.extend(_deduplicate_findings(cred_refs))
    findings.extend(_deduplicate_findings(hardcodes))

    # Check env var requirements in metadata (this is good practice)
    req_env = metadata.get('requires', {})
    if isinstance(req_env, dict):
        envs = req_env.get('env', [])
        if envs:
            findings.append(Finding(
                'data_handling', 'info',
                f'Declares required env vars (good practice): {", ".join(envs)}'))

    # Exfiltration risk: file read + network in same file
    for fpath, content in files:
        has_read = bool(FILE_READ.search(content))
        has_net = bool(NET_URL.search(content) or NET_CMD.search(content)
                       or NET_LIB.search(content))
        if has_read and has_net:
            findings.append(Finding(
                'data_handling', 'high',
                'File read + network access in same file — potential data exfiltration',
                fpath))

    if not cred_refs and not hardcodes:
        findings.append(Finding(
            'data_handling', 'info',
            'No credential patterns detected'))

    deduct = sum(SEVERITY_DEDUCT.get(f.severity, 0)
                 for f in findings if f.severity != 'info')
    deduct = min(1.0, deduct)

    score = max(0.0, 1.0 - deduct)
    return round(score * max_score, 1), findings


def score_supply_chain(fm, metadata, skill_path):
    """D5: Supply Chain Trust — provenance, homepage, structure."""
    findings = []
    max_score = WEIGHTS['supply_chain']
    deduct = 0.0

    skill_dir = Path(skill_path)

    # Origin tracking
    origin = skill_dir / '.clawhub' / 'origin.json'
    meta_json = skill_dir / '_meta.json'

    if origin.exists():
        findings.append(Finding(
            'supply_chain', 'info',
            'ClawHub origin tracking present (.clawhub/origin.json)'))
    elif meta_json.exists():
        findings.append(Finding(
            'supply_chain', 'info',
            'Metadata file present (_meta.json)'))
    else:
        findings.append(Finding(
            'supply_chain', 'medium',
            'No provenance tracking (.clawhub/origin.json or _meta.json missing)'))
        deduct += 0.3

    # Homepage
    if fm.get('homepage'):
        findings.append(Finding(
            'supply_chain', 'info',
            f'Homepage declared: {fm["homepage"][:60]}'))
    else:
        findings.append(Finding(
            'supply_chain', 'low',
            'No homepage URL declared in frontmatter'))
        deduct += 0.15

    # Standard directory structure
    has_skill_md = (skill_dir / 'SKILL.md').exists()
    has_scripts = (skill_dir / 'scripts').is_dir()

    if has_skill_md:
        findings.append(Finding(
            'supply_chain', 'info', 'SKILL.md present'))
    else:
        findings.append(Finding(
            'supply_chain', 'critical',
            'SKILL.md missing — not a valid OpenClaw skill'))
        deduct += 0.5

    if has_scripts:
        findings.append(Finding(
            'supply_chain', 'info', 'Standard scripts/ directory present'))

    score = max(0.0, 1.0 - deduct)
    return round(score * max_score, 1), findings


def score_transparency(fm, metadata, files):
    """D6: Transparency — documentation, safety rules, code readability."""
    findings = []
    max_score = WEIGHTS['transparency']
    deduct = 0.0

    # Description quality
    desc = fm.get('description', '')
    if not desc:
        findings.append(Finding(
            'transparency', 'high',
            'No description in frontmatter'))
        deduct += 0.4
    elif len(desc) < 20:
        findings.append(Finding(
            'transparency', 'medium',
            f'Description too short ({len(desc)} chars) — weak discoverability'))
        deduct += 0.2
    else:
        findings.append(Finding(
            'transparency', 'info',
            f'Description present ({len(desc)} chars)'))

    # Safety documentation
    safety_keywords = re.compile(
        r'safety|security|warning|caution|danger|never|do not|限制|安全|警告',
        re.IGNORECASE)
    has_safety_docs = False
    for fpath, content in files:
        if fpath.endswith('SKILL.md') and safety_keywords.search(content):
            has_safety_docs = True
            break

    if has_safety_docs:
        findings.append(Finding(
            'transparency', 'info',
            'Safety/security documentation found in SKILL.md'))
    else:
        findings.append(Finding(
            'transparency', 'low',
            'No safety rules or warnings documented'))
        deduct += 0.15

    # Code readability — check for binary / heavily obfuscated files
    for fpath, content in files:
        if fpath.endswith(('.py', '.js', '.ts', '.sh')):
            # Check for very long single lines (obfuscation signal)
            for i, line in enumerate(content.split('\n'), 1):
                if len(line) > 500 and not line.strip().startswith('#'):
                    findings.append(Finding(
                        'transparency', 'medium',
                        f'Suspiciously long line ({len(line)} chars) — '
                        f'possible obfuscation', fpath, i))
                    deduct += 0.15
                    break  # one per file is enough

    score = max(0.0, 1.0 - deduct)
    return round(score * max_score, 1), findings


# ---------------------------------------------------------------------------
# Main audit
# ---------------------------------------------------------------------------
def audit_skill(skill_path):
    """Run full security audit on a skill directory.

    Returns dict with scores, findings, grade, and recommendations.
    """
    skill_dir = Path(skill_path)

    # Read SKILL.md
    skill_md = skill_dir / 'SKILL.md'
    if not skill_md.exists():
        return {
            'skill_path': str(skill_dir),
            'skill_name': skill_dir.name,
            'error': 'SKILL.md not found — not a valid OpenClaw skill',
            'total_score': 0,
            'grade': 'F',
            'grade_label': 'Dangerous',
        }

    text = skill_md.read_text(encoding='utf-8', errors='replace')
    fm, body = parse_frontmatter(text)
    metadata = parse_metadata(fm)

    # Scan all files
    files = scan_files(skill_path)

    # v0.2.0: build context maps for context-aware scanning
    context_maps = {}
    for fpath, content in files:
        context_maps[fpath] = classify_lines(fpath, content)

    # Run 6 dimension scorers
    d1_score, d1_findings = score_permission_scope(fm, metadata, files)
    d2_score, d2_findings = score_network_exposure(fm, metadata, files, context_maps)
    d3_score, d3_findings = score_code_execution(fm, metadata, files, context_maps)
    d4_score, d4_findings = score_data_handling(fm, metadata, files, context_maps)
    d5_score, d5_findings = score_supply_chain(fm, metadata, skill_path)
    d6_score, d6_findings = score_transparency(fm, metadata, files)

    total = round(d1_score + d2_score + d3_score + d4_score + d5_score + d6_score, 1)

    # Determine grade
    grade, grade_label = 'F', 'Dangerous'
    for threshold, g, label in GRADE_THRESHOLDS:
        if total >= threshold:
            grade, grade_label = g, label
            break

    all_findings = (d1_findings + d2_findings + d3_findings
                    + d4_findings + d5_findings + d6_findings)

    # Generate recommendations
    recommendations = _generate_recommendations(all_findings)

    return {
        'skill_path': str(skill_dir),
        'skill_name': fm.get('name', skill_dir.name),
        'version': VERSION,
        'total_score': total,
        'grade': grade,
        'grade_label': grade_label,
        'dimensions': {
            'permission_scope':  {'score': d1_score, 'max': WEIGHTS['permission_scope']},
            'network_exposure':  {'score': d2_score, 'max': WEIGHTS['network_exposure']},
            'code_execution':    {'score': d3_score, 'max': WEIGHTS['code_execution']},
            'data_handling':     {'score': d4_score, 'max': WEIGHTS['data_handling']},
            'supply_chain':      {'score': d5_score, 'max': WEIGHTS['supply_chain']},
            'transparency':      {'score': d6_score, 'max': WEIGHTS['transparency']},
        },
        'findings': [f.to_dict() for f in all_findings if f.severity != 'info'],
        'info': [f.to_dict() for f in all_findings if f.severity == 'info'],
        'finding_counts': {
            'critical': sum(1 for f in all_findings if f.severity == 'critical'),
            'high':     sum(1 for f in all_findings if f.severity == 'high'),
            'medium':   sum(1 for f in all_findings if f.severity == 'medium'),
            'low':      sum(1 for f in all_findings if f.severity == 'low'),
        },
        'recommendations': recommendations,
    }


def _generate_recommendations(findings):
    """Generate actionable improvement suggestions from findings."""
    recs = []
    seen = set()

    for f in findings:
        if f.severity == 'info':
            continue

        rec = None
        if f.dimension == 'permission_scope' and 'unrestricted' in f.message:
            rec = 'Add `allowed-tools` to frontmatter to declare minimum required permissions'
        elif f.dimension == 'network_exposure' and 'External domains' in f.message:
            rec = 'Document all external API endpoints in SKILL.md for user awareness'
        elif f.dimension == 'code_execution' and 'eval' in f.message.lower():
            rec = 'Replace eval()/exec() with safer alternatives'
        elif f.dimension == 'code_execution' and 'Privilege' in f.message:
            rec = 'Remove privilege escalation — skills should not require sudo/admin'
        elif f.dimension == 'code_execution' and 'Obfuscation' in f.message:
            rec = 'Remove obfuscation — skill code should be human-readable'
        elif f.dimension == 'data_handling' and 'hardcoded' in f.message.lower():
            rec = 'Move credentials to environment variables — never hardcode secrets'
        elif f.dimension == 'data_handling' and 'exfiltration' in f.message.lower():
            rec = 'Separate file-reading logic from network logic to reduce exfiltration risk'
        elif f.dimension == 'supply_chain' and 'provenance' in f.message.lower():
            rec = 'Publish to ClawHub for provenance tracking and community trust'
        elif f.dimension == 'transparency' and 'description' in f.message.lower():
            rec = 'Add a detailed description in SKILL.md frontmatter'
        elif f.dimension == 'transparency' and 'safety' in f.message.lower():
            rec = 'Add a "Safety Rules" or "Security Notes" section to SKILL.md'

        if rec and rec not in seen:
            seen.add(rec)
            recs.append(rec)

    return recs


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------
def format_text(result):
    """Human-readable terminal output."""
    lines = []

    name = result.get('skill_name', 'unknown')
    grade = result.get('grade', '?')
    label = result.get('grade_label', '')
    total = result.get('total_score', 0)

    if 'error' in result:
        lines.append(f'[ERROR] {name}: {result["error"]}')
        return '\n'.join(lines)

    # Header
    lines.append(f'=== Skill Security Audit: {name} ===')
    lines.append(f'Score: {total}/100  Grade: {grade} ({label})')
    lines.append('')

    # Dimension breakdown
    lines.append('--- Dimensions ---')
    dim_labels = {
        'permission_scope': 'Permission Scope',
        'network_exposure': 'Network Exposure',
        'code_execution':   'Code Execution',
        'data_handling':    'Data Handling',
        'supply_chain':     'Supply Chain',
        'transparency':     'Transparency',
    }
    for key, info in result.get('dimensions', {}).items():
        label = dim_labels.get(key, key)
        bar_len = 20
        filled = int((info['score'] / info['max']) * bar_len) if info['max'] > 0 else 0
        bar = '#' * filled + '-' * (bar_len - filled)
        lines.append(f'  {label:20s} [{bar}] {info["score"]}/{info["max"]}')

    # Finding counts
    counts = result.get('finding_counts', {})
    if any(counts.values()):
        lines.append('')
        lines.append('--- Issues Found ---')
        for sev in ('critical', 'high', 'medium', 'low'):
            c = counts.get(sev, 0)
            if c > 0:
                lines.append(f'  {sev.upper():10s} {c}')

    # Findings detail
    findings = result.get('findings', [])
    if findings:
        lines.append('')
        lines.append('--- Details ---')
        for f in findings:
            loc = f''
            if f.get('file'):
                loc = f' ({f["file"]}'
                if f.get('line'):
                    loc += f':{f["line"]}'
                loc += ')'
            lines.append(f'  [{f["severity"].upper():8s}] {f["message"]}{loc}')

    # Recommendations
    recs = result.get('recommendations', [])
    if recs:
        lines.append('')
        lines.append('--- Recommendations ---')
        for i, r in enumerate(recs, 1):
            lines.append(f'  {i}. {r}')

    return '\n'.join(lines)


def format_batch_text(results):
    """Summary table for batch scan."""
    lines = ['=== Batch Skill Security Audit ===', '']

    # Sort by score ascending (worst first)
    sorted_results = sorted(results, key=lambda r: r.get('total_score', 0))

    lines.append(f'{"Skill":<30s} {"Score":>5s}  {"Grade":>5s}  {"Issues":>6s}')
    lines.append('-' * 55)

    for r in sorted_results:
        name = r.get('skill_name', 'unknown')[:28]
        score = r.get('total_score', 0)
        grade = r.get('grade', '?')
        counts = r.get('finding_counts', {})
        issues = sum(counts.values())
        lines.append(f'{name:<30s} {score:>5.1f}  {grade:>5s}  {issues:>6d}')

    lines.append('')
    total = len(results)
    by_grade = {}
    for r in results:
        g = r.get('grade', '?')
        by_grade[g] = by_grade.get(g, 0) + 1

    summary_parts = [f'{g}: {c}' for g, c in sorted(by_grade.items())]
    lines.append(f'Total: {total} skills  |  {", ".join(summary_parts)}')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Skill Security Auditor — multi-dimension security scoring '
                    'for OpenClaw skills')
    parser.add_argument('skill_path', nargs='?',
                        help='Path to a skill directory')
    parser.add_argument('--scan-dir',
                        help='Scan all skills in a directory')
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--version', action='version',
                        version=f'skill-security-auditor {VERSION}')
    args = parser.parse_args()

    if not args.skill_path and not args.scan_dir:
        parser.error('Provide a skill path or --scan-dir')

    if args.scan_dir:
        # Batch scan
        scan_dir = Path(args.scan_dir)
        if not scan_dir.is_dir():
            print(f'[ERROR] Not a directory: {args.scan_dir}', file=sys.stderr)
            sys.exit(1)

        results = []
        for entry in sorted(scan_dir.iterdir()):
            if entry.is_dir() and (entry / 'SKILL.md').exists():
                results.append(audit_skill(str(entry)))

        if not results:
            print(f'[WARN] No skills found in {args.scan_dir}', file=sys.stderr)
            sys.exit(0)

        if args.json:
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            print(format_batch_text(results))
            print()
            for r in sorted(results, key=lambda x: x.get('total_score', 0)):
                print(format_text(r))
                print()
    else:
        # Single skill
        skill_path = args.skill_path
        if not Path(skill_path).is_dir():
            print(f'[ERROR] Not a directory: {skill_path}', file=sys.stderr)
            sys.exit(1)

        result = audit_skill(skill_path)

        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(format_text(result))


if __name__ == '__main__':
    main()
