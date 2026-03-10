#!/usr/bin/env python3
"""
Package a skill folder into a .skill file with exclusion support.

Usage:
    python scripts/package_skill.py <skill_path> [--output-dir <dir>] [--exclude <pattern> ...]
"""

import argparse
import fnmatch
import sys
import zipfile
from pathlib import Path
from typing import Iterable, List


DEFAULT_EXCLUDES = [
    "tests",
    ".git",
    "dist",
    "__pycache__",
    ".pytest_cache",
    "README.md",
    "ROADMAP.md",
    "CHANGELOG.md",
    ".gitignore",
    ".gitattributes",
    "package_skill.py",  # packaging script is a dev tool, not needed at runtime
    # NOTE: _meta.json and LICENSE must NOT be excluded — required for marketplace
]


def _normalize_patterns(patterns: Iterable[str]) -> List[str]:
    normalized = []
    for raw in patterns:
        for part in str(raw).split(","):
            item = part.strip()
            if item:
                normalized.append(item.replace("\\", "/").strip("/"))
    return normalized


def _should_exclude(relative_path: Path, patterns: List[str]) -> bool:
    rel_posix = relative_path.as_posix()
    name = relative_path.name
    parts = [p for p in relative_path.parts if p not in (".", "")]

    for pattern in patterns:
        if not pattern:
            continue

        if fnmatch.fnmatch(rel_posix, pattern):
            return True
        if fnmatch.fnmatch(name, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
        if pattern in parts:
            return True

    return False


def package_skill(skill_path: Path, output_dir: Path | None, excludes: List[str]) -> Path:
    skill_path = skill_path.resolve()

    if not skill_path.exists():
        raise FileNotFoundError(f"Skill folder not found: {skill_path}")
    if not skill_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {skill_path}")
    if not (skill_path / "SKILL.md").exists():
        raise FileNotFoundError(f"SKILL.md not found in {skill_path}")

    if output_dir is None:
        output_dir = Path.cwd()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    skill_name = skill_path.name
    skill_filename = output_dir / f"{skill_name}.skill"

    candidate_files = [p for p in skill_path.rglob("*") if p.is_file()]

    with zipfile.ZipFile(skill_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file_path in candidate_files:
            if file_path.resolve() == skill_filename.resolve():
                continue
            if not file_path.is_file():
                continue

            relative_to_skill = file_path.relative_to(skill_path)
            if _should_exclude(relative_to_skill, excludes):
                continue

            arcname = file_path.relative_to(skill_path.parent)
            zipf.write(file_path, arcname)
            print(f"Added: {arcname}")

    return skill_filename


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Package a skill folder into a .skill file and optionally exclude files/directories."
    )
    parser.add_argument("skill_path", help="Path to the skill folder.")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional output directory for the .skill file. Defaults to current directory.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude pattern. Can be repeated, e.g. --exclude tests --exclude '*.log'.",
    )

    args = parser.parse_args()

    user_patterns = _normalize_patterns(args.exclude)
    # Always apply DEFAULT_EXCLUDES; merge with any user-supplied patterns
    excludes = list(dict.fromkeys(DEFAULT_EXCLUDES + user_patterns))

    try:
        artifact = package_skill(
            skill_path=Path(args.skill_path),
            output_dir=Path(args.output_dir) if args.output_dir else None,
            excludes=excludes,
        )
        print(f"\nCreated: {artifact}")
        print(f"Excludes: {', '.join(excludes)}")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
