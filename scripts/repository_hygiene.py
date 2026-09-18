from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


PRUNED_DIRECTORIES = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".lake",
    "node_modules",
    "artifacts",
    "build",
    "dist",
    "private",
    "sealed",
    "raw_pdfs",
}
PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
PRIVATE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
SOURCE_PAYLOAD_SUFFIXES = {".pdf"}
BINARY_RELEASE_SUFFIXES = {".whl", ".exe", ".dll", ".so", ".dylib", ".zip", ".7z"}
TEXT_SCAN_LIMIT = 2 * 1024 * 1024
WARN_SIZE = 5 * 1024 * 1024
BLOCK_SIZE = 25 * 1024 * 1024


def patterns() -> dict[str, re.Pattern[str]]:
    private_header = "-----BEGIN " + "PRIVATE KEY-----"
    github_prefix = "gh" + "[pousr]_"
    openai_prefix = "s" + "k-"
    return {
        "private_key_material": re.compile(re.escape(private_header)),
        "github_token": re.compile(github_prefix + r"[A-Za-z0-9]{20,}"),
        "openai_token": re.compile(openai_prefix + r"[A-Za-z0-9_-]{20,}"),
        "aws_access_key": re.compile(r"AKIA[A-Z0-9]{16}"),
        "windows_absolute_path": re.compile(
            r"(?<![A-Za-z0-9])[A-Za-z]:(?:\\\\[A-Za-z0-9_.-]|\\[A-Z0-9_.-])"
        ),
        "wsl_absolute_path": re.compile(r"/mnt/[a-z]/"),
        "private_home_path": re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/"),
        "local_tool_path": re.compile("/opt/" + r"proof-audit(?:/|\b)"),
    }


def finding(severity: str, code: str, path: Path, root: Path, detail: str) -> dict:
    return {
        "severity": severity,
        "code": code,
        "path": path.relative_to(root).as_posix(),
        "detail": detail,
    }


def scan_root(root: Path) -> dict:
    findings = []
    file_count = 0
    total_bytes = 0
    matchers = patterns()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        pruned = sorted(set(directories) & PRUNED_DIRECTORIES)
        for name in pruned:
            findings.append(
                finding(
                    "INFO",
                    "GENERATED_OR_RESTRICTED_DIRECTORY_EXCLUDED",
                    current_path / name,
                    root,
                    "Directory is excluded from release hygiene scanning and must remain ignored.",
                )
            )
        directories[:] = [name for name in directories if name not in PRUNED_DIRECTORIES]
        for name in files:
            path = current_path / name
            if path.is_symlink():
                findings.append(
                    finding("BLOCK", "SYMLINK_FILE", path, root, "Symlink files are not portable release inputs.")
                )
                continue
            stat = path.stat()
            file_count += 1
            total_bytes += stat.st_size
            lower_name = name.lower()
            suffix = path.suffix.lower()
            if lower_name in PRIVATE_KEY_NAMES or suffix in PRIVATE_SUFFIXES:
                findings.append(
                    finding("BLOCK", "PRIVATE_KEY_FILE", path, root, "Private-key-like file name or suffix.")
                )
            if suffix in SOURCE_PAYLOAD_SUFFIXES:
                findings.append(
                    finding("BLOCK", "THIRD_PARTY_SOURCE_PAYLOAD", path, root, "PDF source bytes must remain external.")
                )
            if suffix in BINARY_RELEASE_SUFFIXES:
                findings.append(
                    finding("BLOCK", "BINARY_OR_ARCHIVE_IN_SOURCE", path, root, "Binary release artifacts belong in ignored output directories.")
                )
            if stat.st_size >= BLOCK_SIZE:
                findings.append(
                    finding("BLOCK", "OVERSIZED_FILE", path, root, f"File size is {stat.st_size} bytes.")
                )
            elif stat.st_size >= WARN_SIZE:
                findings.append(
                    finding("WARN", "LARGE_FILE", path, root, f"File size is {stat.st_size} bytes.")
                )
            if stat.st_size > TEXT_SCAN_LIMIT:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for code, matcher in matchers.items():
                if matcher.search(text):
                    findings.append(
                        finding(
                            "BLOCK",
                            code.upper(),
                            path,
                            root,
                            "Sensitive value or non-portable local path detected; matched value omitted.",
                        )
                    )
    blockers = sum(item["severity"] == "BLOCK" for item in findings)
    warnings = sum(item["severity"] == "WARN" for item in findings)
    return {
        "root": root.name,
        "status": "BLOCKED" if blockers else "PASS",
        "file_count": file_count,
        "total_bytes": total_bytes,
        "blocker_count": blockers,
        "warning_count": warnings,
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit repository release hygiene.")
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    reports = [scan_root(Path(raw).expanduser().resolve()) for raw in args.root]
    result = {
        "schema_version": "repository-hygiene.v0.1",
        "status": "PASS" if all(item["status"] == "PASS" for item in reports) else "BLOCKED",
        "repositories": reports,
    }
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if result["status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
