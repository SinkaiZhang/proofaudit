from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from proofaudit.io import resolve_within, sha256_file
from proofaudit.models import (
    ArtifactRef,
    AssuranceDimension,
    AssuranceLevel,
    DimensionAssessment,
    EvidenceAssurance,
    EvidenceClosure,
    Finding,
    Plugin,
    PluginResult,
    Status,
)


_LEAN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_'.]*$")
_AXIOMS = re.compile(r"'([^']+)' depends on axioms:\s*\[([^\]]*)\]")
_NO_AXIOMS = re.compile(r"'([^']+)' does not depend on any axioms")


class LeanLakeReplayPlugin(Plugin):
    """Replay an existing, pinned Lake target without fetching network content."""

    plugin_id = "lean.lake-replay"
    layer = "L5"

    def run(self, context, config):
        try:
            return self._run(context, config)
        except subprocess.TimeoutExpired as exc:
            return self._blocked(
                context,
                "LEAN_REPLAY_TIMEOUT",
                f"Lean command exceeded its timeout: {exc.cmd}",
            )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return self._blocked(
                context,
                "LEAN_REPLAY_INFRASTRUCTURE_ERROR",
                f"{type(exc).__name__}: {exc}",
            )

    def _run(self, context, config):
        repository_env = str(config.get("repository_env", "PROOFAUDIT_LEAN_REPOSITORY"))
        repository_raw = os.environ.get(repository_env)
        if not repository_raw:
            return self._blocked(
                context,
                "LEAN_REPOSITORY_NOT_CONFIGURED",
                f"Environment variable {repository_env} is not set.",
            )
        repository = Path(repository_raw).expanduser().resolve()
        if not repository.is_dir():
            return self._blocked(
                context,
                "LEAN_REPOSITORY_NOT_FOUND",
                f"Configured repository does not exist: {repository}",
            )

        spec_relative = str(config["spec_path"])
        spec_path = resolve_within(context.case_root, spec_relative)
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        expected_commit = str(spec["commit"])
        expected_files = dict(spec["expected_files"])
        permitted_axioms = {str(value) for value in spec["permitted_axioms"]}

        git = shutil.which(str(config.get("git_executable", "git")))
        lake = shutil.which(str(config.get("lake_executable", "lake")))
        if git is None or lake is None:
            missing = [name for name, value in (("git", git), ("lake", lake)) if value is None]
            return self._blocked(
                context,
                "LEAN_TOOL_NOT_FOUND",
                "Required executable is absent from PATH: " + ", ".join(missing),
            )

        timeout = int(config.get("command_timeout_seconds", 1800))
        command_log: list[dict[str, Any]] = []
        commit_result = self._command(
            [git, "-C", str(repository), "rev-parse", "HEAD"], repository, timeout
        )
        command_log.append(commit_result)
        if commit_result["returncode"] != 0:
            return self._command_failed(context, "LEAN_GIT_COMMIT_CHECK_FAILED", command_log)
        observed_commit = commit_result["stdout"].strip()
        if observed_commit.lower() != expected_commit.lower():
            return self._blocked(
                context,
                "LEAN_REPOSITORY_COMMIT_MISMATCH",
                f"Expected commit {expected_commit}, observed {observed_commit}.",
                severity="P0",
            )

        if bool(config.get("require_clean_worktree", True)):
            clean_result = self._command(
                [git, "-C", str(repository), "status", "--porcelain", "--untracked-files=no"],
                repository,
                timeout,
            )
            command_log.append(clean_result)
            if clean_result["returncode"] != 0 or clean_result["stdout"].strip():
                return self._blocked(
                    context,
                    "LEAN_REPOSITORY_NOT_CLEAN",
                    "The pinned repository has tracked worktree changes or could not be inspected.",
                    severity="P0",
                )

        observed_files = {}
        for relative, expected_hash in sorted(expected_files.items()):
            source = resolve_within(repository, str(relative))
            if not source.is_file():
                return self._blocked(
                    context,
                    "LEAN_SOURCE_FILE_MISSING",
                    f"Pinned source file is missing: {relative}",
                    severity="P0",
                )
            observed_hash = sha256_file(source)
            observed_files[str(relative)] = observed_hash
            if observed_hash != str(expected_hash).upper():
                return self._blocked(
                    context,
                    "LEAN_SOURCE_HASH_MISMATCH",
                    f"Pinned source hash mismatch: {relative}",
                    severity="P0",
                )

        for target in config.get("build_targets", []):
            target = str(target)
            if not _LEAN_NAME.fullmatch(target):
                raise ValueError(f"invalid Lake target: {target}")
            result = self._command([lake, "build", target], repository, timeout)
            command_log.append(result)
            if result["returncode"] != 0:
                return self._command_failed(context, "LEAN_BUILD_FAILED", command_log)

        module = str(config["module"])
        if not _LEAN_NAME.fullmatch(module):
            raise ValueError(f"invalid Lean module: {module}")
        obligations = {
            str(obligation): [str(name) for name in declarations]
            for obligation, declarations in dict(config["obligations"]).items()
        }
        declarations = sorted({name for values in obligations.values() for name in values})
        if not declarations or any(not _LEAN_NAME.fullmatch(name) for name in declarations):
            raise ValueError("invalid or empty Lean declaration set")

        check_file = context.artifact_dir / "lean_axiom_check.lean"
        check_file.write_text(
            "import " + module + "\n\n" + "\n".join(
                f"#print axioms {name}" for name in declarations
            ) + "\n",
            encoding="utf-8",
        )
        axiom_result = self._command(
            [lake, "env", "lean", str(check_file)], repository, timeout
        )
        command_log.append(axiom_result)
        if axiom_result["returncode"] != 0:
            return self._command_failed(context, "LEAN_AXIOM_CHECK_FAILED", command_log)

        axiom_map = self._parse_axioms(axiom_result["stdout"] + "\n" + axiom_result["stderr"])
        missing = sorted(set(declarations) - set(axiom_map))
        if missing:
            return self._blocked(
                context,
                "LEAN_AXIOM_OUTPUT_INCOMPLETE",
                "No axiom report was found for: " + ", ".join(missing),
                severity="P0",
            )
        forbidden = {
            name: sorted(set(axioms) - permitted_axioms)
            for name, axioms in axiom_map.items()
            if set(axioms) - permitted_axioms
        }
        if forbidden:
            return self._blocked(
                context,
                "LEAN_FORBIDDEN_AXIOM",
                "A checked declaration depends on a non-allowlisted axiom: "
                + json.dumps(forbidden, sort_keys=True),
                severity="P0",
            )

        artifact_path = context.artifact_dir / "lean_lake_replay.json"
        artifact_payload = {
            "schema_version": "0.1",
            "adapter": self.plugin_id,
            "repository": str(spec.get("repository", "")),
            "expected_commit": expected_commit,
            "observed_commit": observed_commit,
            "observed_files": observed_files,
            "module": module,
            "build_targets": [str(value) for value in config.get("build_targets", [])],
            "obligations": obligations,
            "axioms": axiom_map,
            "permitted_axioms": sorted(permitted_axioms),
            "commands": command_log,
        }
        artifact_path.write_text(
            json.dumps(artifact_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        artifact = ArtifactRef(
            uri=artifact_path.relative_to(context.artifact_dir).as_posix(),
            sha256=sha256_file(artifact_path),
            generated_by=self.plugin_id,
        )
        dependencies = tuple(str(value) for value in config.get(
            "trusted_dependencies", ["lean4", "mathlib"]
        ))
        closures = [
            EvidenceClosure(
                obligation_id=obligation,
                evidence_type="formal_kernel",
                adapter_id=self.plugin_id,
                artifact=artifact,
                verification_method=(
                    "Pinned source hashes, Lake build, Lean elaboration, and declaration axiom "
                    "allowlist check in the current run."
                ),
                trusted_dependencies=dependencies,
                shared_dependencies=("lean4-kernel",),
            )
            for obligation in sorted(obligations)
        ]
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            evidence_closures=closures,
            artifacts={"lean_replay": artifact},
            trusted_dependencies=list(dependencies),
            residual_risks=[
                "Kernel acceptance does not establish paper-to-Lean semantic fidelity."
            ],
            reproduction_commands=[f"{lake} build {target}" for target in config.get("build_targets", [])],
            evidence_manifest={
                "commit": observed_commit,
                "declaration_count": len(declarations),
                "closure_count": len(closures),
            },
            assurance_contributions={
                AssuranceDimension.FORMAL: DimensionAssessment(
                    level=AssuranceLevel.VERIFIED,
                    evidence=(artifact.uri,),
                    shared_dependencies=("lean4-kernel",),
                    residual_risks=(
                        "Formal validity is conditional on the pinned Lean kernel and dependencies.",
                    ),
                )
            },
        )

    @staticmethod
    def _command(argv, cwd, timeout):
        completed = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "argv": [str(value) for value in argv],
            "returncode": completed.returncode,
            "stdout": completed.stdout[-16000:],
            "stderr": completed.stderr[-16000:],
        }

    @staticmethod
    def _parse_axioms(output):
        result = {}
        for match in _AXIOMS.finditer(output):
            result[match.group(1)] = [
                value.strip() for value in match.group(2).split(",") if value.strip()
            ]
        for match in _NO_AXIOMS.finditer(output):
            result.setdefault(match.group(1), [])
        return result

    def _command_failed(self, context, code, command_log):
        last = command_log[-1]
        detail = (
            f"Command exited with {last['returncode']}: {' '.join(last['argv'])}; "
            f"stderr tail: {last['stderr'][-2000:]}"
        )
        return self._blocked(context, code, detail)

    def _blocked(self, context, code, detail, severity="P1"):
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.FAIL,
            risk_level="CRITICAL",
            assurance=EvidenceAssurance.VERIFIED,
            findings=[Finding(
                code=code,
                title=code.lower(),
                severity=severity,
                detail=detail,
            )],
            residual_risks=["No formal_kernel evidence closure was issued."],
        )
