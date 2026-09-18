from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from proofaudit.io import resolve_within, sha256_file
from proofaudit.models import (
    ArtifactRef,
    AssuranceDimension,
    AssuranceLevel,
    ClaimVerdict,
    DimensionAssessment,
    EvidenceAssurance,
    EvidenceClosure,
    Finding,
    Plugin,
    PluginResult,
    Status,
)


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_LEAN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_'.]*$")
_SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9_.\-/]+$")


class LeanComparatorPlugin(Plugin):
    """Run Comparator in a fresh checkout using a pinned, prebuilt dependency cache."""

    plugin_id = "lean.comparator"
    layer = "L5"

    def run(self, context, config):
        workspace = None
        try:
            runtime = self._runtime(config)
            workspace = Path(tempfile.mkdtemp(
                prefix="proofaudit-comparator-", dir=runtime["run_root"]
            )).resolve()
            return self._run(context, config, runtime, workspace)
        except subprocess.TimeoutExpired as exc:
            return self._blocked(
                context, "COMPARATOR_TIMEOUT", f"Comparator command timed out: {exc.cmd}"
            )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return self._blocked(
                context,
                "COMPARATOR_INFRASTRUCTURE_ERROR",
                f"{type(exc).__name__}: {exc}",
            )
        finally:
            if workspace is not None and workspace.exists():
                runtime_root = Path(os.environ.get(
                    str(config.get("run_root_env", "PROOFAUDIT_RUN_ROOT")), ""
                )).expanduser().resolve()
                if (
                    workspace.parent == runtime_root
                    and workspace.name.startswith("proofaudit-comparator-")
                ):
                    shutil.rmtree(workspace)

    def _run(self, context, config, runtime, workspace):
        spec_path = resolve_within(context.case_root, str(config["spec_path"]))
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        commit = str(spec["commit"]).lower()
        mathlib_revision = str(spec["mathlib_revision"]).lower()
        expected_files = {
            str(path): str(digest).lower()
            for path, digest in dict(spec["expected_files"]).items()
        }
        comparator_revision = str(config["comparator_revision"]).lower()
        tool_pins = {
            str(name): str(revision).lower()
            for name, revision in dict(config["tool_pins"]).items()
        }
        tool_binary_sha256 = {
            str(name): str(digest).upper()
            for name, digest in dict(config["tool_binary_sha256"]).items()
        }
        challenge_module = str(config["challenge_module"])
        challenge_file = str(config["challenge_file"])
        comparator_config = str(config["comparator_config"])
        solution_olean = str(config["solution_olean"])
        obligations = [str(value) for value in config["obligations"]]
        writable_cached_packages = [
            str(value) for value in config.get("writable_cached_packages", [])
        ]
        self._validate(
            commit,
            mathlib_revision,
            comparator_revision,
            tool_pins,
            challenge_module,
            challenge_file,
            comparator_config,
            solution_olean,
            expected_files,
            obligations,
            tool_binary_sha256,
            writable_cached_packages,
        )

        cache_material = {
            "cache_format": 3,
            "repository_commit": commit,
            "comparator_revision": comparator_revision,
            "mathlib_revision": mathlib_revision,
            "source_hashes": expected_files,
            "tool_pins": tool_pins,
            "challenge_module": challenge_module,
            "solution_olean": solution_olean,
        }
        cache_key = hashlib.sha256(json.dumps(
            cache_material, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        selected_cache_key = cache_key
        cache = runtime["run_root"] / "comparator-cache" / selected_cache_key
        if not cache.is_dir() or not (cache / "READY").is_file():
            selected_cache_key = str(config.get("compatible_cache_key", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", selected_cache_key):
                return self._blocked(
                    context,
                    "COMPARATOR_CACHE_NOT_AVAILABLE",
                    f"Pinned Comparator cache is absent: {cache_key}",
                )
            cache = runtime["run_root"] / "comparator-cache" / selected_cache_key
        if not cache.is_dir() or not (cache / "READY").is_file():
            return self._blocked(
                context,
                "COMPARATOR_COMPATIBLE_CACHE_NOT_AVAILABLE",
                f"Compatible Comparator cache is absent: {selected_cache_key}",
            )
        if (cache / "READY").read_text(encoding="utf-8").strip() != selected_cache_key:
            return self._blocked(
                context, "COMPARATOR_CACHE_INVALID", "Comparator READY marker is invalid."
            )

        cache_repo = (cache / "repo").resolve()
        self._require_commit(cache_repo, commit, runtime["git"], runtime["timeout"])
        self._require_clean(cache_repo, runtime["git"], runtime["timeout"])
        self._require_hashes(cache_repo, expected_files)
        self._require_commit(
            cache_repo / ".lake/packages/Comparator",
            comparator_revision,
            runtime["git"],
            runtime["timeout"],
        )
        self._require_commit(
            cache_repo / ".lake/packages/mathlib",
            mathlib_revision,
            runtime["git"],
            runtime["timeout"],
        )
        comparator_relative = (cache / "COMPARATOR_BINARY.path").read_text(
            encoding="utf-8"
        ).strip()
        comparator_binary = (cache_repo / comparator_relative).resolve()
        if not comparator_binary.is_file() or not os.access(comparator_binary, os.X_OK):
            raise ValueError("cached Comparator binary is absent or not executable")
        expected_binary_hash = (cache / "COMPARATOR_BINARY.sha256").read_text(
            encoding="utf-8"
        ).strip().upper()
        if sha256_file(comparator_binary) != expected_binary_hash:
            raise ValueError("cached Comparator binary hash mismatch")

        repo = workspace / "repo"
        commands: list[dict[str, Any]] = []
        clone = self._command(
            [runtime["git"], "clone", "--no-hardlinks", str(runtime["mirror"]), str(repo)],
            workspace,
            runtime["timeout"],
        )
        commands.append(clone)
        self._require_success("COMPARATOR_FRESH_CLONE_FAILED", clone)
        checkout = self._command(
            [runtime["git"], "checkout", "--detach", commit], repo, runtime["timeout"]
        )
        commands.append(checkout)
        self._require_success("COMPARATOR_CHECKOUT_FAILED", checkout)
        self._require_commit(repo, commit, runtime["git"], runtime["timeout"])
        self._require_clean(repo, runtime["git"], runtime["timeout"])
        self._require_hashes(repo, expected_files)

        lake_dir = repo / ".lake"
        lake_dir.mkdir(exist_ok=True)
        self._materialize_packages(
            cache_repo / ".lake/packages",
            lake_dir / "packages",
            writable_cached_packages,
        )
        if self._solution_exists(repo, solution_olean):
            raise ValueError("solution olean existed before Comparator execution")
        probe = self._command(
            [runtime["lake"], "exe", "comparator", "--help"], repo, runtime["timeout"]
        )
        commands.append(probe)
        if self._solution_exists(repo, solution_olean):
            raise ValueError("solution olean appeared during Comparator build probe")

        lean_prefix_result = self._command(
            [runtime["lean"], "--print-prefix"], repo, runtime["timeout"]
        )
        commands.append(lean_prefix_result)
        self._require_success("COMPARATOR_LEAN_PREFIX_FAILED", lean_prefix_result)
        lean_prefix = Path(lean_prefix_result["stdout"].strip()).resolve()
        lake = lean_prefix / "bin/lake"
        if not lake.is_file():
            raise ValueError("Lean toolchain Lake binary is missing")

        evidence = workspace / "evidence"
        evidence.mkdir()
        invocation_log = evidence / "landrun.args"
        invocation_log.write_text("", encoding="utf-8")
        real_landrun = (runtime["bin_root"] / "landrun").resolve()
        real_lean4export = (runtime["bin_root"] / "lean4export").resolve()
        real_nanoda = (runtime["bin_root"] / "nanoda_bin").resolve()
        for tool in (real_landrun, real_lean4export, real_nanoda):
            if not tool.is_file() or not os.access(tool, os.X_OK):
                raise ValueError(f"Comparator tool is absent or not executable: {tool}")
        runtime_tools = {
            "landrun": real_landrun,
            "lean4export": real_lean4export,
            "nanoda": real_nanoda,
        }
        for name, tool in runtime_tools.items():
            if sha256_file(tool) != tool_binary_sha256[name]:
                raise ValueError(f"Comparator tool binary hash mismatch: {name}")
        self._require_commit(
            real_lean4export.parents[3], tool_pins["lean4export"], runtime["git"], runtime["timeout"]
        )
        self._require_commit(
            real_nanoda.parents[2], tool_pins["nanoda"], runtime["git"], runtime["timeout"]
        )
        wrapper = evidence / "landrun-wrapper"
        wrapper.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%q ' \"$@\" >> {self._shell_quote(invocation_log)}\n"
            f"printf '\\n' >> {self._shell_quote(invocation_log)}\n"
            f"exec {self._shell_quote(real_landrun)} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o500)
        unit = "proofaudit-comparator-" + uuid.uuid4().hex[:16]
        environment = os.environ.copy()
        environment["PATH"] = str(lean_prefix / "bin") + os.pathsep + environment.get("PATH", "")
        environment["COMPARATOR_LANDRUN"] = str(wrapper)
        environment["COMPARATOR_LEAN4EXPORT"] = str(real_lean4export)
        environment["COMPARATOR_NANODA"] = str(real_nanoda)
        check_argv = [
            runtime["systemd_run"],
            "--user",
            "--wait",
            "--pipe",
            "--collect",
            f"--unit={unit}",
            "--property=RestrictAddressFamilies=~AF_UNIX",
            f"--working-directory={repo}",
            "-E", f"PATH={environment['PATH']}",
            "-E", f"HOME={environment.get('HOME', '')}",
            "-E", f"COMPARATOR_LANDRUN={wrapper}",
            "-E", f"COMPARATOR_LEAN4EXPORT={real_lean4export}",
            "-E", f"COMPARATOR_NANODA={real_nanoda}",
            str(lake), "exe", "comparator", comparator_config,
        ]
        check = self._command(check_argv, repo, runtime["timeout"], environment)
        commands.append(check)
        combined = check["stdout"] + "\n" + check["stderr"]
        if check["returncode"] != 0:
            if self._statement_mismatch(combined):
                return PluginResult(
                    stage_id=context.stage_id,
                    plugin_id=self.plugin_id,
                    status=Status.PASS,
                    risk_level="CRITICAL",
                    assurance=EvidenceAssurance.VERIFIED,
                    claim_verdict=ClaimVerdict.SCOPE_MISMATCH,
                    findings=[Finding(
                        code="COMPARATOR_STATEMENT_MISMATCH",
                        title="formal_statement_mismatch",
                        severity="P0",
                        detail=combined[-8000:],
                    )],
                )
            return self._execution_failure(context, check, invocation_log)

        lines = invocation_log.read_text(encoding="utf-8").splitlines()
        counts = {
            "landrun": len(lines),
            "lean4export": sum(str(real_lean4export) in line for line in lines),
            "nanoda_bin": sum(str(real_nanoda) in line for line in lines),
        }
        if any(counts[name] < 1 for name in counts):
            raise ValueError(f"required Comparator tools were not invoked: {counts}")

        report_path = context.artifact_dir / "lean_comparator.json"
        report = {
            "schema_version": "0.1",
            "adapter": self.plugin_id,
            "repository_commit": commit,
            "material_cache_key": cache_key,
            "selected_compatible_cache_key": selected_cache_key,
            "cache_binary_sha256": expected_binary_hash,
            "fresh_checkout": True,
            "solution_prebuild_absent": True,
            "challenge_file": challenge_file,
            "challenge_module": challenge_module,
            "comparator_config": comparator_config,
            "comparator_revision": comparator_revision,
            "mathlib_revision": mathlib_revision,
            "tool_pins": tool_pins,
            "tool_binary_sha256": tool_binary_sha256,
            "writable_cached_packages": sorted(writable_cached_packages),
            "dependency_cache_mode": "read-only-sources-with-per-run-writable-build-copies",
            "tool_source_revision_status": {
                "landrun": "binary_hash_only",
                "lean4export": "verified",
                "nanoda": "verified"
            },
            "tool_invocations": counts,
            "systemd_guard": "RestrictAddressFamilies=~AF_UNIX",
            "commands": commands,
        }
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        artifact = ArtifactRef(
            uri=report_path.relative_to(context.artifact_dir).as_posix(),
            sha256=sha256_file(report_path),
            generated_by=self.plugin_id,
        )
        dependencies = ("lean4", "mathlib", "comparator")
        closures = [
            EvidenceClosure(
                obligation_id=obligation,
                evidence_type="formal_kernel",
                adapter_id=self.plugin_id,
                artifact=artifact,
                verification_method=(
                    "Fresh-checkout Comparator execution with pinned dependency cache, "
                    "Landlock, lean4export, Lean kernel, nanoda, and systemd AF_UNIX restriction."
                ),
                trusted_dependencies=dependencies,
                shared_dependencies=("lean4-kernel", "nanoda-kernel"),
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
            artifacts={"comparator": artifact},
            trusted_dependencies=list(dependencies),
            residual_risks=[
                "Comparator and nanoda share the exported Lean environment and pinned source inputs.",
                "Landrun source checkout was unavailable; the executed binary was verified by SHA-256 only."
            ],
            reproduction_commands=["lake exe comparator " + comparator_config],
            evidence_manifest={
                "material_cache_key": cache_key,
                "selected_compatible_cache_key": selected_cache_key,
                "closure_count": len(closures),
                "tool_invocations": counts,
            },
            assurance_contributions={
                AssuranceDimension.FORMAL: DimensionAssessment(
                    level=AssuranceLevel.VERIFIED,
                    evidence=(artifact.uri,),
                    shared_dependencies=("lean4-kernel", "nanoda-kernel"),
                )
            },
        )

    @staticmethod
    def _runtime(config):
        def required_path(config_key, default_env):
            env_name = str(config.get(config_key, default_env))
            raw = os.environ.get(env_name)
            if not raw:
                raise ValueError(f"environment variable {env_name} is not set")
            return Path(raw).expanduser().resolve()

        mirror = required_path("mirror_env", "PROOFAUDIT_LEAN_MIRROR")
        run_root = required_path("run_root_env", "PROOFAUDIT_RUN_ROOT")
        bin_root = required_path("bin_root_env", "PROOFAUDIT_COMPARATOR_BIN_ROOT")
        if not mirror.is_dir() or not run_root.is_dir() or not bin_root.is_dir():
            raise ValueError("Comparator mirror, run root, or tool root does not exist")
        executables = {
            name: shutil.which(name) for name in ("git", "lake", "lean", "systemd-run")
        }
        missing = [name for name, path in executables.items() if path is None]
        if missing:
            raise ValueError("required executables are missing: " + ", ".join(missing))
        return {
            "mirror": mirror,
            "run_root": run_root,
            "bin_root": bin_root,
            "timeout": int(config.get("command_timeout_seconds", 5400)),
            "git": executables["git"],
            "lake": executables["lake"],
            "lean": executables["lean"],
            "systemd_run": executables["systemd-run"],
        }

    @staticmethod
    def _validate(commit, mathlib, comparator, tool_pins, module, challenge, config, olean, hashes, obligations, tool_hashes, writable_packages):
        if not all(_COMMIT.fullmatch(value) for value in (commit, mathlib, comparator)):
            raise ValueError("repository revisions must be immutable commits")
        if not tool_pins or any(not _COMMIT.fullmatch(value) for value in tool_pins.values()):
            raise ValueError("Comparator tool pins must be immutable commits")
        if not _LEAN_NAME.fullmatch(module):
            raise ValueError("invalid Comparator challenge module")
        for value in (challenge, config):
            if not _SAFE_RELATIVE.fullmatch(value) or ".." in value:
                raise ValueError("invalid Comparator relative path")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.olean", olean):
            raise ValueError("invalid solution olean basename")
        if not hashes or any(
            not _SAFE_RELATIVE.fullmatch(path) or ".." in path
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for path, digest in hashes.items()
        ):
            raise ValueError("invalid source hash set")
        if not obligations:
            raise ValueError("Comparator obligations are empty")
        if set(tool_hashes) != {"landrun", "lean4export", "nanoda"} or any(
            not re.fullmatch(r"[0-9A-F]{64}", digest) for digest in tool_hashes.values()
        ):
            raise ValueError("Comparator tool binary hashes are incomplete or malformed")
        if len(writable_packages) != len(set(writable_packages)) or any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in writable_packages
        ):
            raise ValueError("invalid writable cached package allowlist")

    @staticmethod
    def _materialize_packages(source_root, destination_root, writable_packages):
        if not source_root.is_dir():
            raise ValueError("cached Lake packages directory is absent")
        available = {entry.name: entry for entry in source_root.iterdir()}
        missing = sorted(set(writable_packages) - set(available))
        if missing:
            raise ValueError(
                "writable cached packages are absent: " + ", ".join(missing)
            )
        destination_root.mkdir()
        writable = set(writable_packages)
        for name, source in sorted(available.items()):
            destination = destination_root / name
            if name in writable:
                if not source.is_dir():
                    raise ValueError(f"writable cached package is not a directory: {name}")
                shutil.copytree(source, destination, symlinks=True)
            elif source.is_dir():
                destination.mkdir()
                for member in source.iterdir():
                    target = destination / member.name
                    if member.name == ".lake" and member.is_dir():
                        shutil.copytree(member, target, symlinks=True)
                    else:
                        target.symlink_to(
                            member, target_is_directory=member.is_dir()
                        )
            else:
                destination.symlink_to(source, target_is_directory=source.is_dir())

    @classmethod
    def _require_commit(cls, repo, expected, git, timeout):
        result = cls._command([git, "-C", str(repo), "rev-parse", "HEAD"], repo, timeout)
        cls._require_success("COMPARATOR_COMMIT_CHECK_FAILED", result)
        if result["stdout"].strip().lower() != expected:
            raise ValueError(f"repository commit mismatch: {repo}")

    @classmethod
    def _require_clean(cls, repo, git, timeout):
        result = cls._command(
            [git, "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            repo,
            timeout,
        )
        cls._require_success("COMPARATOR_WORKTREE_CHECK_FAILED", result)
        if result["stdout"].strip():
            raise ValueError(f"tracked worktree changes detected: {repo}")

    @staticmethod
    def _require_hashes(repo, expected):
        for relative, digest in expected.items():
            path = resolve_within(repo, relative)
            if not path.is_file() or sha256_file(path) != digest.upper():
                raise ValueError(f"source hash mismatch: {relative}")

    @staticmethod
    def _solution_exists(repo, basename):
        result = subprocess.run(
            ["find", str(repo / ".lake"), "-type", "f", "-name", basename, "-print", "-quit"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return bool(result.stdout.strip())

    @staticmethod
    def _command(argv, cwd, timeout, env=None):
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
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
    def _require_success(code, result):
        if result["returncode"] != 0:
            raise ValueError(
                f"{code}: exit={result['returncode']} stderr={result['stderr'][-4000:]}"
            )

    @staticmethod
    def _shell_quote(path):
        return "'" + str(path).replace("'", "'\\''") + "'"

    @staticmethod
    def _statement_mismatch(output):
        lowered = output.lower()
        return any(marker in lowered for marker in (
            "statement mismatch", "different statement", "theorem type mismatch", "declaration mismatch"
        ))

    def _blocked(self, context, code, detail):
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.FAIL,
            risk_level="CRITICAL",
            assurance=EvidenceAssurance.VERIFIED,
            findings=[Finding(
                code=code,
                title=code.lower(),
                severity="P1",
                detail=detail,
            )],
            residual_risks=["No Comparator formal_kernel closure was issued."],
        )

    def _execution_failure(self, context, command, invocation_log):
        path = context.artifact_dir / "lean_comparator_failure.json"
        payload = {
            "schema_version": "0.1",
            "adapter": self.plugin_id,
            "code": "COMPARATOR_EXECUTION_FAILED",
            "command": command,
            "landrun_invocations": (
                invocation_log.read_text(encoding="utf-8").splitlines()
                if invocation_log.is_file() else []
            ),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        artifact = ArtifactRef(
            uri=path.relative_to(context.artifact_dir).as_posix(),
            sha256=sha256_file(path),
            generated_by=self.plugin_id,
        )
        detail = (
            f"Comparator exited with {command['returncode']}. "
            f"stdout tail: {command['stdout'][-8000:]} "
            f"stderr tail: {command['stderr'][-4000:]}"
        )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.FAIL,
            risk_level="CRITICAL",
            assurance=EvidenceAssurance.VERIFIED,
            findings=[Finding(
                code="COMPARATOR_EXECUTION_FAILED",
                title="comparator_execution_failed",
                severity="P1",
                detail=detail,
                evidence=[artifact.uri, artifact.sha256],
            )],
            artifacts={"failure": artifact},
            residual_risks=["No Comparator formal_kernel closure was issued."],
            evidence_manifest={
                "failure_artifact": artifact.uri,
                "landrun_invocation_count": len(payload["landrun_invocations"]),
            },
        )
