from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_WHEEL_MEMBERS = {
    "proofaudit/cli.py",
    "proofaudit/engine.py",
    "proofaudit/test_e2e.py",
    "proofaudit/schemas/case-spec.v0.1.schema.json",
    "proofaudit/schemas/test-e2e.v0.1.schema.json",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def run(
    name: str,
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
) -> dict:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_seconds,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if completed.returncode:
        output = (completed.stdout or "") + (completed.stderr or "")
        raise RuntimeError(f"{name} failed with exit code {completed.returncode}\n{output[-8000:]}")
    return {"name": name, "elapsed_ms": elapsed_ms, "exit_code": 0}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and verify a ProofAudit release wheel.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--wheel-output-dir")
    parser.add_argument("--command-timeout-seconds", type=int, default=600)
    args = parser.parse_args()

    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)
    clean_env["PYTHONNOUSERSITE"] = "1"
    checks: list[dict] = []
    persisted_wheel: Path | None = None

    with tempfile.TemporaryDirectory(prefix="proofaudit-release-preflight-") as raw:
        temp = Path(raw)
        wheelhouse = temp / "wheelhouse"
        wheelhouse.mkdir()
        checks.append(
            run(
                "build-wheel",
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    ".",
                    "--no-deps",
                    "--wheel-dir",
                    str(wheelhouse),
                ],
                cwd=ROOT,
                env=clean_env,
                timeout_seconds=args.command_timeout_seconds,
            )
        )
        wheels = list(wheelhouse.glob("proofaudit-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected exactly one wheel, found {len(wheels)}")
        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as archive:
            members = set(archive.namelist())
        missing_members = sorted(REQUIRED_WHEEL_MEMBERS - members)
        if missing_members:
            raise RuntimeError(f"wheel is missing required runtime files: {missing_members}")

        venv = temp / "clean-venv"
        checks.append(
            run(
                "create-clean-venv",
                [sys.executable, "-m", "venv", str(venv)],
                cwd=ROOT,
                env=clean_env,
                timeout_seconds=args.command_timeout_seconds,
            )
        )
        bindir = venv / ("Scripts" if os.name == "nt" else "bin")
        python = bindir / ("python.exe" if os.name == "nt" else "python")
        proofaudit = bindir / ("proofaudit.exe" if os.name == "nt" else "proofaudit")
        checks.append(
            run(
                "install-wheel-with-dev-extra",
                [str(python), "-m", "pip", "install", f"{wheel}[dev]"],
                cwd=ROOT,
                env=clean_env,
                timeout_seconds=args.command_timeout_seconds,
            )
        )
        checks.append(
            run(
                "console-script-version",
                [str(proofaudit), "--version"],
                cwd=temp,
                env=clean_env,
                timeout_seconds=args.command_timeout_seconds,
            )
        )
        checks.append(
            run(
                "unit-tests-from-installed-wheel",
                [str(python), "-m", "pytest"],
                cwd=ROOT,
                env=clean_env,
                timeout_seconds=args.command_timeout_seconds,
            )
        )
        case = ROOT / "examples/minimal/case.json"
        checks.append(
            run(
                "validate-minimal-case",
                [str(proofaudit), "validate", "--case", str(case)],
                cwd=temp,
                env=clean_env,
                timeout_seconds=args.command_timeout_seconds,
            )
        )
        smoke_result = temp / "minimal-test-e2e.json"
        checks.append(
            run(
                "minimal-test-e2e",
                [
                    str(proofaudit),
                    "test-e2e",
                    "--case",
                    str(case),
                    "--output",
                    str(smoke_result),
                    "--timeout-ms",
                    "60000",
                ],
                cwd=temp,
                env=clean_env,
                timeout_seconds=args.command_timeout_seconds,
            )
        )
        smoke = json.loads(smoke_result.read_text(encoding="utf-8"))
        if smoke.get("status") != "VERIFIED_TEST_ONLY":
            raise RuntimeError(f"unexpected smoke result: {smoke.get('status')!r}")

        if args.wheel_output_dir:
            wheel_output_dir = Path(args.wheel_output_dir).expanduser().resolve()
            wheel_output_dir.mkdir(parents=True, exist_ok=True)
            persisted_wheel = wheel_output_dir / wheel.name
            shutil.copy2(wheel, persisted_wheel)

        result = {
            "schema_version": "release-preflight.v0.1",
            "status": "PASS",
            "isolated_install": True,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "wheel": {
                "filename": wheel.name,
                "sha256": sha256(wheel),
                "size_bytes": wheel.stat().st_size,
                "persisted_path": str(persisted_wheel) if persisted_wheel else None,
                "required_members": sorted(REQUIRED_WHEEL_MEMBERS),
            },
            "checks": checks,
            "minimal_test_e2e": {
                "status": smoke["status"],
                "stage_count": smoke["stage_count"],
                "stage_statuses": smoke["stage_statuses"],
                "governance_open_requirements": smoke["governance_open_requirements"],
            },
            "temporary_build_environment_destroyed": True,
        }

    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
