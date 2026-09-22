"""Run CI using temporary sources, pinned sibling wheels and fresh environments."""

import argparse
import io
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = {
    "toolframe-sdk": "ef15b3575615839f24b2710beb3e40f9ae3ca2aa",
    "toolframe-storage-sqlite": "a6c3148a5079f78c935b434a60f6cbb62489ded7",
}


def validate_release_ref(ref, version):
    if ref != f"refs/tags/v{version}":
        raise ValueError(f"Publishing requires refs/tags/v{version}; received {ref!r}")


def check_distributions(directory, source, project):
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1, "Expected one wheel and one sdist"
    with zipfile.ZipFile(wheels[0]) as wheel:
        metadata_name = next(n for n in wheel.namelist() if n.endswith("/METADATA"))
        metadata = BytesParser().parsebytes(wheel.read(metadata_name))
        assert metadata["Name"] == project["name"]
        assert metadata["Version"] == project["version"]
        assert metadata["Requires-Python"] == project["requires-python"]
        assert metadata.get_all("Requires-Dist") == project["dependencies"]
        assert metadata["License-Expression"] == project["license"]
        assert set(metadata.get_all("License-File")) == {"LICENSE", "NOTICE"}
        dist_info = metadata_name.rsplit("/", 1)[0]
        for name in ("LICENSE", "NOTICE"):
            assert (
                wheel.read(f"{dist_info}/licenses/{name}")
                == (source / name).read_bytes()
            )
    with tarfile.open(sdists[0]) as sdist:
        for name in ("LICENSE", "NOTICE"):
            member = next(n for n in sdist.getnames() if n.endswith(f"/{name}"))
            assert sdist.extractfile(member).read() == (source / name).read_bytes()
    print("Distribution metadata, LICENSE and NOTICE verified", flush=True)
    return wheels[0], sdists[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-repo", type=Path, default=ROOT.parent / "toolframe-sdk")
    parser.add_argument(
        "--storage-repo", type=Path, default=ROOT.parent / "toolframe-storage-sqlite"
    )
    parser.add_argument(
        "--output", type=Path, help="Empty directory for validated artifacts"
    )
    parser.add_argument(
        "--release-ref", default="", help="Optional refs/tags/v<version> gate"
    )
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 14):
        parser.error("Run this script with Python 3.14 (CI uses 3.14.7)")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    if args.release_ref:
        validate_release_ref(args.release_ref, project["version"])
    output = args.output.resolve() if args.output else None
    if output and output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error(
            "--output must be absent or empty; existing artifacts are never reused"
        )

    with tempfile.TemporaryDirectory(prefix="toolframe-auth-ci-") as temporary:
        workspace = Path(temporary)
        print(f"Fresh validation workspace: {workspace}", flush=True)
        env = dict(os.environ)
        for key in (
            "VIRTUAL_ENV",
            "PYTHONPATH",
            "PYTHONHOME",
            "UV_PROJECT_ENVIRONMENT",
        ):
            env.pop(key, None)
        env.update(
            UV_CACHE_DIR=str(workspace / "uv-cache"),
            UV_PYTHON=sys.executable,
            PYTHONDONTWRITEBYTECODE="1",
        )

        def run(*command, cwd=workspace, **kwargs):
            command = [str(part) for part in command]
            print(f"+ {shlex.join(command)}", flush=True)
            return subprocess.run(command, cwd=cwd, env=env, check=True, **kwargs)

        source = workspace / "toolframe-auth"
        shutil.copytree(
            ROOT,
            source,
            ignore=shutil.ignore_patterns(
                ".git", ".venv", "dist", "__pycache__", ".pytest_cache", ".ruff_cache"
            ),
        )
        wheelhouse = workspace / "dependency-wheels"
        for name, repository in (
            ("toolframe-sdk", args.sdk_repo),
            ("toolframe-storage-sqlite", args.storage_repo),
        ):
            destination = workspace / name
            destination.mkdir()
            archive = run(
                "git",
                "-C",
                repository.resolve(),
                "archive",
                "--format=tar",
                DEPENDENCIES[name],
                stdout=subprocess.PIPE,
            ).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as files:
                files.extractall(destination, filter="data")
            run(
                "uv",
                "build",
                "--no-sources",
                "--wheel",
                "--out-dir",
                wheelhouse,
                destination,
            )

        requirements = workspace / "requirements.txt"
        run(
            "uv",
            "export",
            "--locked",
            "--no-emit-local",
            "--no-hashes",
            "--output-file",
            requirements,
            cwd=source,
            stdout=subprocess.DEVNULL,
        )
        distributions = workspace / "dist"
        # uv builds the wheel from the new sdist when neither format is specified.
        run("uv", "build", "--no-sources", "--out-dir", distributions, source)
        wheel, sdist = check_distributions(distributions, source, project)
        run(
            "uv",
            "tool",
            "run",
            "--isolated",
            "--from",
            "twine==7.0.0",
            "twine",
            "check",
            "--strict",
            wheel,
            sdist,
        )

        test_env = workspace / "test-venv"
        run("uv", "venv", "--python", sys.executable, test_env)
        test_python = test_env / "bin/python"
        dependency_wheels = sorted(wheelhouse.glob("*.whl"))
        assert len(dependency_wheels) == 2
        run(
            "uv",
            "pip",
            "install",
            "--python",
            test_python,
            "--no-sources",
            "--requirements",
            requirements,
            wheel,
            *dependency_wheels,
        )
        run("uv", "pip", "check", "--python", test_python)
        run(
            test_python,
            "-I",
            "-m",
            "ruff",
            "check",
            "src",
            "tests",
            "scripts",
            cwd=source,
        )
        run(test_python, "-I", "-m", "pytest", "-q", cwd=source)

        smoke_env = workspace / "smoke-venv"
        run("uv", "venv", "--python", sys.executable, smoke_env)
        smoke_python = smoke_env / "bin/python"
        sdk_wheel = next(wheelhouse.glob("toolframe_sdk-*.whl"))
        run(
            "uv",
            "pip",
            "install",
            "--python",
            smoke_python,
            "--no-sources",
            "--constraints",
            requirements,
            wheel,
            sdk_wheel,
        )
        run("uv", "pip", "check", "--python", smoke_python)
        run(
            smoke_python,
            "-I",
            "-c",
            """
import importlib.metadata as metadata
import importlib.util
import pathlib
import sys
import toolframe_auth
from toolframe_auth.plugin import plugin
from toolframe_auth.crypto import new_verifier, verifier

location = pathlib.Path(toolframe_auth.__file__).resolve()
assert location.is_relative_to(pathlib.Path(sys.prefix).resolve())
assert metadata.version("toolframe-auth") == sys.argv[1]
assert metadata.version("toolframe-sdk") == "0.2.0"
entry_point, = metadata.distribution("toolframe-auth").entry_points
assert entry_point.group == "toolframe.plugins" and entry_point.name == "auth"
assert entry_point.load() is plugin
assert importlib.util.find_spec("toolframe_storage_sqlite") is None
assert importlib.util.find_spec("pytest") is None
salt, hashed = new_verifier("smoke-password")
assert verifier("smoke-password", salt) == hashed
assert verifier("wrong-password", salt) != hashed
print(f"Wheel import, plugin entry point and scrypt passed: {location}")
""",
            project["version"],
        )
        run("uv", "pip", "freeze", "--python", smoke_python)
        if output:
            output.mkdir(parents=True, exist_ok=True)
            for artifact in (wheel, sdist):
                shutil.copy2(artifact, output / artifact.name)
            print(f"Validated distributions: {output}", flush=True)
        print(
            "All validation passed; temporary environments will be removed", flush=True
        )


if __name__ == "__main__":
    main()
