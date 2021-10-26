from pathlib import Path
import shutil
import subprocess
import random
import string
from typing import Any, Optional, Mapping, Union
import json
import os

StrPath = Union[str, Path]


def decode_clean(b: bytes):
    return "" if not b else b.decode("utf-8").strip()


def run_process(
    *cmd: str,
    capture: bool = True,
    check: bool = True,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None
):
    try:
        result = subprocess.run(cmd, capture_output=capture, check=check, env=env, cwd=cwd, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise (
            Exception(
                {
                    "stdout": decode_clean(e.stdout),
                    "stderr": decode_clean(e.stderr),
                }
            )
        ) from e
    return result


def rand_str(len: int, seed: Any = None):
    old_state: object = None
    if seed is not None:
        old_state = random.getstate()
        random.seed(seed)
    result = "".join(random.choices(string.ascii_lowercase + string.digits, k=len))
    if old_state is not None:
        random.setstate(old_state)
    return result


def kill_xcode():
    return run_process("killall", "Xcode", check=False)


def get_prov_profiles():
    prov_profiles_path = Path.home().joinpath("Library/MobileDevice/Provisioning Profiles")
    result = list(prov_profiles_path.glob("*.mobileprovision"))
    return result


def open_xcode(project: Optional[Path] = None):
    if project:
        return run_process("xed", str(project))
    else:
        return run_process("xed")


def debug():
    return run_process("./debug.sh", capture=False)


def read_file(file_path: StrPath):
    with open(file_path) as f:
        return f.read()


def extract_zip(archive: Path, dest_dir: Path):
    if shutil.which("7z"):
        return run_process("7z", "x", str(archive), "-o" + str(dest_dir))
    else:
        return run_process("unzip", "-o", str(archive), "-d", str(dest_dir))


def print_object(obj: Any):
    print(json.dumps(obj, indent=4, sort_keys=True, default=str))
