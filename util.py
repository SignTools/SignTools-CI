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


def rand_str(len: int):
    result = "".join(random.choices(string.ascii_letters + string.digits, k=len))
    return result


def gen_id(bundle_id: str, seed: str, skip_parts: int):
    """
    Encode the bundle id into a different but constant id that
    has the same length and is unique based on the provided seed.
    The bundle id after its skipped parts will be prepended to the seed.
    """
    parts = bundle_id.split(".")
    keep_parts = parts[:skip_parts]
    new_parts = parts[skip_parts:]
    seed = ".".join(new_parts) + seed
    old_state = random.getstate()
    random.seed(seed)
    new_parts = map(lambda x: rand_str(len(x)), new_parts)
    result = ".".join([*keep_parts, *new_parts])
    random.setstate(old_state)
    return result


def kill_xcode(check: bool):
    return run_process("killall", "Xcode", check=check)


def get_prov_profiles():
    """
    The list will be sorted by descending modification time.
    """
    prov_profiles_path = Path.home().joinpath("Library/MobileDevice/Provisioning Profiles")
    result = list(prov_profiles_path.glob("*.mobileprovision"))
    result.sort(key=os.path.getmtime, reverse=True)
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
    print(json.dumps(obj, indent=4, sort_keys=True))
