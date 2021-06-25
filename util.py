from pathlib import Path
import subprocess
import random
import string
from typing import Optional, Mapping, Union

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


def gen_id(bundle_id: str, seed: str):
    """
    Encode the bundle id into a different but constant id that
    has the same length and is unique based on the provided seed.
    """
    old_state = random.getstate()
    random.seed(seed)
    parts = bundle_id.split(".")
    new_parts = map(lambda x: rand_str(len(x)), parts[1:])
    result = ".".join([parts[0], *new_parts])
    random.setstate(old_state)
    return result


def kill_xcode(check: bool):
    return run_process("killall", "Xcode", check=check)


def get_prov_profiles():
    prov_profiles_path = Path.home().joinpath("Library/MobileDevice/Provisioning Profiles")
    return prov_profiles_path.glob("*.mobileprovision")


def open_xcode(project: Optional[Path] = None):
    if project:
        return run_process("open", "-a", "/Applications/Xcode.app", str(project))
    else:
        return run_process("open", "/Applications/Xcode.app")


def debug():
    return run_process("./debug.sh", capture=False)


def read_file(file_path: StrPath):
    with open(file_path) as f:
        return f.read()
