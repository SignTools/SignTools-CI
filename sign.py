#!/usr/bin/env python3

# https://mypy.readthedocs.io/en/stable/runtime_troubles.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime
from __future__ import annotations

import copy
import os
import re
import sys
import time
import traceback
from subprocess import CompletedProcess, PIPE, Popen, TimeoutExpired
import subprocess
from typing import Callable, Dict, List, NamedTuple, Set, Tuple, IO, Any, Optional, Mapping, Union
from pathlib import Path
import plistlib
import shutil
import random
import string
import tempfile
import json

secret_url = os.path.expandvars("$SECRET_URL").strip().rstrip("/")
secret_key = os.path.expandvars("$SECRET_KEY")
old_keychain: Optional[str] = None
StrPath = Union[str, Path]


def safe_glob(input: Path, pattern: str):
    for f in input.glob(pattern):
        if not f.name.startswith("._") and f.name not in [".DS_Store", ".AppleDouble", "__MACOSX"]:
            yield f


def decode_clean(b: bytes):
    return "" if not b else b.decode("utf-8").strip()


def run_process(
    *cmd: str,
    capture: bool = True,
    check: bool = True,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None,
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
    result = list(safe_glob(prov_profiles_path, "*.mobileprovision"))
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
    return run_process("unzip", "-o", str(archive), "-d", str(dest_dir))


def archive_zip(content_dir: Path, dest_file: Path):
    return run_process("zip", "-r", str(dest_file.resolve()), ".", cwd=str(content_dir))


def print_object(obj: Any):
    print(json.dumps(obj, indent=4, sort_keys=True, default=str))


def plutil_convert(plist: Path):
    return run_process("plutil", "-convert", "xml1", "-o", "-", str(plist), capture=True).stdout


def plist_load(plist: Path):
    return plistlib.loads(plutil_convert(plist))


def plist_loads(plist: str) -> Any:
    with tempfile.NamedTemporaryFile(suffix=".plist", mode="w") as f:
        f.write(plist)
        f.flush()
        return plist_load(Path(f.name))


def plist_dump(data: Any, f: IO[bytes]):
    return plistlib.dump(data, f)


def network_init():
    return run_process("npm", "install", cwd="node-utils")


def node_upload(file: Path, endpoint: str, capture: bool = True):
    return run_process("node", "node-utils/upload.js", str(file), endpoint, secret_key, capture=capture)


def node_download(download_url: str, output_file: Path, capture: bool = True):
    return run_process(
        "node",
        "node-utils/download.js",
        download_url,
        secret_key,
        str(output_file),
        capture=capture,
    )


def curl_with_auth(
    url: str,
    form_data: List[Tuple[str, str]] = [],
    output: Optional[Path] = None,
    check: bool = True,
    capture: bool = True,
):
    args = map(lambda x: ["-F", f"{x[0]}={x[1]}"], form_data)
    args = [item for sublist in args for item in sublist]
    if output:
        args.extend(["-o", str(output)])
    return run_process(
        "curl",
        *["-S", "-f", "-L", "-H"],
        f"Authorization: Bearer {secret_key}",
        *args,
        url,
        check=check,
        capture=capture,
    )


def security_set_default_keychain(keychain: str):
    old_keychain = decode_clean(run_process("security", "default-keychain").stdout).strip('"')
    run_process("security", "default-keychain", "-s", keychain)
    return old_keychain


def security_get_keychain_list():
    return map(
        lambda x: x.strip('"'),
        decode_clean(run_process("security", "list-keychains", "-d", "user").stdout).split(),
    )


def security_remove_keychain(keychain: str):
    keychains = security_get_keychain_list()
    keychains = filter(lambda x: keychain not in x, keychains)
    run_process("security", "list-keychains", "-d", "user", "-s", *keychains)
    run_process("security", "delete-keychain", keychain)


def security_import(cert: Path, cert_pass: str, keychain: str) -> List[str]:
    password = "1234"
    keychains = [*security_get_keychain_list(), keychain]
    run_process("security", "create-keychain", "-p", password, keychain),
    run_process("security", "unlock-keychain", "-p", password, keychain),
    run_process("security", "set-keychain-settings", keychain),
    run_process("security", "list-keychains", "-d", "user", "-s", *keychains),
    run_process("security", "import", str(cert), "-P", cert_pass, "-A", "-k", keychain),
    run_process(
        "security",
        *["set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k"],
        password,
        keychain,
    ),
    identity: str = decode_clean(run_process("security", "find-identity", "-p", "appleID", "-v", keychain).stdout)
    return [line.strip('"') for line in re.findall('".*"', identity)]


def osascript(
    script: Path,
    env: Optional[Mapping[str, str]] = None,
    check: bool = True,
    timeout: Optional[float] = None,
):
    return run_process("osascript", str(script), env=env, check=check, timeout=timeout)


def extract_tar(archive: Path, dest_dir: Path):
    return run_process("tar", "-x", "-f", str(archive), "-C" + str(dest_dir))


def extract_deb(app_bin_name: str, app_bundle_id: str, archive: Path, dest_dir: Path):
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        run_process("ar", "x", str(archive.resolve()), cwd=str(temp_dir))
        with tempfile.TemporaryDirectory() as temp_dir2_str:
            temp_dir2 = Path(temp_dir2_str)
            extract_tar(next(safe_glob(temp_dir, "data.tar*")), temp_dir2)

            for file in safe_glob(temp_dir2, "**/*"):
                if file.is_symlink():
                    target = file.resolve()
                    if target.is_absolute():
                        target = temp_dir2.joinpath(str(target)[1:])
                        os.unlink(file)
                        if target.is_dir():
                            shutil.copytree(target, file)
                        else:
                            shutil.copy2(target, file)

            for glob in [
                "Library/Application Support/*/*.bundle",
                "Library/Application Support/*",  # *.bundle, background@2x.png
                "Library/Frameworks/*.framework",
                "usr/lib/*.framework",
            ]:
                for file in safe_glob(temp_dir2, glob):
                    # skip empty directories
                    if file.is_dir() and next(safe_glob(file, "*"), None) is None:
                        continue
                    move_merge_replace(file, dest_dir)
            for glob in [
                "Library/MobileSubstrate/DynamicLibraries/*.dylib",
                "usr/lib/*.dylib",
            ]:
                for file in safe_glob(temp_dir2, glob):
                    if not file.is_file():
                        continue
                    file_plist = file.parent.joinpath(file.stem + ".plist")
                    if file_plist.exists():
                        info = plist_load(file_plist)
                        if "Filter" in info:
                            ok = False
                            if "Bundles" in info["Filter"] and app_bundle_id in info["Filter"]["Bundles"]:
                                ok = True
                            elif "Executables" in info["Filter"] and app_bin_name in info["Filter"]["Executables"]:
                                ok = True
                            if not ok:
                                continue
                    move_merge_replace(file, dest_dir)


def move_merge_replace(src: Path, dest_dir: Path):
    dest = dest_dir.joinpath(src.name)
    if src == dest:
        return
    dest_dir.mkdir(exist_ok=True, parents=True)
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
        shutil.rmtree(src)
    else:
        shutil.copy2(src, dest)
        os.remove(src)


def file_is_type(file: Path, type: str):
    return type in decode_clean(run_process("file", str(file)).stdout)


def get_otool_imports(binary: Path):
    output = decode_clean(run_process("otool", "-L", str(binary)).stdout).splitlines()[1:]
    matches = [re.search(r"(.+)\s\(.+\)", line.strip()) for line in output]
    results = [match.group(1) for match in matches if match]
    if len(output) != len(results):
        raise Exception("Failed to parse imports", {"output": output, "parsed": results})
    return results


def install_name_change(binary: Path, old: Path, new: Path):
    print("Re-linking", binary, old, new)
    return run_process("install_name_tool", "-change", str(old), str(new), str(binary))


def insert_dylib(binary: Path, path: Path):
    return run_process("./insert_dylib", "--inplace", "--no-strip-codesig", str(path), str(binary))


def get_binary_map(dir: Path):
    return {file.name: file for file in safe_glob(dir, "**/*") if file_is_type(file, "Mach-O")}


def codesign(identity: str, component: Path, entitlements: Optional[Path] = None):
    cmd = ["codesign", "--continue", "-f", "--no-strict", "-s", identity]
    if entitlements:
        cmd.extend(["--entitlements", str(entitlements)])
    return run_process(*cmd, str(component))


def codesign_async(identity: str, component: Path, entitlements: Optional[Path] = None):
    cmd = ["codesign", "--continue", "-f", "--no-strict", "-s", identity]
    if entitlements:
        cmd.extend(["--entitlements", str(entitlements)])
    return subprocess.Popen([*cmd, str(component)], stdout=PIPE, stderr=PIPE)


def codesign_dump_entitlements(component: Path) -> Dict[Any, Any]:
    entitlements_str = decode_clean(
        run_process("codesign", "--no-strict", "-d", "--entitlements", ":-", str(component)).stdout
    )
    return plist_loads(entitlements_str)


def binary_replace(pattern: str, f: Path):
    if not f.exists() or not f.is_file():
        raise Exception(f, "does not exist or is a directory")
    return run_process("perl", "-p", "-i", "-e", pattern, str(f))


def security_dump_prov(f: Path):
    return decode_clean(run_process("security", "cms", "-D", "-i", str(f)).stdout)


def exec_retry(name: str, func: Callable[[], CompletedProcess[bytes]]):
    start_time = time.time()
    last_error: Optional[Exception] = None
    retry_count = 0
    while retry_count < 3 and time.time() - start_time < 120:
        try:
            return func()
        except Exception as e:
            last_error = e
            if not isinstance(e.__cause__, TimeoutExpired):
                retry_count += 1
            print(f"{name} errored, retrying")
    if last_error is None:
        raise Exception(f"{name} had an unknown error")
    raise last_error


def xcode_archive(project_dir: Path, scheme_name: str, archive: Path):
    # Xcode needs to be open to "cure" hanging issues
    open_xcode(project_dir)
    try:
        return exec_retry("xcode_archive", lambda: _xcode_archive(project_dir, scheme_name, archive))
    finally:
        kill_xcode()


def _xcode_archive(project_dir: Path, scheme_name: str, archive: Path):
    return run_process(
        "xcodebuild",
        "-allowProvisioningUpdates",
        "-project",
        str(project_dir.resolve()),
        "-scheme",
        scheme_name,
        "clean",
        "archive",
        "-archivePath",
        str(archive.resolve()),
        timeout=20,
    )


def xcode_export(project_dir: Path, archive: Path, export_dir: Path):
    # Xcode needs to be open to "cure" hanging issues
    open_xcode(project_dir)
    try:
        return exec_retry("xcode_export", lambda: _xcode_export(project_dir, archive, export_dir))
    finally:
        kill_xcode()


def _xcode_export(project_dir: Path, archive: Path, export_dir: Path):
    options_plist = export_dir.joinpath("options.plist")
    with options_plist.open("wb") as f:
        plist_dump({"method": "ad-hoc", "iCloudContainerEnvironment": "Production"}, f)
    return run_process(
        "xcodebuild",
        "-allowProvisioningUpdates",
        "-project",
        str(project_dir.resolve()),
        "-exportArchive",
        "-archivePath",
        str(archive.resolve()),
        "-exportPath",
        str(export_dir.resolve()),
        "-exportOptionsPlist",
        str(options_plist.resolve()),
        timeout=20,
    )


def dump_prov(prov_file: Path) -> Dict[Any, Any]:
    s = security_dump_prov(prov_file)
    return plist_loads(s)


def dump_prov_entitlements(prov_file: Path) -> Dict[Any, Any]:
    return dump_prov(prov_file)["Entitlements"]


def popen_check(pipe: Popen[bytes]):
    if pipe.returncode != 0:
        data = {"message": f"{pipe.args} failed with status code {pipe.returncode}"}
        if pipe.stdout:
            data["stdout"] = decode_clean(pipe.stdout.read())
        if pipe.stderr:
            data["stderr"] = decode_clean(pipe.stderr.read())
        raise Exception(data)


def inject_tweaks(ipa_dir: Path, tweaks_dir: Path):
    app_dir = next(safe_glob(ipa_dir, "Payload/*.app"))
    info = plist_load(app_dir.joinpath("Info.plist"))
    app_bundle_id = info["CFBundleIdentifier"]
    app_bin = app_dir.joinpath(app_dir.stem)
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        for tweak in safe_glob(tweaks_dir, "*"):
            print("Processing", tweak.name)
            if tweak.suffix == ".zip":
                extract_zip(tweak, temp_dir)
            elif tweak.suffix == ".tar":
                extract_tar(tweak, temp_dir)
            elif tweak.suffix == ".deb":
                extract_deb(app_bin.name, app_bundle_id, tweak, temp_dir)
            else:
                move_merge_replace(tweak, temp_dir)

        # move files if we know where they need to go
        move_map = {"Frameworks": ["*.framework", "*.dylib"], "PlugIns": ["*.appex"]}
        for dest_dir, globs in move_map.items():
            for glob in globs:
                for file in safe_glob(temp_dir, glob):
                    move_merge_replace(file, temp_dir.joinpath(dest_dir))

        # NOTE: https://iphonedev.wiki/index.php/Cydia_Substrate
        # hooking with "MSHookFunction" does not work in a jailed environment using any of the libs
        # libsubstrate will silently fail and continue, while the rest will crash the app
        # if you're a tweak developer, use fishhook instead, though it only works on public symbols
        support_libs = {
            # Path("./libhooker"): ["libhooker.dylib", "libblackjack.dylib"],
            # Path("./libsubstitute"): ["libsubstitute.dylib", "libsubstitute.0.dylib"],
            Path("./libsubstrate"): ["libsubstrate.dylib", "CydiaSubstrate"],
        }
        aliases = {
            "libsubstitute.0.dylib": "libsubstitute.dylib",
            "CydiaSubstrate": "libsubstrate.dylib",
        }

        binary_map = get_binary_map(temp_dir)

        # inject any user libs
        for binary_path in binary_map.values():
            binary_rel = binary_path.relative_to(temp_dir)
            if (len(binary_rel.parts) == 2 and binary_rel.parent.name == "Frameworks") or (
                len(binary_rel.parts) == 3
                and binary_rel.parent.suffix == ".framework"
                and binary_rel.parent.parent.name == "Frameworks"
            ):
                binary_fixed = Path("@executable_path").joinpath(binary_rel)
                print("Injecting", binary_path, binary_fixed)
                insert_dylib(app_bin, binary_fixed)

        # detect any references to support libs and install missing files
        for binary_path in binary_map.values():
            for link in get_otool_imports(binary_path):
                link_path = Path(link)
                for lib_dir, lib_names in support_libs.items():
                    if link_path.name not in lib_names:
                        continue
                    print("Detected", lib_dir.name)
                    for lib_src in safe_glob(lib_dir, "*"):
                        lib_dest = temp_dir.joinpath("Frameworks").joinpath(lib_src.name)
                        if not lib_dest.exists():
                            print(f"Installing {lib_src.name} to {lib_dest}")
                            lib_dest.parent.mkdir(exist_ok=True, parents=True)
                            shutil.copy2(lib_src, lib_dest)

        # refresh the binary map with any new libs from previous step
        binary_map = get_binary_map(temp_dir)

        # re-link any dependencies
        for binary_path in binary_map.values():
            for link in get_otool_imports(binary_path):
                link_path = Path(link)
                link_name = aliases[link_path.name] if link_path.name in aliases else link_path.name
                if link_name in binary_map:
                    link_fixed = Path("@executable_path").joinpath(binary_map[link_name].relative_to(temp_dir))
                    print("Re-linking", binary_path, link_path, link_fixed)
                    install_name_change(binary_path, link_path, link_fixed)

        for file in safe_glob(temp_dir, "*"):
            move_merge_replace(file, app_dir)


def setup_account(account_name_file: Path, account_pass_file: Path):
    global old_keychain
    print("Using developer account")
    account_name = read_file(account_name_file)
    account_pass = read_file(account_pass_file)
    kill_xcode()
    for prov_profile in get_prov_profiles():
        os.remove(prov_profile)
    old_keychain = security_set_default_keychain(keychain_name)

    print("Logging in (1/2)...")
    open_xcode()
    osascript(
        Path("login1.applescript"),
        {
            **os.environ,
            "ACCOUNT_NAME": account_name,
            "ACCOUNT_PASS": account_pass,
        },
        timeout=30,
    )

    print(
        "Logging in (2/2)...",
        "If you receive a two-factor authentication (2FA) code, please submit it to the web service.",
        sep="\n",
    )
    code_entered = False
    start_time = time.time()
    while True:
        if time.time() - start_time > 60:
            raise Exception("Operation timed out")
        elif osascript(Path("login3.applescript"), check=False, timeout=10).returncode == 0:
            print("Logged in!")
            break
        elif not code_entered:
            account_2fa_file = Path("account_2fa.txt")
            result = curl_with_auth(
                f"{secret_url}/jobs/{job_id}/2fa",
                output=account_2fa_file,
                check=False,
            )
            if result.returncode != 0:
                continue
            account_2fa = read_file(account_2fa_file)
            osascript(
                Path("login2.applescript"),
                {**os.environ, "ACCOUNT_2FA": account_2fa},
                timeout=10,
            )
            code_entered = True
        time.sleep(1)

    teams = decode_clean(osascript(Path("login4.applescript"), timeout=10).stderr).splitlines()
    kill_xcode()
    return teams


class SignOpts(NamedTuple):
    app_dir: Path
    common_name: str
    team_id: str
    is_free_account: bool
    prov_file: Optional[Path]
    bundle_id: Optional[str]
    bundle_name: Optional[str]
    patch_debug: bool
    patch_all_devices: bool
    patch_mac: bool
    patch_file_sharing: bool
    encode_ids: bool
    patch_ids: bool
    force_original_id: bool


class RemapDef(NamedTuple):
    entitlements: List[str]
    prefix: str
    prefix_only: bool
    is_list: bool


class ComponentData(NamedTuple):
    old_bundle_id: str
    bundle_id: str
    entitlements_plist: Path
    info_plist: Path
    embedded_prov: Path


class Signer:
    opts: SignOpts
    main_bundle_id: str
    old_main_bundle_id: str
    mappings: Dict[str, str]
    removed_entitlements: Set[str]
    is_distribution: bool
    components: List[Path]

    def gen_id(self, input_id: str):
        """
        Encodes the provided id into a different but constant id that
        has the same length and is unique based on the team id.
        """
        if not input_id.strip():
            return input_id
        if not self.opts.encode_ids:
            return input_id
        new_parts = map(lambda x: rand_str(len(x), x + self.opts.team_id), input_id.split("."))
        result = ".".join(new_parts)
        return result

    def __init__(self, opts: SignOpts):
        self.opts = opts
        main_app = next(safe_glob(opts.app_dir, "Payload/*.app"))
        main_info_plist = main_app.joinpath("Info.plist")
        main_info: Dict[Any, Any] = plist_load(main_info_plist)
        self.old_main_bundle_id = main_info["CFBundleIdentifier"]
        self.is_distribution = "Distribution" in opts.common_name

        self.mappings: Dict[str, str] = {}
        self.removed_entitlements = set()

        if opts.prov_file:
            if opts.bundle_id is None:
                print("Using original bundle id")
                self.main_bundle_id = self.old_main_bundle_id
            elif opts.bundle_id == "":
                print("Using provisioning profile's application id")
                prov_app_id = dump_prov_entitlements(opts.prov_file)["application-identifier"]
                self.main_bundle_id = prov_app_id[prov_app_id.find(".") + 1 :]
                if self.main_bundle_id == "*":
                    print("Provisioning profile is wildcard, using original bundle id")
                    self.main_bundle_id = self.old_main_bundle_id
            else:
                print("Using custom bundle id")
                self.main_bundle_id = opts.bundle_id
        else:
            if opts.bundle_id:
                print("Using custom bundle id")
                self.main_bundle_id = opts.bundle_id
            elif opts.encode_ids:
                print("Using encoded original bundle id")
                self.main_bundle_id = self.gen_id(self.old_main_bundle_id)
                if not self.opts.force_original_id and self.old_main_bundle_id != self.main_bundle_id:
                    self.mappings[self.old_main_bundle_id] = self.main_bundle_id
            else:
                print("Using original bundle id")
                self.main_bundle_id = self.old_main_bundle_id

        if opts.bundle_name:
            print(f"Setting CFBundleDisplayName to {opts.bundle_name}")
            main_info["CFBundleDisplayName"] = opts.bundle_name

        if self.opts.patch_all_devices:
            # https://developer.apple.com/documentation/bundleresources/information_property_list/minimumosversion
            main_info["MinimumOSVersion"] = "3.0"

        with open("bundle_id.txt", "w") as f:
            if opts.force_original_id:
                f.write(self.old_main_bundle_id)
            else:
                f.write(self.main_bundle_id)

        with main_info_plist.open("wb") as f:
            plist_dump(main_info, f)

        for watch_name in ["com.apple.WatchPlaceholder", "Watch"]:
            watch_dir = main_app.joinpath(watch_name)
            if watch_dir.exists():
                print(f"Removing {watch_name} directory")
                shutil.rmtree(watch_dir)

        component_exts = ["*.app", "*.appex", "*.framework", "*.dylib"]
        # make sure components are ordered depth-first, otherwise signing will overlap and become invalid
        self.components = [item for e in component_exts for item in safe_glob(main_app, "**/" + e)][::-1]
        self.components.append(main_app)

    def __sign_secondary(self, component: Path, workdir: Path):
        # entitlements of frameworks, etc. don't matter, so leave them (potentially) invalid
        print("Signing with original entitlements")
        return codesign_async(self.opts.common_name, component)

    def __sign_primary(self, component: Path, workdir: Path, data: ComponentData):
        if self.opts.prov_file is not None:
            pass
        else:
            with tempfile.TemporaryDirectory() as tmpdir_str:
                tmpdir = Path(tmpdir_str)
                simple_app_dir = tmpdir.joinpath("SimpleApp")
                shutil.copytree("SimpleApp", simple_app_dir)
                xcode_entitlements_plist = simple_app_dir.joinpath("SimpleApp/SimpleApp.entitlements")
                shutil.copy2(data.entitlements_plist, xcode_entitlements_plist)

                simple_app_proj = simple_app_dir.joinpath("SimpleApp.xcodeproj")
                simple_app_pbxproj = simple_app_proj.joinpath("project.pbxproj")
                binary_replace(f"s/BUNDLE_ID_HERE_V9KP12/{data.bundle_id}/g", simple_app_pbxproj)
                binary_replace(f"s/DEV_TEAM_HERE_J8HK5C/{self.opts.team_id}/g", simple_app_pbxproj)

                for prov_profile in get_prov_profiles():
                    os.remove(prov_profile)

                print("Obtaining provisioning profile...")
                print("Archiving app...")
                archive = simple_app_dir.joinpath("archive.xcarchive")
                xcode_archive(simple_app_proj, "SimpleApp", archive)
                if self.is_distribution:
                    print("Exporting app...")
                    for prov_profile in get_prov_profiles():
                        os.remove(prov_profile)
                    xcode_export(simple_app_proj, archive, simple_app_dir)
                    exported_ipa = simple_app_dir.joinpath("SimpleApp.ipa")
                    extract_zip(exported_ipa, simple_app_dir)
                    output_bin = simple_app_dir.joinpath("Payload/SimpleApp.app")
                else:
                    output_bin = archive.joinpath("Products/Applications/SimpleApp.app")

                prov_profiles = list(get_prov_profiles())
                # sometimes Xcode will create multiple prov profiles:
                # - iOS Team Provisioning Profile: *
                # - iOS Team Provisioning Profile: com.test.app
                # - iOS Team Ad Hoc Provisioning Profile: com.test.app
                # by taking the longest named one, we are taking the one which supports the most entitlements
                prov_profiles.sort(key=lambda p: len(dump_prov(p)["Name"]), reverse=True)
                prov_profile = prov_profiles[0]
                shutil.copy2(prov_profile, data.embedded_prov)
                for prov_profile in prov_profiles:
                    os.remove(prov_profile)
                with data.entitlements_plist.open("wb") as f:
                    plist_dump(codesign_dump_entitlements(output_bin), f)

        info = plist_load(data.info_plist)
        entitlements = plist_load(data.entitlements_plist)

        if self.opts.force_original_id:
            print("Keeping original CFBundleIdentifier")
            info["CFBundleIdentifier"] = data.old_bundle_id
        else:
            print(f"Setting CFBundleIdentifier to {data.bundle_id}")
            info["CFBundleIdentifier"] = data.bundle_id

        if self.opts.patch_debug:
            entitlements["get-task-allow"] = True
            print("Enabled app debugging")
        else:
            entitlements.pop("get-task-allow", False)
            print("Disabled app debugging")

        if self.opts.patch_all_devices:
            print("Force enabling support for all devices")
            info.pop("UISupportedDevices", False)
            # https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html
            info["UIDeviceFamily"] = [1, 2, 3, 4]  # iOS, iPadOS, tvOS, watchOS

        if self.opts.patch_mac:
            info.pop("UIRequiresFullScreen", False)
            for device in ["ipad", "iphone", "ipod"]:
                info.pop("UISupportedInterfaceOrientations~" + device, False)
            info["UISupportedInterfaceOrientations"] = [
                "UIInterfaceOrientationPortrait",
                "UIInterfaceOrientationPortraitUpsideDown",
                "UIInterfaceOrientationLandscapeLeft",
                "UIInterfaceOrientationLandscapeRight",
            ]

        if self.opts.patch_file_sharing:
            print("Force enabling file sharing")
            info["UIFileSharingEnabled"] = True
            info["UISupportsDocumentBrowser"] = True

        with data.info_plist.open("wb") as f:
            plist_dump(info, f)
        with data.entitlements_plist.open("wb") as f:
            plist_dump(entitlements, f)

        print("Signing with entitlements:")
        print_object(entitlements)
        return codesign_async(self.opts.common_name, component, data.entitlements_plist)

    def __prepare_primary(
        self,
        component: Path,
        workdir: Path,
    ):
        info_plist = component.joinpath("Info.plist")
        info: Dict[Any, Any] = plist_load(info_plist)
        embedded_prov = component.joinpath("embedded.mobileprovision")
        old_bundle_id = info["CFBundleIdentifier"]
        # create bundle id by suffixing the existing main bundle id with the original suffix
        bundle_id = f"{self.main_bundle_id}{old_bundle_id[len(self.old_main_bundle_id):]}"
        if not self.opts.force_original_id and old_bundle_id != bundle_id:
            if len(old_bundle_id) != len(bundle_id):
                print(
                    f"WARNING: Component's bundle id '{bundle_id}' is different length from the original bundle id '{old_bundle_id}'.",
                    "The signed app may crash!",
                )
            else:
                self.mappings[old_bundle_id] = bundle_id

        with tempfile.NamedTemporaryFile(dir=workdir, suffix=".plist", delete=False) as f:
            entitlements_plist = Path(f.name)

        old_entitlements: Dict[Any, Any]
        try:
            old_entitlements = codesign_dump_entitlements(component)
        except:
            print("Failed to dump entitlements, using empty")
            old_entitlements = {}

        print("Original entitlements:")
        print_object(old_entitlements)

        old_team_id: Optional[str] = old_entitlements.get("com.apple.developer.team-identifier", None)
        if not old_team_id:
            print("Failed to read old team id")
        elif old_team_id != self.opts.team_id:
            if len(old_team_id) != len(self.opts.team_id):
                print("WARNING: Team ID length mismatch:", old_team_id, self.opts.team_id)
            else:
                self.mappings[old_team_id] = self.opts.team_id

        # before 2011 this was known as 'bundle seed id' and could be set freely
        # now it is always equal to team id, but some old apps haven't updated
        old_app_id_prefix: Optional[str] = old_entitlements.get("application-identifier", "").split(".")[0]
        if not old_app_id_prefix:
            old_app_id_prefix = None
            print("Failed to read old app id prefix")
        elif old_app_id_prefix != self.opts.team_id:
            if len(old_app_id_prefix) != len(self.opts.team_id):
                print("WARNING: App ID Prefix length mismatch:", old_app_id_prefix, self.opts.team_id)
            else:
                self.mappings[old_app_id_prefix] = self.opts.team_id

        if self.opts.prov_file is not None:
            shutil.copy2(self.opts.prov_file, embedded_prov)
            # This may cause issues with wildcard entitlements, since they are valid in the provisioning
            # profile, but not when applied to a binary. For example:
            #   com.apple.developer.icloud-services = *
            # Ideally, all such cases should be manually replaced.
            entitlements = dump_prov_entitlements(embedded_prov)

            prov_app_id = entitlements["application-identifier"]
            component_app_id = f"{self.opts.team_id}.{bundle_id}"
            wildcard_app_id = f"{self.opts.team_id}.*"

            # if the prov file has wildcard app id, expand it, or it would be invalid
            if prov_app_id == wildcard_app_id:
                entitlements["application-identifier"] = component_app_id
            elif prov_app_id != component_app_id:
                print(
                    f"WARNING: Provisioning profile's app id '{prov_app_id}' does not match component's app id '{component_app_id}'.",
                    "Using provisioning profile's app id - the component will run, but some functions such as file importing will not work!",
                    sep="\n",
                )

            # if the prov file has wildcard keychain group, expand it, or all signed apps will use the same keychain
            keychain = entitlements.get("keychain-access-groups", [])
            if any(item == wildcard_app_id for item in keychain):
                keychain.clear()
                for item in old_entitlements.get("keychain-access-groups", []):
                    keychain.append(f"{self.opts.team_id}.{item[item.index('.')+1:]}")
        else:
            supported_entitlements = [
                "com.apple.developer.default-data-protection",
                "com.apple.developer.healthkit",
                "com.apple.developer.healthkit.access",
                "com.apple.developer.homekit",
                "com.apple.external-accessory.wireless-configuration",
                "com.apple.security.application-groups",
                "inter-app-audio",
                "get-task-allow",
                "keychain-access-groups",
            ]
            if not self.opts.is_free_account:
                supported_entitlements.extend(
                    [
                        "aps-environment",
                        "com.apple.developer.icloud-container-development-container-identifiers",
                        "com.apple.developer.icloud-container-environment",
                        "com.apple.developer.icloud-container-identifiers",
                        "com.apple.developer.icloud-services",
                        "com.apple.developer.kernel.extended-virtual-addressing",
                        "com.apple.developer.kernel.increased-memory-limit",
                        "com.apple.developer.networking.multipath",
                        "com.apple.developer.networking.networkextension",
                        "com.apple.developer.networking.vpn.api",
                        "com.apple.developer.networking.wifi-info",
                        "com.apple.developer.nfc.readersession.formats",
                        "com.apple.developer.siri",
                        "com.apple.developer.ubiquity-container-identifiers",
                        "com.apple.developer.ubiquity-kvstore-identifier",
                    ]
                )
            entitlements = copy.deepcopy(old_entitlements)
            for entitlement in list(entitlements):
                if entitlement not in supported_entitlements:
                    self.removed_entitlements.add(entitlement)
                    entitlements.pop(entitlement)

            # Taurine jailbreak demands this entitlement, even if blank
            if "keychain-access-groups" not in entitlements:
                entitlements["keychain-access-groups"] = []

            # some apps define iCloud properties but without identifiers
            # this is pointless, but it also causes modern Xcode to fail - remove them
            if not any(
                item
                in [
                    "com.apple.developer.icloud-container-identifiers",
                    "com.apple.developer.ubiquity-container-identifiers",
                    "com.apple.developer.icloud-container-development-container-identifiers",
                ]
                for item in entitlements
            ):
                for entitlement in list(entitlements):
                    if isinstance(entitlement, str) and entitlement.startswith("com.apple.developer.icloud"):
                        print(f"Removing incorrectly used entitlement {entitlement}")
                        self.removed_entitlements.add(entitlement)
                        entitlements.pop(entitlement)

            # make sure the app can be signed in development
            for entitlement, value in {
                "com.apple.developer.icloud-container-environment": "Development",
                "aps-environment": "development",
                "get-task-allow": True,
            }.items():
                if entitlement in entitlements:
                    entitlements[entitlement] = value

            # remap any ids in entitlements, will later byte patch them into various files
            if self.opts.encode_ids:
                for remap_def in (
                    RemapDef(["com.apple.security.application-groups"], "group.", False, True),  # group.com.test.app
                    RemapDef(
                        [
                            "com.apple.developer.icloud-container-identifiers",
                            "com.apple.developer.ubiquity-container-identifiers",
                            "com.apple.developer.icloud-container-development-container-identifiers",
                        ],
                        "iCloud.",
                        False,
                        True,
                    ),  # iCloud.com.test.app
                    #
                    # the "prefix_only" definitions need to be at the end to make sure that the correct
                    # action is taken if the same id is already remapped for non-"prefix_only" ids
                    #
                    RemapDef(
                        ["keychain-access-groups"], self.opts.team_id + ".", True, True
                    ),  # APP_ID_PREFIX.com.test.app
                    RemapDef(
                        ["com.apple.developer.ubiquity-kvstore-identifier"], self.opts.team_id + ".", True, False
                    ),  # APP_ID_PREFIX.com.test.app
                ):
                    for entitlement in remap_def.entitlements:
                        remap_ids: List[str] | str = entitlements.get(entitlement, [])
                        if isinstance(remap_ids, str):
                            remap_ids = [remap_ids]

                        if len(remap_ids) < 1:
                            continue

                        entitlements[entitlement] = []

                        for remap_id in [id[len(remap_def.prefix) :] for id in remap_ids]:
                            if remap_def.prefix_only:
                                # don't change the id as only its prefix needs to be remapped
                                new_id = remap_def.prefix + remap_id
                            else:
                                new_id = remap_def.prefix + self.gen_id(remap_id)
                                self.mappings[remap_def.prefix + remap_id] = new_id

                            entitlements[entitlement].append(new_id)
                            if not remap_def.is_list:
                                entitlements[entitlement] = entitlements[entitlement][0]

        with entitlements_plist.open("wb") as f:
            plist_dump(entitlements, f)

        return ComponentData(old_bundle_id, bundle_id, entitlements_plist, info_plist, embedded_prov)

    def sign(self):
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)

            job_defs: List[Tuple[Path, Optional[ComponentData]]] = []
            for component in self.components:
                print(f"Preparing component {component}")

                if component.suffix in [".appex", ".app"]:
                    job_defs.append((component, self.__prepare_primary(component, tmpdir)))
                else:
                    job_defs.append((component, None))

            print("ID mappings:")
            print_object(self.mappings)
            # ensure all mappings are same length and actually byte patchable
            assert all(len(k) == len(v) for k, v in self.mappings.items())

            print("Removed entitlements:")
            print_object(list(self.removed_entitlements))

            jobs: Dict[Path, subprocess.Popen[bytes]] = {}
            for component, data in job_defs:
                print(f"Processing component {component}")

                for path in list(jobs.keys()):
                    pipe = jobs[path]
                    try:
                        path.relative_to(component)
                    except:
                        continue
                    if pipe.poll() is None:
                        print("Waiting for sub-component to finish signing:", path)
                        pipe.wait()
                    popen_check(pipe)
                    jobs.pop(path)

                sc_info = component.joinpath("SC_Info")
                if sc_info.exists():
                    print(
                        f"WARNING: Found leftover AppStore metadata - removing it.",
                        "If the app is encrypted, it will fail to launch!",
                        sep="\n",
                    )
                    shutil.rmtree(sc_info)

                if self.opts.patch_ids:
                    # make sure patches are the same length
                    patches = {k: v for k, v in self.mappings.items() if len(k) == len(v)}
                    # sort by decreasing length to make sure that there are no overlaps
                    patches = dict(sorted(self.mappings.items(), key=lambda x: len(x[0]), reverse=True))

                    if len(patches) < 1:
                        print("Nothing to patch")
                    else:
                        targets = [
                            x for x in [component, component.joinpath(component.stem)] if x.exists() and x.is_file()
                        ]
                        if data is not None:
                            targets.append(data.info_plist)
                        for target in targets:
                            print(f"Patching {len(patches)} patterns in {target}")
                            for old, new in patches.items():
                                binary_replace(f"s/{re.escape(old)}/{re.escape(new)}/g", target)

                if data is not None:
                    jobs[component] = self.__sign_primary(component, tmpdir, data)
                else:
                    jobs[component] = self.__sign_secondary(component, tmpdir)

            print("Waiting for any remaining components to finish signing")
            for pipe in jobs.values():
                pipe.wait()
                popen_check(pipe)


def run():
    print("Creating keychain...")
    common_names = security_import(Path("cert.p12"), cert_pass, keychain_name)
    if len(common_names) < 1:
        raise Exception("No valid code signing certificate found, aborting.")
    common_names = {
        # "Apple Development" for paid dev account
        # "iPhone Developer" for free dev account, etc
        "Development": next((n for n in common_names if "Develop" in n), None),
        "Distribution": next((n for n in common_names if "Distribution" in n), None),
    }

    if common_names["Development"] is None:
        raise Exception("No development certificate found, aborting.")

    if common_names["Distribution"] is not None:
        print("Using distribution certificate")
        common_name = common_names["Distribution"]
        if "-d" in sign_args:
            raise Exception("Debugging cannot be enabled on distribution certificate, use development.")
    else:
        print("Using development certificate")
        common_name = common_names["Development"]

    prov_profile = Path("prov.mobileprovision")
    account_name_file = Path("account_name.txt")
    account_pass_file = Path("account_pass.txt")
    is_free_account = False
    bundle_name = Path("bundle_name.txt")
    if account_name_file.is_file() and account_pass_file.is_file():
        teams = setup_account(account_name_file, account_pass_file)
        if len(teams) < 1 or teams[0].strip() == "":
            raise Exception("Unable to read account teams")
        if len(teams) == 1 and teams[0].endswith("(Personal Team)"):
            print("Detected free developer account")
            is_free_account = True
    elif prov_profile.is_file():
        print("Using provisioning profile")
    else:
        raise Exception("Nothing to sign with!")

    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        print("Extracting app...")
        extract_zip(Path("unsigned.ipa"), temp_dir)

        tweaks_dir = Path("tweaks")
        if tweaks_dir.exists():
            print("Found tweaks, injecting...")
            inject_tweaks(temp_dir, tweaks_dir)

        print("Signing...")
        Signer(
            SignOpts(
                temp_dir,
                common_name,
                team_id,
                is_free_account,
                prov_profile if prov_profile.is_file() else None,
                "" if "-n" in sign_args else user_bundle_id,
                read_file(bundle_name) if bundle_name.exists() else None,
                "-d" in sign_args,
                "-a" in sign_args,
                "-m" in sign_args,
                "-s" in sign_args,
                "-e" in sign_args,
                "-p" in sign_args,
                "-o" in sign_args,
            )
        ).sign()

        print("Packaging signed IPA...")
        signed_ipa = Path("signed.ipa")
        archive_zip(temp_dir, signed_ipa)

    print("Uploading...")
    node_upload(signed_ipa, f"{secret_url}/jobs/{job_id}/tus/", capture=False)
    file_id = read_file(Path("file_id.txt"))
    bundle_id = read_file(Path("bundle_id.txt"))
    curl_with_auth(f"{secret_url}/jobs/{job_id}/signed", [("file_id", file_id), ("bundle_id", bundle_id)])


if __name__ == "__main__":
    print("Initializing dependencies...")
    network_init()

    print("Downloading job files...")
    job_archive = Path("job.tar")
    node_download(secret_url + "/jobs", job_archive, capture=False)
    extract_tar(job_archive, Path("."))
    os.remove(job_archive)

    cert_pass = read_file("cert_pass.txt")
    sign_args = read_file("args.txt")
    job_id = read_file("id.txt")
    user_bundle_id = read_file("user_bundle_id.txt")
    if user_bundle_id.strip() == "":
        user_bundle_id = None
    team_id = read_file("team_id.txt")
    keychain_name = "ios-signer-" + rand_str(8)

    print("Downloading app...")
    unsigned_ipa = Path("unsigned.ipa")
    node_download(secret_url + f"/jobs/{job_id}/unsigned", unsigned_ipa, capture=False)

    try:
        failed = False
        run()
    except:
        failed = True
        traceback.print_exc()
    finally:
        if failed:
            debug()
        print("Cleaning up...")
        if old_keychain:
            security_set_default_keychain(old_keychain)
            security_remove_keychain(keychain_name)
        if failed:
            curl_with_auth(f"{secret_url}/jobs/{job_id}/fail")
            sys.exit(1)
