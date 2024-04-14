#!/usr/bin/env python3

import copy
import os
import re
import sys
import time
import traceback
from subprocess import PIPE, Popen
import subprocess
from typing import Dict, List, NamedTuple, Set, Tuple, IO, Any, Optional, Mapping, Union
from pathlib import Path
import plistlib
import shutil
import random
import string
import tempfile
import json
from multiprocessing.pool import ThreadPool

secret_url = os.path.expandvars("$SECRET_URL").strip().rstrip("/")
secret_key = os.path.expandvars("$SECRET_KEY")
StrPath = Union[str, Path]


def safe_glob(input: Path, pattern: str):
    for f in sorted(input.glob(pattern)):
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


def run_process_async(
    *cmd: str,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[str] = None,
):
    return subprocess.Popen(cmd, env=env, cwd=cwd, stdout=PIPE, stderr=PIPE)


def rand_str(len: int, seed: Any = None):
    old_state: object = None
    if seed is not None:
        old_state = random.getstate()
        random.seed(seed)
    result = "".join(random.choices(string.ascii_lowercase + string.digits, k=len))
    if old_state is not None:
        random.setstate(old_state)
    return result


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

            rootless_dir = temp_dir2 / "var" / "jb"
            if rootless_dir.is_dir():
                temp_dir2 = rootless_dir

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


def codesign_async(identity: str, component: Path, entitlements: Optional[Path] = None):
    cmd = ["codesign", "--continue", "-f", "--no-strict", "-s", identity]
    if entitlements:
        cmd.extend(["--entitlements", str(entitlements)])
    return run_process_async(*cmd, str(component))


def clean_dev_portal_name(name: str):
    return re.sub("[^0-9a-zA-Z]+", " ", name).strip()


def fastlane_auth(account_name: str, account_pass: str, team_id: str):
    my_env = os.environ.copy()
    my_env["FASTLANE_USER"] = account_name
    my_env["FASTLANE_PASSWORD"] = account_pass
    my_env["FASTLANE_TEAM_ID"] = team_id

    auth_pipe = subprocess.Popen(
        # enable copy to clipboard so we're not interactively prompted
        ["fastlane", "spaceauth", "--copy_to_clipboard"],
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        env=my_env,
    )

    start_time = time.time()
    while True:
        if time.time() - start_time > 60:
            raise Exception("Operation timed out")
        else:
            result = auth_pipe.poll()
            if result == 0:
                print("Logged in!")
                break
            elif result is not None:
                raise Exception(f"Error logging in, got result: {result}")

            account_2fa_file = Path("account_2fa.txt")
            result = curl_with_auth(
                f"{secret_url}/jobs/{job_id}/2fa",
                output=account_2fa_file,
                check=False,
            )
            if result.returncode == 0:
                account_2fa = read_file(account_2fa_file)
                auth_pipe.communicate((account_2fa + "\n").encode())
        time.sleep(1)


def fastlane_register_app_extras(
    my_env: Dict[Any, Any],
    bundle_id: str,
    extra_type: str,
    extra_prefix: str,
    matchable_entitlements: List[str],
    entitlements: Dict[Any, Any],
):
    matched_ids: Set[str] = set()
    for k, v in entitlements.items():
        if k in matchable_entitlements:
            if type(v) is list:
                matched_ids.update(v)
            elif type(v) is str:
                matched_ids.add(v)
            else:
                raise Exception(f"Unknown value type for {v}: {type(v)}")

    # ensure all ids are prefixed correctly or registration will fail
    # some matchable entitlements are incorrectly prefixed with team id
    matched_ids = set(
        id if id.startswith(extra_prefix) else extra_prefix + id[id.index(".") + 1 :] for id in matched_ids
    )

    jobs: List[Popen[bytes]] = []

    for id in matched_ids:
        jobs.append(
            run_process_async(
                "fastlane",
                "produce",
                extra_type,
                "--skip_itc",
                "-g",
                id,
                "-n",
                clean_dev_portal_name(f"ST {id}"),
                env=my_env,
            )
        )

    for pipe in jobs:
        if pipe.poll() is None:
            pipe.wait()
        popen_check(pipe)

    run_process(
        "fastlane",
        "produce",
        f"associate_{extra_type}",
        "--skip_itc",
        "--app_identifier",
        bundle_id,
        *matched_ids,
        env=my_env,
    )


def fastlane_register_app(
    account_name: str, account_pass: str, team_id: str, bundle_id: str, entitlements: Dict[Any, Any]
):
    my_env = os.environ.copy()
    my_env["FASTLANE_USER"] = account_name
    my_env["FASTLANE_PASSWORD"] = account_pass
    my_env["FASTLANE_TEAM_ID"] = team_id

    # no-op if already exists
    run_process(
        "fastlane",
        "produce",
        "create",
        "--skip_itc",
        "--app_identifier",
        bundle_id,
        "--app-name",
        clean_dev_portal_name(f"ST {bundle_id}"),
        env=my_env,
    )

    supported_services = [
        "--push-notification",
        "--health-kit",
        "--home-kit",
        "--wireless-accessory",
        "--inter-app-audio",
        "--extended-virtual-address-space",
        "--multipath",
        "--network-extension",
        "--personal-vpn",
        "--access-wifi",
        "--nfc-tag-reading",
        "--siri-kit",
        "--associated-domains",
        "--icloud",
        "--app-group",
    ]

    # clear any previous services
    run_process(
        "fastlane",
        "produce",
        "disable_services",
        "--skip_itc",
        "--app_identifier",
        bundle_id,
        *supported_services,
        env=my_env,
    )

    icloud_entitlements = [
        "com.apple.developer.icloud-container-development-container-identifiers",
        "com.apple.developer.icloud-container-identifiers",
        "com.apple.developer.ubiquity-container-identifiers",
        "com.apple.developer.ubiquity-kvstore-identifier",
    ]

    group_entitlements = ["com.apple.security.application-groups"]

    entitlement_map: Dict[str, Tuple[str, ...]] = {
        "aps-environment": tuple(["--push-notification"]),  # iOS
        "com.apple.developer.aps-environment": tuple(["--push-notification"]),  # macOS
        "com.apple.developer.healthkit": tuple(["--health-kit"]),
        "com.apple.developer.homekit": tuple(["--home-kit"]),
        "com.apple.external-accessory.wireless-configuration": tuple(["--wireless-accessory"]),
        "inter-app-audio": tuple(["--inter-app-audio"]),
        "com.apple.developer.kernel.extended-virtual-addressing": tuple(["--extended-virtual-address-space"]),
        "com.apple.developer.networking.multipath": tuple(["--multipath"]),
        "com.apple.developer.networking.networkextension": tuple(["--network-extension"]),
        "com.apple.developer.networking.vpn.api": tuple(["--personal-vpn"]),
        "com.apple.developer.networking.wifi-info": tuple(["--access-wifi"]),
        "com.apple.developer.nfc.readersession.formats": tuple(["--nfc-tag-reading"]),
        "com.apple.developer.siri": tuple(["--siri-kit"]),
        "com.apple.developer.associated-domains": tuple(["--associated-domains"]),
    }
    for k in icloud_entitlements:
        entitlement_map[k] = tuple(["--icloud", "xcode6_compatible"])
    for k in group_entitlements:
        entitlement_map[k] = tuple(["--app-group"])

    service_flags = set(entitlement_map[f] for f in entitlements.keys() if f in entitlement_map)
    service_flags = [item for sublist in service_flags for item in sublist]

    print("Enabling services:", service_flags)

    run_process(
        "fastlane",
        "produce",
        "enable_services",
        "--skip_itc",
        "--app_identifier",
        bundle_id,
        *service_flags,
        env=my_env,
    )

    app_extras = [("cloud_container", "iCloud.", icloud_entitlements), ("group", "group.", group_entitlements)]
    with ThreadPool(len(app_extras)) as p:
        p.starmap(
            lambda extra_type, extra_prefix, matchable_entitlements: fastlane_register_app_extras(
                my_env, bundle_id, extra_type, extra_prefix, matchable_entitlements, entitlements
            ),
            app_extras,
        )


def fastlane_get_prov_profile(
    account_name: str, account_pass: str, team_id: str, bundle_id: str, prov_type: str, platform: str, out_file: Path
):
    my_env = os.environ.copy()
    my_env["FASTLANE_USER"] = account_name
    my_env["FASTLANE_PASSWORD"] = account_pass
    my_env["FASTLANE_TEAM_ID"] = team_id

    with tempfile.TemporaryDirectory() as tmpdir_str:
        run_process(
            "fastlane",
            "sigh",
            "renew",
            "--app_identifier",
            bundle_id,
            "--provisioning_name",
            clean_dev_portal_name(f"ST {bundle_id} {prov_type}"),
            "--force",
            "--skip_install",
            "--include_mac_in_profiles",
            "--platform",
            platform,
            "--" + prov_type,
            "--output_path",
            tmpdir_str,
            "--filename",
            "prov.mobileprovision",
            env=my_env,
        )
        shutil.copy2(Path(tmpdir_str).joinpath("prov.mobileprovision"), out_file)


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
    main_app = get_main_app_path(ipa_dir)
    main_info_plist = get_info_plist_path(main_app)
    info = plist_load(main_info_plist)
    app_bundle_id = info["CFBundleIdentifier"]
    app_bundle_exe = info["CFBundleExecutable"]
    is_mac_app = main_info_plist.parent.name == "Contents"

    if is_mac_app:
        base_dir = main_info_plist.parent
        app_bin = base_dir.joinpath("MacOS", app_bundle_exe)
        base_load_path = Path("@executable_path").joinpath("..")
    else:
        base_dir = main_app
        app_bin = base_dir.joinpath(app_bundle_exe)
        base_load_path = Path("@executable_path")

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
                binary_fixed = base_load_path.joinpath(binary_rel)
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
                    link_fixed = base_load_path.joinpath(binary_map[link_name].relative_to(temp_dir))
                    print("Re-linking", binary_path, link_path, link_fixed)
                    install_name_change(binary_path, link_path, link_fixed)

        for file in safe_glob(temp_dir, "*"):
            move_merge_replace(file, base_dir)


class SignOpts(NamedTuple):
    app_dir: Path
    common_name: str
    team_id: str
    account_name: str
    account_pass: str
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
    entitlements: Dict[Any, Any]
    info_plist: Path


def get_info_plist_path(app_dir: Path):
    return min(list(safe_glob(app_dir, "**/Info.plist")), key=lambda p: len(str(p)))


def get_main_app_path(app_dir: Path):
    return min(list(safe_glob(app_dir, "**/*.app")), key=lambda p: len(str(p)))


class Signer:
    opts: SignOpts
    main_bundle_id: str
    old_main_bundle_id: str
    mappings: Dict[str, str]
    removed_entitlements: Set[str]
    is_distribution: bool
    components: List[Path]
    is_mac_app: bool

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

    def __get_application_identifier_key(self):
        return "com.apple.application-identifier" if self.is_mac_app else "application-identifier"

    def __get_aps_environment_key(self):
        return "com.apple.developer.aps-environment" if self.is_mac_app else "aps-environment"

    def __init__(self, opts: SignOpts):
        self.opts = opts
        main_app = get_main_app_path(opts.app_dir)
        main_info_plist = get_info_plist_path(main_app)
        main_info: Dict[Any, Any] = plist_load(main_info_plist)
        self.old_main_bundle_id = main_info["CFBundleIdentifier"]
        self.is_distribution = "Distribution" in opts.common_name
        self.is_mac_app = main_info_plist.parent.name == "Contents"

        if self.is_distribution and self.is_mac_app:
            raise Exception(
                "Cannot use distribution certificate for macOS as the platform does not support adhoc provisioning profiles."
            )

        self.mappings: Dict[str, str] = {}
        self.removed_entitlements = set()

        if opts.prov_file:
            if opts.bundle_id is None:
                print("Using original bundle id")
                self.main_bundle_id = self.old_main_bundle_id
            elif opts.bundle_id == "":
                print("Using provisioning profile's application id")
                prov_app_id = dump_prov_entitlements(opts.prov_file)[self.__get_application_identifier_key()]
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
            if self.is_mac_app:
                # https://developer.apple.com/documentation/bundleresources/information_property_list/lsminimumsystemversion
                main_info["LSMinimumSystemVersion"] = "10.0"
            else:
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

        component_exts = ["*.app", "*.appex", "*.framework", "*.dylib", "PlugIns/*.bundle"]
        # make sure components are ordered depth-first, otherwise signing will overlap and become invalid
        self.components = [item for e in component_exts for item in safe_glob(main_app, "**/" + e)][::-1]
        self.components.append(main_app)

    def __sign_secondary(self, component: Path, tmpdir: Path):
        # entitlements of frameworks, etc. don't matter, so leave them (potentially) invalid
        print("Signing with original entitlements")
        return codesign_async(self.opts.common_name, component)

    def __sign_primary(self, component: Path, tmpdir: Path, data: ComponentData):
        info = plist_load(data.info_plist)

        if self.opts.force_original_id:
            print("Keeping original CFBundleIdentifier")
            info["CFBundleIdentifier"] = data.old_bundle_id
        else:
            print(f"Setting CFBundleIdentifier to {data.bundle_id}")
            info["CFBundleIdentifier"] = data.bundle_id

        if self.opts.patch_debug:
            data.entitlements["get-task-allow"] = True
            print("Enabled app debugging")
        else:
            data.entitlements.pop("get-task-allow", False)
            print("Disabled app debugging")

        if not self.is_mac_app:
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

        print("Signing with entitlements:")
        print_object(data.entitlements)

        # iOS   : MyApp.app/embedded.mobileprovision
        # macOS : MyApp.app/Contents/embedded.provisionprofile
        embedded_prov = data.info_plist.parent.joinpath(
            "embedded.provisionprofile" if self.is_mac_app else "embedded.mobileprovision"
        )
        if self.opts.prov_file is not None:
            shutil.copy2(self.opts.prov_file, embedded_prov)
        else:
            print("Registering component with Apple...")
            fastlane_register_app(
                self.opts.account_name, self.opts.account_pass, self.opts.team_id, data.bundle_id, data.entitlements
            )

            print("Generating provisioning profile...")
            prov_type = "adhoc" if self.is_distribution else "development"
            platform = "macos" if self.is_mac_app else "ios"
            fastlane_get_prov_profile(
                self.opts.account_name,
                self.opts.account_pass,
                self.opts.team_id,
                data.bundle_id,
                prov_type,
                platform,
                embedded_prov,
            )

        entitlements_plist = Path(tmpdir).joinpath("entitlements.plist")
        with open(entitlements_plist, "wb") as f:
            plist_dump(data.entitlements, f)

        print("Signing component...")
        return codesign_async(self.opts.common_name, component, entitlements_plist)

    def __prepare_primary(
        self,
        component: Path,
        workdir: Path,
    ):
        info_plist = get_info_plist_path(component)
        info: Dict[Any, Any] = plist_load(info_plist)
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
        old_app_id_prefix: Optional[str] = old_entitlements.get(self.__get_application_identifier_key(), "").split(
            "."
        )[0]
        if not old_app_id_prefix:
            old_app_id_prefix = None
            print("Failed to read old app id prefix")
        elif old_app_id_prefix != self.opts.team_id:
            if len(old_app_id_prefix) != len(self.opts.team_id):
                print("WARNING: App ID Prefix length mismatch:", old_app_id_prefix, self.opts.team_id)
            else:
                self.mappings[old_app_id_prefix] = self.opts.team_id

        if self.opts.prov_file is not None:
            # This may cause issues with wildcard entitlements, since they are valid in the provisioning
            # profile, but not when applied to a binary. For example:
            #   com.apple.developer.icloud-services = *
            # Ideally, all such cases should be manually replaced.
            entitlements = dump_prov_entitlements(self.opts.prov_file)

            prov_app_id = entitlements[self.__get_application_identifier_key()]
            component_app_id = f"{self.opts.team_id}.{bundle_id}"
            wildcard_app_id = f"{self.opts.team_id}.*"

            # if the prov file has wildcard app id, expand it, or it would be invalid
            if prov_app_id == wildcard_app_id:
                entitlements[self.__get_application_identifier_key()] = component_app_id
            elif prov_app_id != component_app_id:
                print(
                    f"WARNING: Provisioning profile's app id '{prov_app_id}' does not match component's app id '{component_app_id}'.",
                    "Using provisioning profile's app id - the component will run, but some functions such as file importing will not work!",
                    sep="\n",
                )

            keychain: Optional[List[str]] = entitlements.get("keychain-access-groups", None)
            old_keychain: Optional[List[str]] = old_entitlements.get("keychain-access-groups", None)
            if old_keychain is None:
                entitlements.pop("keychain-access-groups", None)
            # if the prov file has wildcard keychain group, expand it, or all signed apps will use the same keychain
            elif keychain and any(item == wildcard_app_id for item in keychain):
                keychain.clear()
                for item in old_keychain:
                    keychain.append(f"{self.opts.team_id}.{item[item.index('.')+1:]}")
        else:
            supported_entitlements = [
                self.__get_application_identifier_key(),
                "com.apple.developer.team-identifier",
                "com.apple.developer.healthkit",
                "com.apple.developer.healthkit.access",
                "com.apple.developer.homekit",
                "com.apple.external-accessory.wireless-configuration",
                "com.apple.security.application-groups",
                "inter-app-audio",
                "get-task-allow",
                "keychain-access-groups",
                self.__get_aps_environment_key(),
                "com.apple.developer.icloud-container-development-container-identifiers",
                "com.apple.developer.icloud-container-environment",
                "com.apple.developer.icloud-container-identifiers",
                "com.apple.developer.icloud-services",
                "com.apple.developer.kernel.extended-virtual-addressing",
                "com.apple.developer.networking.multipath",
                "com.apple.developer.networking.networkextension",
                "com.apple.developer.networking.vpn.api",
                "com.apple.developer.networking.wifi-info",
                "com.apple.developer.nfc.readersession.formats",
                "com.apple.developer.siri",
                "com.apple.developer.ubiquity-container-identifiers",
                "com.apple.developer.ubiquity-kvstore-identifier",
                "com.apple.developer.associated-domains",
                # macOS only
                "com.apple.security.app-sandbox",
                "com.apple.security.assets.pictures.read-write",
                "com.apple.security.cs.allow-jit",
                "com.apple.security.cs.allow-unsigned-executable-memory",
                "com.apple.security.cs.disable-library-validation",
                "com.apple.security.device.audio-input",
                "com.apple.security.device.bluetooth",
                "com.apple.security.device.usb",
                "com.apple.security.files.user-selected.read-only",
                "com.apple.security.files.user-selected.read-write",
                "com.apple.security.network.client",
                "com.apple.security.network.server",
            ]
            entitlements = copy.deepcopy(old_entitlements)
            for entitlement in list(entitlements):
                if entitlement not in supported_entitlements:
                    self.removed_entitlements.add(entitlement)
                    entitlements.pop(entitlement)

            # make sure environment-sensitive entitlements are set correctly
            for entitlement, value in {
                "com.apple.developer.icloud-container-environment": (
                    "Production" if self.is_distribution else "Development"
                ),
                self.__get_aps_environment_key(): "production" if self.is_distribution else "development",
                "get-task-allow": False if self.is_distribution else True,
            }.items():
                if entitlement in entitlements:
                    entitlements[entitlement] = value

            # change identifiers that don't need to be remapped
            entitlements["com.apple.developer.team-identifier"] = self.opts.team_id
            entitlements[self.__get_application_identifier_key()] = f"{self.opts.team_id}.{bundle_id}"

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
                    ),  # JF8WQ0B38Z.com.test.app
                    RemapDef(
                        ["com.apple.developer.ubiquity-kvstore-identifier"], self.opts.team_id + ".", False, False
                    ),  # JF8WQ0B38Z.com.test.app
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

        return ComponentData(old_bundle_id, bundle_id, entitlements, info_plist)

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

            if self.opts.prov_file is None:
                print(
                    "Logging in...",
                    "If you receive a two-factor authentication (2FA) code, please submit it to the web service.",
                    sep="\n",
                )
                fastlane_auth(self.opts.account_name, self.opts.account_pass, self.opts.team_id)

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

    if common_names["Distribution"] is not None:
        print("Using distribution certificate")
        common_name = common_names["Distribution"]
        if "-d" in sign_args:
            raise Exception("Debugging cannot be enabled on distribution certificate, use development.")
    elif common_names["Development"] is not None:
        print("Using development certificate")
        common_name = common_names["Development"]
    else:
        raise Exception("Unrecognized code signing certificate, aborting.")

    prov_profile = Path("prov.mobileprovision")
    account_name_file = Path("account_name.txt")
    account_pass_file = Path("account_pass.txt")
    bundle_name = Path("bundle_name.txt")
    if account_name_file.is_file() and account_pass_file.is_file():
        print("Using developer account")
    elif prov_profile.is_file():
        print("Using provisioning profile")
    else:
        raise Exception("Developer account or provisioning profile required, found none.")

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
                read_file(account_name_file) if account_name_file.is_file() else "",
                read_file(account_pass_file) if account_pass_file.is_file() else "",
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

        print("Packaging signed app...")
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

    failed = False
    try:
        run()
    except:
        failed = True
        traceback.print_exc()
    finally:
        print("Cleaning up...")
        security_remove_keychain(keychain_name)
        if failed:
            curl_with_auth(f"{secret_url}/jobs/{job_id}/fail")
            sys.exit(1)
