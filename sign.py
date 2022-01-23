from typing import Optional, List, Tuple
import os
from pathlib import Path
from util import *
import re
import time
import tempfile
from xsign import Signer, SignOpts
import traceback
import sys

secret_url = os.path.expandvars("$SECRET_URL").strip().rstrip("/")
secret_key = os.path.expandvars("$SECRET_KEY")
old_keychain: Optional[str] = None


def network_init():
    return run_process("npm", "install", cwd="node-utils")


def node_upload(file: Path, endpoint: str, capture: bool = True):
    return run_process("node", "node-utils/upload.js", str(file), endpoint, secret_key, capture=capture)


def node_download(downloadUrl: str, outputFile: Path, capture: bool = True):
    return run_process(
        "node",
        "node-utils/download.js",
        downloadUrl,
        secret_key,
        str(outputFile),
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
            extract_tar(next(temp_dir.glob("data.tar*")), temp_dir2)

            for file in temp_dir2.glob("**/*"):
                if file.is_symlink():
                    target = file.resolve()
                    if target.is_absolute():
                        target = temp_dir2.joinpath(str(target)[1:])
                        os.unlink(file)
                        if target.is_dir():
                            shutil.copytree(target, file)
                        else:
                            shutil.copy2(target, file)

            for glob in ["Library/Application Support/*", "Library/Frameworks/*.framework"]:
                for file in temp_dir2.glob(glob):
                    move_merge_replace(file, dest_dir)
            for glob in ["Library/MobileSubstrate/DynamicLibraries/*.dylib", "usr/lib/**/*.dylib"]:
                for file in temp_dir2.glob(glob):
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


def archive_zip(content_dir: Path, dest_file: Path):
    return run_process("zip", "-r", str(dest_file.resolve()), ".", cwd=str(content_dir))


def move_merge_replace(src: Path, dest_dir: Path):
    dest = dest_dir.joinpath(src.name)
    if src == dest:
        return
    if not dest_dir.exists():
        dest_dir.mkdir(parents=True)
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


def inject_tweaks(ipa_dir: Path, tweaks_dir: Path):
    app_dir = next(ipa_dir.glob("Payload/*.app"))
    info = plist_load(app_dir.joinpath("Info.plist"))
    app_bundle_id = info["CFBundleIdentifier"]
    app_bin = app_dir.joinpath(app_dir.stem)
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        for tweak in tweaks_dir.glob("*"):
            print("Processing", tweak.name)
            if tweak.suffix == ".zip":
                extract_zip(tweak, temp_dir)
            elif tweak.suffix == ".tar":
                extract_tar(tweak, temp_dir)
            elif tweak.suffix == ".deb":
                extract_deb(app_bin.name, app_bundle_id, tweak, temp_dir)
            else:
                move_merge_replace(tweak, temp_dir)

        for glob in ["*.framework", "*.dylib"]:
            for file in temp_dir.glob(glob):
                move_merge_replace(file, temp_dir.joinpath("Frameworks"))

        binary_map = {file.name: file for file in temp_dir.glob("**/*") if file_is_type(file, "Mach-O")}
        for binary_path in binary_map.values():
            binary_fixed = Path("@executable_path").joinpath(binary_path.relative_to(temp_dir))
            if binary_path.suffix == ".dylib":
                print("Injecting", binary_path, binary_fixed)
                insert_dylib(app_bin, binary_fixed)
            for link in get_otool_imports(binary_path):
                link_path = Path(link)
                if link_path.name in ["libsubstitute.dylib", "libsubstrate.dylib", "CydiaSubstrate"]:
                    substrate_src = Path("./CydiaSubstrate.framework")
                    substrate_dest = temp_dir.joinpath("Frameworks", "CydiaSubstrate.framework")
                    substrate_path = Path("@executable_path").joinpath(
                        substrate_dest.joinpath("CydiaSubstrate").relative_to(temp_dir)
                    )
                    if not substrate_dest.exists():
                        print("Installing CydiaSubstrate to", substrate_dest)
                        substrate_dest.parent.mkdir(exist_ok=True, parents=True)
                        shutil.copytree(substrate_src, substrate_dest)
                    print("Re-linking", binary_path, link_path, substrate_path)
                    install_name_change(binary_path, link_path, substrate_path)
                elif link_path.name in binary_map:
                    link_fixed = Path("@executable_path").joinpath(binary_map[link_path.name].relative_to(temp_dir))
                    print("Re-linking", binary_path, link_path, link_fixed)
                    install_name_change(binary_path, link_path, link_fixed)

        for file in temp_dir.glob("*"):
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


def run():
    print("Creating keychain...")
    common_names = security_import(Path("cert.p12"), cert_pass, keychain_name)
    if len(common_names) < 1:
        raise Exception("No valid code signing certificate found, aborting.")
    common_name = common_names[0]
    for name in common_names:
        if "Distribution" in name:
            print("Using distribution certificate")
            common_name = name

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

    print("Obtaining files...")
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
