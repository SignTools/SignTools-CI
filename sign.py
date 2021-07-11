from typing import Optional, List, Tuple
import os
from pathlib import Path
from util import *
import re
import time
import tempfile
import xsign
import shutil
import traceback
import sys

secret_url = os.path.expandvars("$SECRET_URL").strip().rstrip("/")
secret_key = os.path.expandvars("$SECRET_KEY")
old_keychain: Optional[str] = None


def curl_with_auth(
    url: str,
    form_data: List[Tuple[str, str]] = [],
    output: Optional[Path] = None,
    check: bool = True,
):
    args = map(lambda x: ["-F", f"{x[0]}={x[1]}"], form_data)
    args = [item for sublist in args for item in sublist]
    if output:
        args.extend(["-o", str(output)])
    return run_process(
        "curl",
        *["-s", "-S", "-f", "-L", "-H"],
        f"Authorization: Bearer {secret_key}",
        *args,
        url,
        check=check,
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


def security_import(cert: Path, cert_pass: str, keychain: str) -> str:
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
    return re.findall('".*"', identity)[0].strip('"')


def osascript(
    script: Path,
    env: Optional[Mapping[str, str]] = None,
    check: bool = True,
    timeout: Optional[float] = None,
):
    return run_process("osascript", str(script), env=env, check=check, timeout=timeout)


def extract_zip(archive: Path, dest_dir: Path):
    if shutil.which("7z"):
        return run_process("7z", "x", str(archive), "-o" + str(dest_dir))
    else:
        return run_process("unzip", "-o", str(archive), "-d", str(dest_dir))


def extract_tar(archive: Path, dest_dir: Path):
    return run_process("tar", "-x", "-f", str(archive), "-C" + str(dest_dir))


def archive_zip(content_dir: Path, dest_file: Path):
    return run_process("zip", "-r", str(dest_file.resolve()), ".", cwd=str(content_dir))


def setup_account(account_name_file: Path, account_pass_file: Path):
    global old_keychain
    print("Using developer account")
    account_name = read_file(account_name_file)
    account_pass = read_file(account_pass_file)
    kill_xcode(False)
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

    if osascript(Path("login4.applescript"), check=False).returncode != 0:
        raise Exception("Certificate is revoked. Please provide a new one.")

    kill_xcode(True)


def run():
    print("Creating keychain...")
    common_name = security_import(Path("cert.p12"), cert_pass, keychain_name)
    if not common_name:
        raise Exception("No valid code signing certificate found, aborting.")

    prov_profile = Path("prov.mobileprovision")
    account_name_file = Path("account_name.txt")
    account_pass_file = Path("account_pass.txt")
    if account_name_file.is_file() and account_pass_file.is_file():
        setup_account(account_name_file, account_pass_file)
    elif prov_profile.is_file():
        print("Using provisioning profile")
    else:
        raise Exception("Nothing to sign with!")

    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        print("Extracting app...")
        extract_zip(Path("unsigned.ipa"), temp_dir)

        print("Signing...")
        xsign.sign(
            xsign.SignOpts(
                temp_dir,
                common_name,
                team_id,
                prov_profile if prov_profile.is_file() else None,
                "" if "-n" in sign_args else user_bundle_id,
                "-d" in sign_args,
                "-a" in sign_args,
                "-s" in sign_args,
            )
        )

        print("Packaging signed IPA...")
        signed_ipa = Path("signed.ipa")
        archive_zip(temp_dir, signed_ipa)

    print("Uploading...")
    bundle_id = read_file(Path("bundle_id.txt"))
    curl_with_auth(
        f"{secret_url}/jobs/{job_id}/signed",
        [("file", "@" + str(signed_ipa)), ("bundle_id", bundle_id)],
    )


if __name__ == "__main__":
    print("Obtaining files...")
    job_archive = Path("job.tar")
    curl_with_auth(secret_url + "/jobs", output=job_archive)
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
        run()
    except:
        traceback.print_exc()
        # debug()
        print("Cleaning up...")
        curl_with_auth(f"{secret_url}/jobs/{job_id}/fail")
        if old_keychain:
            security_set_default_keychain(old_keychain)
        security_remove_keychain(keychain_name)
        sys.exit(1)
