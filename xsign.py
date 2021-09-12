# https://mypy.readthedocs.io/en/stable/runtime_troubles.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime
from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess, PIPE, Popen, TimeoutExpired
import tempfile
import shutil
from typing import Any, Callable, Dict, Optional, NamedTuple
import re
import os
from util import *
import time
import plistlib
import copy


def codesign(identity: str, component: Path, entitlements: Optional[Path] = None):
    cmd = ["/usr/bin/codesign", "--continue", "-f", "--no-strict", "-s", identity]
    if entitlements:
        cmd.extend(["--entitlements", str(entitlements)])
    return run_process(*cmd, str(component))


def codesign_async(identity: str, component: Path, entitlements: Optional[Path] = None):
    cmd = ["/usr/bin/codesign", "--continue", "-f", "--no-strict", "-s", identity]
    if entitlements:
        cmd.extend(["--entitlements", str(entitlements)])
    return subprocess.Popen([*cmd, str(component)], stdout=PIPE, stderr=PIPE)


def codesign_dump_entitlements(component: Path) -> Dict[Any, Any]:
    entitlements_str = decode_clean(
        run_process("/usr/bin/codesign", "--no-strict", "-d", "--entitlements", ":-", str(component)).stdout
    )
    return plistlib.loads(entitlements_str.encode("utf-8"))


def binary_replace(pattern: str, f: Path):
    return run_process("perl", "-p", "-i", "-e", pattern, str(f))


def security_dump_prov(f: Path):
    return decode_clean(run_process("security", "cms", "-D", "-i", str(f)).stdout)


def exec_retry(name: str, func: Callable[[], CompletedProcess[bytes]]):
    start_time = time.time()
    last_error: Optional[Exception] = None
    retry_count = 0
    while retry_count < 3 and time.time() - start_time < 90:
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
        kill_xcode(True)


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
        kill_xcode(True)


def _xcode_export(project_dir: Path, archive: Path, export_dir: Path):
    options_plist = export_dir.joinpath("options.plist")
    with options_plist.open("wb") as f:
        plistlib.dump({"method": "ad-hoc", "iCloudContainerEnvironment": "Production"}, f)
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


def dump_prov_entitlements(prov_file: Path) -> Dict[Any, Any]:
    s = security_dump_prov(prov_file)
    return plistlib.loads(s.encode("utf-8"))["Entitlements"]


def popen_check(pipe: Popen[bytes]):
    if pipe.returncode != 0:
        data = {"message": f"{pipe.args} failed with status code {pipe.returncode}"}
        if pipe.stdout:
            data["stdout"] = decode_clean(pipe.stdout.read())
        if pipe.stderr:
            data["stderr"] = decode_clean(pipe.stderr.read())
        raise Exception(data)


class SignOpts(NamedTuple):
    app_dir: Path
    common_name: str
    team_id: str
    prov_file: Optional[Path]
    bundle_id: Optional[str]
    bundle_name: Optional[str]
    patch_debug: bool
    patch_all_devices: bool
    patch_file_sharing: bool
    encode_ids: bool
    patch_ids: bool
    force_original_id: bool


def sign(opts: SignOpts):
    main_app = next(opts.app_dir.glob("Payload/*.app"))
    main_info_plist = main_app.joinpath("Info.plist")
    with main_info_plist.open("rb") as f:
        main_info: Dict[Any, Any] = plistlib.load(f)
    old_main_bundle_id = main_info["CFBundleIdentifier"]
    is_distribution = "Distribution" in opts.common_name

    if opts.prov_file:
        if opts.bundle_id is None:
            print("Using original bundle id")
            main_bundle_id = old_main_bundle_id
        elif opts.bundle_id == "":
            print("Using provisioning profile's application id")
            with tempfile.TemporaryDirectory() as tmpdir_str:
                prov_app_id = dump_prov_entitlements(opts.prov_file)["application-identifier"]
                main_bundle_id = prov_app_id[prov_app_id.find(".") + 1 :]
                if "*" in main_bundle_id:
                    print("Provisioning profile is wildcard, using original bundle id")
                    main_bundle_id = old_main_bundle_id
        else:
            print("Using custom bundle id")
            main_bundle_id = opts.bundle_id
    else:
        if opts.bundle_id:
            print("Using custom bundle id")
            main_bundle_id = opts.bundle_id
        elif opts.encode_ids:
            print("Using encoded original bundle id")
            seed = old_main_bundle_id + opts.team_id
            main_bundle_id = gen_id(old_main_bundle_id, seed, 1)
        else:
            print("Using original bundle id")
            main_bundle_id = old_main_bundle_id

    if opts.bundle_name:
        print(f"Setting CFBundleDisplayName to {opts.bundle_name}")
        main_info["CFBundleDisplayName"] = opts.bundle_name

    with open("bundle_id.txt", "w") as f:
        if opts.force_original_id:
            f.write(old_main_bundle_id)
        else:
            f.write(main_bundle_id)

    with main_info_plist.open("wb") as f:
        plistlib.dump(main_info, f)

    component_exts = ["*.app", "*.appex", "*.framework", "*.dylib"]
    # make sure components are ordered depth-first, otherwise signing will overlap and become invalid
    components = [item for e in component_exts for item in main_app.glob("**/" + e)][::-1]
    components.append(main_app)

    mappings: Dict[str, str] = {}

    def sign_secondary(component: Path, workdir: Path):
        # entitlements of frameworks, etc. don't matter, so leave them (potentially) invalid
        print("Signing with original entitlements")
        return codesign_async(opts.common_name, component)

    def sign_primary(component: Path, workdir: Path):
        info_plist = component.joinpath("Info.plist")
        with info_plist.open("rb") as f:
            info: Dict[Any, Any] = plistlib.load(f)
        embedded_prov = component.joinpath("embedded.mobileprovision")
        old_bundle_id = info["CFBundleIdentifier"]
        bundle_id = f"{main_bundle_id}{old_bundle_id[len(old_main_bundle_id):]}"
        component_bin = component.joinpath(component.stem)

        with tempfile.NamedTemporaryFile(dir=workdir, suffix=".plist", delete=False) as f:
            entitlements_plist = Path(f.name)

        old_entitlements: Dict[Any, Any]
        try:
            old_entitlements = codesign_dump_entitlements(component)
        except:
            print("Failed to dump entitlements, using empty")
            old_entitlements = {}

        if opts.prov_file is not None:
            shutil.copy2(opts.prov_file, embedded_prov)
            # This may cause issues with wildcard entitlements, since they are valid in the provisioning
            # profile, but not when applied to a binary. For example:
            #   com.apple.developer.icloud-services = *
            # Ideally, all such cases should be manually replaced.
            entitlements = dump_prov_entitlements(embedded_prov)

            print("Original entitlements:")
            print_object(entitlements)

            prov_app_id = entitlements["application-identifier"]
            component_app_id = f"{opts.team_id}.{bundle_id}"
            wildcard_app_id = f"{opts.team_id}.*"
            if prov_app_id in [component_app_id, wildcard_app_id]:
                entitlements["application-identifier"] = component_app_id
            else:
                print(
                    f"WARNING: Provisioning profile's app id '{prov_app_id}' does not match component's app id '{component_app_id}'.",
                    "Using provisioning profile's app id - the component will run, but its entitlements will be broken!",
                    sep="\n",
                )

            keychain = entitlements.get("keychain-access-groups", [])
            if any(item == wildcard_app_id for item in keychain):
                keychain.clear()
                for item in old_entitlements.get("keychain-access-groups", []):
                    keychain.append(f"{opts.team_id}.{item[item.index('.')+1:]}")

            with entitlements_plist.open("wb") as f:
                plistlib.dump(entitlements, f)
        else:
            with tempfile.TemporaryDirectory() as tmpdir_str:
                tmpdir = Path(tmpdir_str)
                simple_app_dir = tmpdir.joinpath("SimpleApp")
                shutil.copytree("SimpleApp", simple_app_dir)
                xcode_entitlements_plist = simple_app_dir.joinpath("SimpleApp/SimpleApp.entitlements")
                xcode_entitlements = copy.deepcopy(old_entitlements)

                old_team_id: Optional[str] = old_entitlements.get("com.apple.developer.team-identifier", None)
                if not old_team_id:
                    print("Failed to read old team id")
                # before 2011 this was known as 'bundle seed id' and could be set freely
                # now it is always equal to team id
                old_app_id_prefix: Optional[str] = old_entitlements.get("application-identifier", "").split(".")[0]
                if not old_app_id_prefix:
                    old_app_id_prefix = None
                    print("Failed to read old app id prefix")

                print("Original entitlements:")
                print_object(old_entitlements)

                for entitlement in list(xcode_entitlements):
                    if entitlement not in [
                        "application-identifier",
                        "aps-environment",
                        "com.apple.developer.associated-domains",
                        "com.apple.developer.default-data-protection",
                        "com.apple.developer.icloud-container-development-container-identifiers",
                        "com.apple.developer.icloud-container-environment",
                        "com.apple.developer.icloud-container-identifiers",
                        "com.apple.developer.icloud-services",
                        "com.apple.developer.kernel.extended-virtual-addressing",
                        "com.apple.developer.networking.multipath",
                        "com.apple.developer.networking.networkextension",
                        "com.apple.developer.networking.wifi-info",
                        "com.apple.developer.siri",
                        "com.apple.developer.team-identifier",
                        "com.apple.developer.ubiquity-container-identifiers",
                        "com.apple.developer.ubiquity-kvstore-identifier",
                        "com.apple.security.application-groups",
                        "get-task-allow",
                        "keychain-access-groups",
                    ]:
                        xcode_entitlements.pop(entitlement)

                for entitlement, value in {
                    "com.apple.developer.icloud-container-environment": "Development",
                    "aps-environment": "development",
                }.items():
                    if entitlement in xcode_entitlements:
                        xcode_entitlements[entitlement] = value

                patches: Dict[str, str] = {}

                for entitlements, prefix, skip_parts, parents in (
                    ("com.apple.security.application-groups", "group.", 2, []),
                    (
                        [
                            "com.apple.developer.icloud-container-identifiers",
                            "com.apple.developer.ubiquity-container-identifiers",
                        ],
                        "iCloud.",
                        2,
                        ["com.apple.developer.icloud-container-environment", "com.apple.developer.icloud-services"],
                    ),
                    ("keychain-access-groups", "", 2, []),  # TEAM_ID.com.test.app
                ):
                    for entitlement in entitlements:
                        remap_ids = xcode_entitlements.get(entitlement, [])
                        if len(remap_ids) < 1:
                            # some apps define entitlement properties such as iCloud without identifiers, but modern iOS doesn't like that
                            # manually add identifiers if necessary
                            if any(parent in xcode_entitlements for parent in parents):
                                remap_ids.append(prefix + bundle_id)

                        if len(remap_ids) < 1:
                            continue

                        for remap_id in remap_ids:
                            if remap_id not in mappings:
                                if opts.encode_ids:
                                    seed = remap_id + opts.team_id
                                    if opts.bundle_id:
                                        seed += opts.bundle_id
                                    mappings[remap_id] = gen_id(remap_id, seed, skip_parts)
                                else:
                                    mappings[remap_id] = remap_id

                        xcode_entitlements[entitlement] = []
                        for remap_id in remap_ids:
                            xcode_entitlements[entitlement].append(remap_id)
                            patches[remap_id] = mappings[remap_id]

                if old_team_id:
                    patches[old_team_id] = opts.team_id
                if old_app_id_prefix:
                    patches[old_app_id_prefix] = opts.team_id
                patches[old_bundle_id] = bundle_id
                patches[old_main_bundle_id] = main_bundle_id

                # sort patches by decreasing length to make sure that there are no overlaps
                patches = dict(sorted(patches.items(), key=lambda x: len(x[0]), reverse=True))

                with info_plist.open("wb") as f:
                    plistlib.dump(info, f)
                with xcode_entitlements_plist.open("wb") as f:
                    plistlib.dump(xcode_entitlements, f)

                print("Applying patches...")
                targets = [xcode_entitlements_plist]
                if opts.patch_ids:
                    targets.append(component_bin)
                    targets.append(info_plist)
                else:
                    print("Skipping component binary")
                for target in targets:
                    for old, new in patches.items():
                        binary_replace(f"s/{re.escape(old)}/{re.escape(new)}/g", target)

                with xcode_entitlements_plist.open("rb") as f:
                    print("Patched entitlements:")
                    print_object(plistlib.load(f))

                simple_app_proj = simple_app_dir.joinpath("SimpleApp.xcodeproj")
                simple_app_pbxproj = simple_app_proj.joinpath("project.pbxproj")
                binary_replace(f"s/BUNDLE_ID_HERE_V9KP12/{bundle_id}/g", simple_app_pbxproj)
                binary_replace(f"s/DEV_TEAM_HERE_J8HK5C/{opts.team_id}/g", simple_app_pbxproj)

                for prov_profile in get_prov_profiles():
                    os.remove(prov_profile)

                print("Obtaining provisioning profile...")
                print("Archiving app...")
                archive = simple_app_dir.joinpath("archive.xcarchive")
                xcode_archive(simple_app_proj, "SimpleApp", archive)
                if is_distribution:
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
                shutil.move(str(prov_profiles[0]), embedded_prov)
                for prov_profile in prov_profiles[1:]:
                    os.remove(prov_profile)
                with entitlements_plist.open("wb") as f:
                    plistlib.dump(codesign_dump_entitlements(output_bin), f)

        with entitlements_plist.open("rb") as f:
            entitlements = plistlib.load(f)

        if opts.force_original_id:
            print("Keeping original CFBundleIdentifier")
            info["CFBundleIdentifier"] = old_bundle_id
        else:
            print(f"Setting CFBundleIdentifier to {bundle_id}")
            info["CFBundleIdentifier"] = bundle_id

        if opts.patch_debug:
            entitlements["get-task-allow"] = True
            print("Enabled app debugging")
        else:
            entitlements.pop("get-task-allow", False)
            print("Disabled app debugging")

        if opts.patch_all_devices:
            print("Force enabling support for all devices")
            info.pop("UISupportedDevices", False)
            # https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html
            info["UIDeviceFamily"] = [1, 2]

        if opts.patch_file_sharing:
            print("Force enabling file sharing")
            info["UIFileSharingEnabled"] = True
            info["UISupportsDocumentBrowser"] = True

        with info_plist.open("wb") as f:
            plistlib.dump(info, f)
        with entitlements_plist.open("wb") as f:
            plistlib.dump(entitlements, f)

        print("Signing with entitlements:")
        print_object(entitlements)
        return codesign_async(opts.common_name, component, entitlements_plist)

    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        jobs: Dict[Path, subprocess.Popen[bytes]] = {}
        for component in components:
            print(f"Preparing component {component}")

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

            print("Processing")

            sc_info = component.joinpath("SC_Info")
            if sc_info.exists():
                print(f"Removing leftover AppStore data")
                shutil.rmtree(sc_info)

            if component.suffix in [".appex", ".app"]:
                jobs[component] = sign_primary(component, tmpdir)
            else:
                jobs[component] = sign_secondary(component, tmpdir)

        print("Waiting for any remaining components to finish signing")
        for pipe in jobs.values():
            pipe.wait()
            popen_check(pipe)
