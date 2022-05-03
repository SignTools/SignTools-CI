# https://mypy.readthedocs.io/en/stable/runtime_troubles.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime
from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess, PIPE, Popen, TimeoutExpired
import tempfile
import shutil
from typing import Any, Callable, Dict, List, Optional, NamedTuple, Set, Tuple
import re
import os
from util import *
import time
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
        main_app = next(opts.app_dir.glob("Payload/*.app"))
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
        self.components = [item for e in component_exts for item in main_app.glob("**/" + e)][::-1]
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
            # https://developer.apple.com/documentation/bundleresources/information_property_list/minimumosversion
            info["MinimumOSVersion"] = "3.0"
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
                        "com.apple.developer.networking.multipath",
                        "com.apple.developer.networking.networkextension",
                        "com.apple.developer.networking.vpn.api",
                        "com.apple.developer.networking.wifi-info",
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

                    print("Applying patches...")
                    targets = [
                        x for x in [component, component.joinpath(component.stem)] if x.exists() and x.is_file()
                    ]
                    if data is not None:
                        targets.append(data.info_plist)
                    for target in targets:
                        for old, new in patches.items():
                            print("Patching", target)
                            binary_replace(f"s/{re.escape(old)}/{re.escape(new)}/g", target)

                print("Signing")

                if data is not None:
                    jobs[component] = self.__sign_primary(component, tmpdir, data)
                else:
                    jobs[component] = self.__sign_secondary(component, tmpdir)

            print("Waiting for any remaining components to finish signing")
            for pipe in jobs.values():
                pipe.wait()
                popen_check(pipe)
