#!/usr/bin/env python3
"""Hunt for the SCKit toolkit and rogue ScreenConnect clients (November 2026 campaign).

Checks three places, using only the indicators that ConnectWise, Huntress and Blackpoint Cyber published:

  endpoint   python3 sckit_hunt.py --root C:\\            a Windows machine's system drive, or a mounted image
  server     python3 sckit_hunt.py --server "C:\\Program Files (x86)\\ScreenConnect"   an on-premises server
  logs       python3 sckit_hunt.py --logs audit.csv proxy.log   any text export (audit log, DNS, proxy, EDR)

Run it from EDR live response, WinRM or another out-of-band tool. Do not connect to a suspected host through
ScreenConnect: the toolkit is built to spread to the technician who connects. Read-only: it changes nothing.
Python 3.10+, standard library only. Exit codes: 0 nothing found, 1 findings, 2 nothing could be checked.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"
SOURCES = ("ConnectWise Trust Center advisory, updated 13 Nov 2026", "Huntress, SCKit worm report, 11 Nov 2026 with 13 Nov update",
           "Blackpoint Cyber, SCKit analysis, 11 Nov 2026", "Sophos, malicious ScreenConnect deployments, Nov 2026")

# --------------------------------------------------------------------------- published indicators
ROGUE_CLIENT_IDS = {"2588ef5c15954b10": "rogue client (ConnectWise, Huntress, Blackpoint)",
                    "ed630cc2c873b091": "rogue client (ConnectWise, Huntress, Blackpoint)"}
SOURCE_INSTANCE_IDS = {"d905b2b1b165d0a9", "4b8f4089ddaac6a9", "df1f7ef0cfacd0d8"}   # Sophos: instances the commands came from
ATTACKER_HOSTS = {
    "185.99.255.28": "attacker ScreenConnect server (serves the client installer)",
    "185.241.211.197": "attacker server hosting the rogue client in the 13 November wave (Huntress)",
    "155.94.150.39": "secondary command-and-control (sc.payproofkit.com)",
    "ns.mo7sen.dev": "PowerShell loader delivery / staging",
    "sc.payproofkit.com": "attacker-controlled ScreenConnect panel",
    "cdn007-digitaldownloads.com": "rogue ScreenConnect deployment / C2",
    "newnewnew.gotdns.org": "attacker relay",
    "soxnewwork.homedns.org": "attacker relay (port 81) for rogue client ed630cc2c873b091",
}
URL_MARKERS = {"EadF.php": "staging URL path (ns.mo7sen.dev/EadF.php?p=N)",
               "UpdateConnect.ClientSetup.msi": "installer name used in the 13 November wave (Huntress)"}
FILE_NAMES = {
    "sckit-run.bat": "dropper: retrieves and executes the loader",
    "sckit-decoder.ps1": "PowerShell decoder and loader",
    "sckit-loader.ps1": "loader fetched by runnew.cmd",
    "TrapWatch.ps1": "persistent SYSTEM-level payload (runs every 10 seconds)",
    "Panel-Lateral.ps1": "lateral movement: steals the technician's session cookie",
    "Panel-Lateral-free.ps1": "lateral movement installer without config",
    "Run-Lateral-Full.bat": "dropper for the technician-side spread",
    "runnew.cmd": "downloads the loader with curl.exe",
    "ToolboxRelayUploader.exe": "uploads the payload to the panel's Shared Toolbox",
    "LabConfig.ps1": "helper: decrypts cookies, probes panels",
    "Lab-context.json": "kit configuration (attacker panel, keys, rogue client IDs)",
    "RelayTrap.cs": "source of the relay trap, compiled on each host",
    "RelayTrap.exe": "the relay trap",
    "install.ps1": "trap installer (only suspicious inside RelayTrap folders)",
    "Lite-Alert.ps1": "logs ScreenConnect file-run events for the attacker",
    "Stage0Loader.ps1": "stage-0 loader",
    "Release-Machine.cmd": "trap removal script shipped with the kit",
    "Recover-ExecutionPolicy.cmd": "removes the kit's AppLocker/SRP rules",
    "TRAP-PROOF.bat": "test payload: writes RELAY-TRAP-PROOF.txt",
    "Stop-LabTrap.bat": "cleanup dropper",
    "WithUninstall.ps1": "Shared Toolbox payload",
    "SilentForceInstall-WithUninstall.ps1": "installs two unauthorized Access clients",
    "RELAY-TRAP-PROOF.txt": "marker file the trap writes to %PUBLIC%",
}
# Published SHA-256 values. Weak indicators: the scripts are rebuilt per victim and the trap is compiled per host.
HASHES = {
    "94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11": "Panel-Lateral-free.ps1",
    "7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec": "Panel-Lateral.ps1",
    "b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d": "LabConfig.ps1",
    "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4": "RelayTrap.cs",
    "d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a": "TrapWatch.ps1",
    "4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b": "install.ps1",
    "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af": "ToolboxRelayUploader.exe",
    "cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956": "Lite-Alert.ps1",
    "81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781": "Stage0Loader.ps1",
    "c31e6f075cd77e01839aebce32ed35659a9ee962d102aca53040bb5e297410a9": "Release-Machine.cmd",
    "deda7c30d798a19b6699a45fbcba503cf778594df9163c61c2f96bb2d2b9fb45": "Recover-ExecutionPolicy.cmd",
    "0bd84c776dc01f784a617e73fc77b269f847fc4a062ffd489e4692869724bf08": "Lab-context.json",
    "454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a": "TRAP-PROOF.bat",
    "5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0": "Stop-LabTrap.bat",
    "43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95": "Run-Lateral-Full.bat",
    "50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61": "runnew.cmd",
    "a1937467fd862916f89342cdd61f55c4bc405fb35b6e1379e27cfbfdba77dcdc": "SilentForceInstall-WithUninstall.ps1",
    "d85315bd7602b6f5c13dc0eada2c9cba0892c7cd3b1eb7dacb1bffdd536ceb21": "ScreenConnect.ClientSetup.msi (attacker-configured)",
}
ACCOUNT_NAMES = {"Addmin": "attacker participant/operator name", "rmmserver": "attacker-associated account name"}
INSTALLER_PATTERN = re.compile(r"c=Exploited\w*", re.I)       # ...ClientSetup.msi?...&c=Exploited<N>, also c=ExploitedNOTUSA
MACHINE_SCRIPT = re.compile(r"^k[0-9a-f]{32}\.ps1$", re.I)      # machine-keyed script left in %TEMP%
TASK_NAME, RUN_KEY_VALUE = "TrapWatch", "RelayTrapLiteAlert"
# Extensions ConnectWise disabled, and the setting name Huntress found at fault.
EXTENSION_MARKERS = {"RMM+": "RMM+ family (disabled by ConnectWise)", "RMM Plus": "RMM+ family",
                     "RMMPlus": "RMM+ family", "Labtech Plus": "RMM+ family", "LabTech Plus": "RMM+ family",
                     "Password Link": "RMM+ family", "RMMPlus.AccessKey": "the access-key setting that accepted a blank value in 1.0.31/1.0.32",
                     # Added to ConnectWise's precautionary list on 13 November 2026 (cloud and marketplace disabled).
                     "ITBoost": "ITBoost Integration (disabled as a precaution, 13 Nov)",
                     "RepairShopr": "RepairShopr Integration (disabled as a precaution, 13 Nov)",
                     "Guest Session Starter": "Guest Session Starter (disabled as a precaution, 13 Nov)"}
CLIENT_DIR = re.compile(r"^ScreenConnect Client \(([0-9a-f]{16})\)$", re.I)


# --------------------------------------------------------------------------- helpers
def defang(text: str) -> str:
    """Make domains and IPs safe to paste: 185.99.255[.]28, ns.mo7sen[.]dev."""
    return re.sub(r"\.(?=[^.\s/]*$)", "[.]", text) if re.search(r"[A-Za-z]", text) else re.sub(r"\.(?=\d+$)", "[.]", text)


def sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class Findings:
    def __init__(self):
        self.items: list[dict] = []
        self.checked: list[str] = []

    def add(self, level: str, where: str, what: str, detail: str = "") -> None:
        self.items.append({"level": level, "where": where, "what": what, "detail": detail})

    @property
    def hits(self) -> int:
        return sum(1 for i in self.items if i["level"] in ("HIGH", "MEDIUM"))


def relay_host(image_path: str) -> str | None:
    """The ScreenConnect relay a client service connects to, from its command line (…?e=Access&y=Guest&h=HOST&p=…)."""
    m = re.search(r"[?&]h=([^&\s\"]+)", image_path)
    return m.group(1).strip().lower() if m else None


# --------------------------------------------------------------------------- endpoint (file system)
def _exists(root: str, *parts: str) -> str | None:
    """The path if it exists. Folder names are tried as written and upper/lower-cased, because a Windows drive
    mounted on Linux is case-sensitive while Windows itself is not."""
    seen = set()
    for variant in ((), (str.upper,), (str.lower,)):
        fixed = [v(part) if variant and i < len(parts) - 1 else part for i, part in enumerate(parts) for v in (variant or (lambda x: x,))]
        p = os.path.join(root, *fixed)
        key = os.path.normcase(os.path.realpath(p))
        if key in seen:
            continue
        seen.add(key)
        if os.path.exists(p):
            return p
    return None


def scan_endpoint(root: str, f: Findings, allow: set[str]) -> None:
    root = os.path.abspath(root)
    f.checked.append(f"endpoint files under {root}")
    if p := _exists(root, "ProgramData", "RelayTrap"):
        f.add("HIGH", p, "SCKit persistence folder C:\\ProgramData\\RelayTrap\\")
        for name in os.listdir(p):
            f.add("HIGH", os.path.join(p, name), f"file inside RelayTrap folder: {name}")
    if p := _exists(root, "Windows", "System32", "Tasks", TASK_NAME):
        f.add("HIGH", p, f"scheduled task '{TASK_NAME}' (runs the trap as SYSTEM every 10 seconds)")
    if p := _exists(root, "Users", "Public", "RELAY-TRAP-PROOF.txt"):
        f.add("HIGH", p, "trap marker file RELAY-TRAP-PROOF.txt")
    for name in ("sckit-run.bat", "sckit-decoder.ps1", "sckit-loader.ps1"):
        if p := _exists(root, "Windows", "Temp", name):
            f.add("HIGH", p, f"SCKit staging file {name}")
    if p := _exists(root, "Windows", "Temp", "sc.msi"):
        digest = sha256(p)
        f.add("HIGH" if digest in HASHES else "MEDIUM", p,
              "sc.msi in C:\\Windows\\TEMP (rogue client installer path used by the campaign)",
              f"sha256 {digest}" + (" matches the published attacker installer" if digest in HASHES else ""))
    # Temp folders of every user profile, plus the Windows temp folder.
    temp_dirs = [d for d in (_exists(root, "Windows", "Temp", ""),) if d] + glob.glob(os.path.join(root, "Users", "*", "AppData", "Local", "Temp"))
    for temp in temp_dirs:
        if not os.path.isdir(temp):
            continue
        try:
            names = os.listdir(temp)
        except OSError:
            continue
        for name in names:
            low = name.lower()
            path = os.path.join(temp, name)
            if low.startswith("sckit-") or low == "sc.msi":
                if any(i["where"] == path for i in f.items):
                    continue                                   # already reported above
                f.add("HIGH", path, "SCKit staging item (sckit-*) in a temp folder")
            elif name in FILE_NAMES and name not in ("install.ps1",):
                f.add("HIGH", path, f"{name}: {FILE_NAMES[name]}")
            elif MACHINE_SCRIPT.match(name):
                f.add("HIGH", path, "machine-keyed loader script k<32 hex>.ps1 in a temp folder")
            elif low == "sqlite3.exe":
                f.add("MEDIUM", path, "sqlite3.exe in a temp folder (used to read browser cookie databases; legitimate tool, weak on its own)")
    # Installed ScreenConnect clients: one per legitimate instance is normal; a second one is the campaign's backdoor.
    for pf in ("Program Files (x86)", "Program Files"):
        for d in glob.glob(os.path.join(root, pf, "ScreenConnect Client (*)")):
            m = CLIENT_DIR.match(os.path.basename(d))
            if not m:
                continue
            cid = m.group(1).lower()
            if cid in ROGUE_CLIENT_IDS:
                f.add("HIGH", d, f"rogue ScreenConnect client {cid}: {ROGUE_CLIENT_IDS[cid]}")
            elif cid in allow:
                f.add("INFO", d, f"ScreenConnect client {cid} (on your allow list)")
            else:
                f.add("MEDIUM", d, f"ScreenConnect client {cid} not on your allow list: confirm it is yours (--allow {cid})")
    # Any published file name or hash anywhere under RelayTrap-style folders is covered above; hashes for named hits:
    for item in list(f.items):
        if item["level"] == "HIGH" and os.path.isfile(item["where"]):
            digest = sha256(item["where"])
            if digest in HASHES:
                item["detail"] = (item["detail"] + "; " if item["detail"] else "") + f"sha256 matches published {HASHES[digest]}"


# --------------------------------------------------------------------------- endpoint (live Windows registry)
def scan_registry(f: Findings, allow: set[str]) -> None:
    if platform.system() != "Windows":
        return
    import winreg  # noqa: WPS433  (Windows only)
    f.checked.append("Windows registry: Run key, ScreenConnect services, Defender exclusions")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                if name == RUN_KEY_VALUE:
                    f.add("HIGH", "HKLM\\...\\CurrentVersion\\Run", f"Run value '{RUN_KEY_VALUE}' (SCKit persistence)", str(value))
    except OSError as err:
        f.add("INFO", "registry", f"could not read the Run key: {err}")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as services:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(services, i)
                except OSError:
                    break
                i += 1
                m = CLIENT_DIR.match(name)
                if not m:
                    continue
                cid = m.group(1).lower()
                try:
                    with winreg.OpenKey(services, name) as svc:
                        image = str(winreg.QueryValueEx(svc, "ImagePath")[0])
                except OSError:
                    image = ""
                host = relay_host(image)
                if cid in ROGUE_CLIENT_IDS:
                    f.add("HIGH", f"service {name}", f"rogue client service: {ROGUE_CLIENT_IDS[cid]}", f"relay {defang(host or '?')}")
                elif host and host in ATTACKER_HOSTS:
                    f.add("HIGH", f"service {name}", f"client service pointed at attacker relay {defang(host)}", ATTACKER_HOSTS[host])
                elif cid not in allow:
                    f.add("MEDIUM", f"service {name}", f"client service not on your allow list (relay {defang(host or '?')})", image[:160])
    except OSError as err:
        f.add("INFO", "registry", f"could not list services: {err}")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes") as k:
            i = 0
            while True:
                try:
                    name, _, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                if name.lower() in ("msiexec.exe", "powershell.exe") or "relaytrap" in name.lower():
                    f.add("MEDIUM", "Defender process exclusions", f"exclusion for {name} (SCKit adds exclusions for its tooling)")
    except OSError:
        pass        # needs admin rights; absence of access is not a finding


# --------------------------------------------------------------------------- server (extensions)
def scan_server(server: str, f: Findings) -> None:
    ext_root = os.path.join(server, "App_Extensions")
    f.checked.append(f"extensions under {ext_root}")
    if not os.path.isdir(ext_root):
        f.add("INFO", ext_root, "no App_Extensions folder here (is this the ScreenConnect install folder?)")
        return
    for ext in sorted(os.listdir(ext_root)):
        folder = os.path.join(ext_root, ext)
        if not os.path.isdir(folder):
            continue
        matched: dict[str, str] = {}
        for dirpath, _, files in os.walk(folder):
            for name in files:
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 5_000_000:
                        continue
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                for marker, why in EXTENSION_MARKERS.items():
                    if marker in text and marker not in matched:
                        matched[marker] = f"{why} [{os.path.relpath(path, folder)}]"
        if matched:
            f.add("HIGH", folder, "installed extension from the RMM+ family: disable it (Administration > Extensions) and do not re-enable it",
                  "; ".join(f"{m}: {w}" for m, w in matched.items()))
        else:
            f.add("INFO", folder, "extension folder (no RMM+ markers)")


# --------------------------------------------------------------------------- logs
def scan_logs(paths: list[str], f: Findings) -> None:
    needles: dict[str, tuple[str, str, str]] = {}          # lower-case needle -> (level, why, how to print it)
    for host, why in ATTACKER_HOSTS.items():
        needles[host.lower()] = ("HIGH", why, defang(host))
    for marker, why in URL_MARKERS.items():
        needles[marker.lower()] = ("HIGH", why, marker)
    for cid, why in ROGUE_CLIENT_IDS.items():
        needles[cid] = ("HIGH", why, cid)
    for cid in SOURCE_INSTANCE_IDS:
        needles[cid] = ("MEDIUM", "instance ID the rogue deployments were pushed from (Sophos); if it is yours, treat the panel as compromised", cid)
    for name, why in FILE_NAMES.items():
        needles[name.lower()] = ("MEDIUM" if name in ("install.ps1", "RelayTrap.exe") else "HIGH", why, name)
    for name, why in ACCOUNT_NAMES.items():
        needles[name.lower()] = ("MEDIUM", why, name)
    for path in paths:
        f.checked.append(f"log {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for n, line in enumerate(fh, 1):
                    low = line.lower()
                    for needle, (level, why, shown) in needles.items():
                        if needle in low:
                            f.add(level, f"{path}:{n}", f"{shown}: {why}", line.strip()[:200])
                    if INSTALLER_PATTERN.search(line):
                        f.add("HIGH", f"{path}:{n}", "installer URL with c=Exploited<N> (the campaign's numbered victims)", line.strip()[:200])
        except OSError as err:
            f.add("INFO", path, f"could not read: {err}")


# --------------------------------------------------------------------------- output
def report(f: Findings, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"tool": f"sckit_hunt {VERSION}", "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          "checked": f.checked, "findings": f.items, "sources": SOURCES}, indent=1))
        return
    print(f"sckit_hunt {VERSION}: indicators from {'; '.join(SOURCES)}")
    for c in f.checked:
        print(f"  checked: {c}")
    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    for item in sorted(f.items, key=lambda i: order[i["level"]]):
        print(f"[{item['level']:<6}] {item['what']}\n         at {item['where']}" + (f"\n         {item['detail']}" if item["detail"] else ""))
    hits = f.hits
    if hits:
        print(f"\n{hits} finding(s) need a look. Isolate the host, investigate from a clean device, and do not open it through "
              "ScreenConnect. Disabling extensions and resetting passwords alone does not remove what is already installed.")
    else:
        print("\nNo published indicator found. That lowers the odds; it does not clear the host (hashes and names change).")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", help="system drive or mounted image to check for endpoint artefacts (default on Windows: C:\\)")
    ap.add_argument("--server", help="ScreenConnect on-premises install folder (the one holding App_Extensions)")
    ap.add_argument("--logs", nargs="*", default=[], help="text log exports to scan for the published indicators")
    ap.add_argument("--allow", action="append", default=[], help="a ScreenConnect client instance ID you know is yours (repeatable)")
    ap.add_argument("--no-registry", action="store_true", help="skip the live Windows registry checks")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = args.root or ("C:\\" if platform.system() == "Windows" else None)
    if not root and not args.server and not args.logs:
        ap.error("nothing to check: give --root, --server and/or --logs")
    allow = {a.lower() for a in args.allow}
    f = Findings()
    if root:
        if not os.path.isdir(root):
            print(f"--root {root} is not a folder", file=sys.stderr)
            return 2
        scan_endpoint(root, f, allow)
        if not args.no_registry and platform.system() == "Windows" and os.path.abspath(root).rstrip("\\/").lower() == os.environ.get("SystemDrive", "C:").lower():
            scan_registry(f, allow)
    if args.server:
        scan_server(args.server, f)
    if args.logs:
        scan_logs(args.logs, f)
    report(f, args.json)
    return 1 if f.hits else 0


if __name__ == "__main__":
    sys.exit(main())
