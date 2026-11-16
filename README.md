# sckit_hunt: find SCKit and rogue ScreenConnect clients

One Python file that checks a Windows endpoint, a ScreenConnect on-premises server and your log exports for the
indicators published for the November 2026 ScreenConnect campaign (the SCKit toolkit, the rogue clients it installs,
and the RMM+ extension family ConnectWise disabled). It reads; it never changes anything.

This is the code from the TrickyWorld report
[ScreenConnect attack: SCKit and the RMM+ add-on](https://www.trickyworld.in/computer-tricks/cyber-security/screenconnect-attack-sckit-rmm-plus/).

Python 3.10 or newer, standard library only. Run it from EDR live response, WinRM, PsExec or a mounted disk image.
**Do not open a suspected host through ScreenConnect**: the toolkit is built to spread to the technician who connects.

## What it checks

| Mode | Command | Looks for |
|---|---|---|
| Endpoint | `python3 sckit_hunt.py --root C:\` (default on Windows) | `C:\ProgramData\RelayTrap\`, the `TrapWatch` scheduled task, `RELAY-TRAP-PROOF.txt`, the `sckit-*` staging files, `sc.msi`, `k<32 hex>.ps1`, the kit's script names in every user's temp folder, and every `ScreenConnect Client (<id>)` install: the two published rogue IDs are flagged, anything not on your allow list is listed for review. On a live Windows system it also reads the `RelayTrapLiteAlert` Run key, the relay each ScreenConnect client service connects to, and Defender process exclusions. |
| Server | `python3 sckit_hunt.py --server "C:\Program Files (x86)\ScreenConnect"` | Every folder under `App_Extensions` whose files name an extension from ConnectWise's disabled list (RMM+, RMM Plus, Labtech Plus, the Password Link variants; ITBoost Integration, RepairShopr Integration and Guest Session Starter since 13 November) or contain the `RMMPlus.AccessKey` setting. |
| Logs | `python3 sckit_hunt.py --logs audit.csv dns.log` | The published IPs, domains, URL paths, file names, rogue client IDs, the Sophos-listed source instance IDs, the `Addmin`/`rmmserver` account names and installer URLs with `c=Exploited<N>`. Hosts are printed defanged. |

Modes combine: `--root`, `--server` and `--logs` can be given together. `--allow <id>` (repeatable) marks a
ScreenConnect client instance as yours. `--json` prints machine-readable output. `--no-registry` skips the live
Windows checks.

Exit codes: `0` nothing found, `1` at least one HIGH or MEDIUM finding, `2` nothing could be checked.

## Reading the result

- **HIGH**: a published artefact, path, task, Run value, rogue client ID or attacker host. Isolate the host and
  investigate from a clean device.
- **MEDIUM**: needs a human decision. A ScreenConnect client that is not on your allow list, `sqlite3.exe` in a temp
  folder, an `sc.msi` whose hash is not a published one, a Defender exclusion for `msiexec.exe` or `powershell.exe`.
- **INFO**: context, such as an allowed client or an extension folder without markers.

A clean run lowers the odds; it does not clear the machine. Huntress notes that the scripts are rebuilt with different
embedded values and the trap is compiled on each host, so names and hashes change. ConnectWise's advisory says the
same of its own list: "An absence of matches does not rule out compromise."

## If it finds something

ConnectWise, Huntress and Blackpoint give the same order of work: isolate the host but do not connect to it through
ScreenConnect; from a trusted device revoke active ScreenConnect and identity-provider sessions, reset credentials and
enforce MFA; preserve the Run Command, Toolbox, extension-installation and authentication records; remove the rogue
client service, the `TrapWatch` task, `C:\ProgramData\RelayTrap\`, the temp files and the `RelayTrapLiteAlert` Run
value; and treat any technician workstation that connected to the host as exposed. Disabling the extensions and
resetting passwords does not remove what is already installed.

## Tests

```bash
python3 -m unittest -v
```

13 tests build a fake system drive, a fake `App_Extensions` folder and a fake audit export in a temporary directory.
They need no Windows machine and no network.

## Sources for every indicator

- [ConnectWise Trust Center: ScreenConnect security advisory](https://www.connectwise.com/company/trust/advisories) (updated 13 November 2026) and the
  [CVE-2026-127063 advisory](https://github.com/ConnectWise-Advisories/Disclosures/tree/main/CVE-2026-127063)
- [Huntress: SCKit worm installs rogue ScreenConnect clients](https://www.huntress.com/blog/sckit-worm-rogue-screenconnect) (11 November, updated 13 November)
- [Blackpoint Cyber: SCKit turns remote support into an attack platform](https://blackpointcyber.com/blog/screenconnect-attack-sckit/) (11 November)
- [Sophos: malicious ScreenConnect deployments observed](https://www.sophos.com/en-us/blog/malicious-screenconnect-deployments-observed)
- The client service command-line format (`?e=Access&y=Guest&h=<relay>&p=…`) follows
  [Elastic's detection rule for newly observed ScreenConnect hosts](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/command_and_control_newly_observed_screenconnect_host_server)
