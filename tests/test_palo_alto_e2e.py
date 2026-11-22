#!/usr/bin/env python3
"""
tests/test_palo_alto_e2e.py - End-to-End & Unit Tests for Palo Alto Tooling
Exercises tmp/palo_alto_ccdc_inv_2026.py CLI switches, XML parsing,
drift detection, redundant NAT identification, and PAN-OS CLI remediation generation.
"""

import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

# Ensure workspace root is in sys.path
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

from tmp.palo_alto_ccdc_inv_2026 import (
    SCORED_HOSTS,
    BASELINE_APPROVED_RULES,
    REDUNDANT_NAT_NAMES,
    REQUIRED_SCORED_RULES,
    Severity,
    AuditFinding,
    parse_security_rules,
    parse_nat_rules,
    parse_permitted_ips,
    audit_xml_tree,
    generate_remediation_script,
)


class TestPaloAltoCoreLogic(unittest.TestCase):
    """Unit tests for constants, data structures, and core parsing functions."""

    def test_22_scored_services_across_5_hosts(self):
        """Verify exactly 22 scored services across Rocky, Email, Splunk, AD, and MSSQL."""
        self.assertEqual(len(SCORED_HOSTS), 5)
        all_services = []
        for host, info in SCORED_HOSTS.items():
            all_services.extend(info["services"])
        self.assertEqual(
            len(all_services),
            22,
            f"Expected exactly 22 scored services, found {len(all_services)}: {all_services}",
        )
        self.assertEqual(len(set(all_services)), 22, "Scored service names must be unique")

    def test_scored_hosts_private_ips(self):
        """Verify correct private IPs for the 5 internal hosts."""
        expected_ips = {
            "Rocky Ecom": "172.20.240.10",
            "Ubuntu Email": "172.20.240.15",
            "Debian Splunk": "172.20.240.20",
            "2022 AD": "172.20.240.100",
            "2019 MSSQL": "172.20.240.120",
        }
        for host, ip in expected_ips.items():
            self.assertEqual(SCORED_HOSTS[host]["priv_ip"], ip)

    def test_redundant_nat_rules_set(self):
        """Verify redundant NAT rule names include static NATs and LAN-OutboundPAT."""
        expected = {
            "Ecomm-StaticNAT",
            "Email-StaticNAT",
            "Splunk-StaticNAT",
            "AD-StaticNAT",
            "MSSQL-StaticNAT",
            "LAN-OutboundPAT",
        }
        self.assertTrue(expected.issubset(REDUNDANT_NAT_NAMES))

    def test_audit_clean_xml_in_memory(self):
        """Verify clean XML fixture yields zero audit findings."""
        clean_path = os.path.join(WORKSPACE_DIR, "tests/fixtures/palo_alto/clean_running_config.xml")
        tree = ET.parse(clean_path)
        findings = audit_xml_tree(tree.getroot())
        self.assertEqual(len(findings), 0, f"Clean fixture should have 0 findings, got: {findings}")

    def test_audit_public_destinations_drift(self):
        """Verify drift_public_destinations.xml triggers AUD-DEST-PUB findings."""
        drift_path = os.path.join(
            WORKSPACE_DIR, "tests/fixtures/palo_alto/drift_public_destinations.xml"
        )
        tree = ET.parse(drift_path)
        findings = audit_xml_tree(tree.getroot())
        dest_findings = [f for f in findings if f.check_id == "AUD-DEST-PUB"]
        self.assertGreaterEqual(
            len(dest_findings), 1, "Should detect public destination mismatch"
        )
        for f in dest_findings:
            self.assertEqual(f.severity, Severity.CRITICAL)
            self.assertTrue(any("destination" in cmd for cmd in f.remediation_cmds))

    def test_audit_redundant_nat_drift(self):
        """Verify drift_redundant_nat.xml triggers AUD-RED-NAT findings."""
        drift_path = os.path.join(
            WORKSPACE_DIR, "tests/fixtures/palo_alto/drift_redundant_nat.xml"
        )
        tree = ET.parse(drift_path)
        findings = audit_xml_tree(tree.getroot())
        nat_findings = [f for f in findings if f.check_id == "AUD-RED-NAT"]
        self.assertGreaterEqual(len(nat_findings), 1, "Should detect redundant static NAT rules")
        for f in nat_findings:
            self.assertEqual(f.severity, Severity.HIGH)
            self.assertTrue(any("delete rulebase nat rules" in cmd for cmd in f.remediation_cmds))

    def test_audit_disabled_scored_service(self):
        """Verify drift_disabled_scored.xml triggers AUD-DIS-RULE for disabled rules."""
        drift_path = os.path.join(
            WORKSPACE_DIR, "tests/fixtures/palo_alto/drift_disabled_scored.xml"
        )
        tree = ET.parse(drift_path)
        findings = audit_xml_tree(tree.getroot())
        dis_findings = [f for f in findings if f.check_id == "AUD-DIS-RULE"]
        self.assertGreaterEqual(len(dis_findings), 1, "Should detect disabled scored rule")
        self.assertTrue(any("disabled no" in cmd for f in dis_findings for cmd in f.remediation_cmds))

    def test_audit_rogue_backdoor_allow_rule(self):
        """Verify drift_rogue_backdoor.xml triggers AUD-ROG-ALLOW for unapproved allow rule."""
        drift_path = os.path.join(
            WORKSPACE_DIR, "tests/fixtures/palo_alto/drift_rogue_backdoor.xml"
        )
        tree = ET.parse(drift_path)
        findings = audit_xml_tree(tree.getroot())
        rogue_findings = [f for f in findings if f.check_id == "AUD-ROG-ALLOW"]
        self.assertGreaterEqual(len(rogue_findings), 1, "Should detect rogue backdoor rule")
        self.assertTrue(any('delete rulebase security rules "RogueBackdoorAllow"' in cmd for f in rogue_findings for cmd in f.remediation_cmds))

    def test_audit_open_management_ip(self):
        """Verify drift_open_mgmt.xml triggers AUD-MGMT-OPEN for 0.0.0.0/0."""
        drift_path = os.path.join(
            WORKSPACE_DIR, "tests/fixtures/palo_alto/drift_open_mgmt.xml"
        )
        tree = ET.parse(drift_path)
        findings = audit_xml_tree(tree.getroot())
        open_findings = [f for f in findings if f.check_id == "AUD-MGMT-OPEN"]
        self.assertGreaterEqual(len(open_findings), 1, "Should detect 0.0.0.0/0 in permitted-ip")
        self.assertEqual(open_findings[0].severity, Severity.CRITICAL)

    def test_remediation_commands_syntax(self):
        """Verify remediation script starts with scripting mode and configure, terminates with commit."""
        findings = [
            AuditFinding(
                check_id="TEST-1",
                severity=Severity.HIGH,
                title="Test Finding",
                details="Details",
                remediation_cmds=['delete rulebase nat rules "TestNAT"'],
            )
        ]
        script = generate_remediation_script(findings)
        self.assertIn("set cli scripting-mode on", script)
        self.assertIn("configure", script)
        self.assertIn('delete rulebase nat rules "TestNAT"', script)
        self.assertIn("commit", script)
        self.assertIn("exit", script)


class TestPaloAltoCLI(unittest.TestCase):
    """End-to-End subprocess execution tests for tmp/palo_alto_ccdc_inv_2026.py."""

    SCRIPT_PATH = os.path.join(WORKSPACE_DIR, "tmp/palo_alto_ccdc_inv_2026.py")

    def run_tool(self, args: list) -> subprocess.CompletedProcess:
        cmd = [sys.executable, self.SCRIPT_PATH] + args
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_cli_help(self):
        """Verify --help outputs usage description and exits 0."""
        res = self.run_tool(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("--audit-xml", res.stdout)
        self.assertIn("--keygen", res.stdout)
        self.assertIn("--instructions", res.stdout)

    def test_cli_instructions(self):
        """Verify --instructions outputs setup guide and exits 0."""
        res = self.run_tool(["--instructions"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("Palo Alto PAN-OS 11.0.2 - API Keygen", res.stdout)
        self.assertIn("type=keygen", res.stdout)

    def test_cli_audit_clean_exit_0(self):
        """Verify audit of clean baseline exits 0 with compliant message."""
        clean_xml = os.path.join(WORKSPACE_DIR, "tests/fixtures/palo_alto/clean_running_config.xml")
        res = self.run_tool(["--audit-xml", clean_xml])
        self.assertEqual(res.returncode, 0)
        self.assertIn("100% compliant", res.stdout)
        self.assertIn("Findings: 0 total", res.stdout)

    def test_cli_audit_drift_exit_1(self):
        """Verify audit of drifted config exits 1 and displays findings."""
        drift_xml = os.path.join(WORKSPACE_DIR, "tests/fixtures/palo_alto/drift_comprehensive.xml")
        res = self.run_tool(["--audit-xml", drift_xml])
        self.assertEqual(res.returncode, 1)
        self.assertIn("PAN-OS CONFIGURATION AUDIT REPORT", res.stdout)
        self.assertIn("Findings:", res.stdout)

    def test_cli_remediation_file_creation(self):
        """Verify --remediate creates an executable PAN-OS CLI script."""
        drift_xml = os.path.join(WORKSPACE_DIR, "tests/fixtures/palo_alto/drift_public_destinations.xml")
        with tempfile.NamedTemporaryFile(suffix=".pan", delete=False) as tf:
            out_file = tf.name

        try:
            res = self.run_tool(["--audit-xml", drift_xml, "--remediate", out_file])
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r") as f:
                content = f.read()
            self.assertIn("set cli scripting-mode on", content)
            self.assertIn("configure", content)
            self.assertIn("commit", content)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)

    def test_cli_malformed_xml_handling(self):
        """Verify malformed XML triggers parse error and non-zero exit."""
        malformed_xml = os.path.join(WORKSPACE_DIR, "tests/fixtures/palo_alto/malformed_syntax.xml")
        res = self.run_tool(["--audit-xml", malformed_xml])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("XML parsing failed", res.stdout)

    def test_cli_nonexistent_file_handling(self):
        """Verify nonexistent file triggers error without unhandled python stack trace."""
        res = self.run_tool(["--audit-xml", "/nonexistent/path/config.xml"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("XML file not found", res.stdout)


if __name__ == "__main__":
    unittest.main()
