//! Comprehensive integration test suite for Palo Alto XML parser, audit engine, and CLI remediation.

use std::path::PathBuf;

use linux_defender::core::finding::Severity;
use linux_defender::tools::palo_alto::{
    InterfaceConfig, RemediationScript, STANDARD_INTERFACES, XmlNode, ZoneConfig, audit_config,
    diff_baseline, extract_interfaces, extract_nat_rules, extract_permitted_ips,
    extract_security_rules, extract_zones,
};

const SAMPLE_CLEAN_BASELINE_XML: &str = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <permitted-ip>
            <entry name="172.20.240.50/32"/>
            <entry name="172.20.240.60/32"/>
          </permitted-ip>
        </system>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <security>
              <rules>
                <entry name="AllowICMP">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>ping</member><member>icmp</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowEcomm-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>EcommPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>web-browsing</member><member>ssl</member><member>ssh</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowEmail-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>EmailPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>smtp</member><member>pop3</member><member>imap</member><member>web-browsing</member><member>ssl</member><member>ssh</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowSplunk-SSH-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>SplunkPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>ssh</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowSplunk-WebMgmt-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>SplunkPrivate</member></destination>
                  <service><member>svc-splunk-web</member><member>svc-splunk-mgmt</member></service>
                  <application><member>splunk</member><member>web-browsing</member><member>ssl</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowAD-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>ADPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>dns</member><member>windows-remote-management</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowMSSQL-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>MSSQLPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>mssql-db-base</member><member>mssql-db</member><member>ms-rdp</member><member>ms-ds-smb</member><member>netbios-ss</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="DENYINBOUND">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>deny</action>
                  <disabled>no</disabled>
                </entry>
              </rules>
            </security>
            <nat>
              <rules/>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"#;

const SAMPLE_DRIFTED_XML: &str = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <permitted-ip>
            <entry name="0.0.0.0/0"/>
            <entry name="172.20.240.0/24"/>
          </permitted-ip>
        </system>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <security>
              <rules>
                <entry name="AllowICMP">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>ping</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <!-- Public Destination Mismatch (*Pub instead of *Private) -->
                <entry name="AllowEcomm-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>EcommPub</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>web-browsing</member><member>ssl</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <!-- Disabled Scored Rule -->
                <entry name="AllowEmail-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>EmailPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>smtp</member></application>
                  <action>allow</action>
                  <disabled>yes</disabled>
                </entry>
                <entry name="AllowSplunk-SSH-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>SplunkPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>ssh</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowSplunk-WebMgmt-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>SplunkPrivate</member></destination>
                  <service><member>svc-splunk-web</member></service>
                  <application><member>splunk</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <!-- Active Directory Overexposure (Finding F1) -->
                <entry name="AllowAD-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>ADPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application>
                    <member>dns</member>
                    <member>windows-remote-management</member>
                    <member>active-directory</member>
                    <member>msrpc</member>
                    <member>ms-ds-smb</member>
                  </application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <entry name="AllowMSSQL-AppID">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>MSSQLPrivate</member></destination>
                  <service><member>application-default</member></service>
                  <application><member>mssql-db</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
                <!-- Rogue Allow Rule (Backdoor Persistence) -->
                <entry name="AllowRedTeamBackdoor">
                  <from><member>External</member></from>
                  <to><member>Internal</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <disabled>no</disabled>
                </entry>
              </rules>
            </security>
            <!-- Redundant Static NAT Rules -->
            <nat>
              <rules>
                <entry name="Ecomm-StaticNAT">
                  <from><member>Internal</member></from>
                  <to><member>External</member></to>
                  <source><member>EcommPriv</member></source>
                  <destination><member>any</member></destination>
                  <disabled>no</disabled>
                </entry>
                <entry name="LAN-OutboundPAT">
                  <from><member>Internal</member></from>
                  <to><member>External</member></to>
                  <source><member>LAN</member></source>
                  <destination><member>any</member></destination>
                  <disabled>no</disabled>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"#;

#[test]
fn test_xml_parser_basic() {
    let xml = r#"<entry name="test-rule"><action>allow</action><disabled>no</disabled></entry>"#;
    let root = XmlNode::parse(xml).expect("XML parse failed");
    assert_eq!(root.tag, "entry");
    assert_eq!(root.attr("name"), Some("test-rule"));
    assert_eq!(root.child("action").map(|c| c.text.as_str()), Some("allow"));
    assert_eq!(root.child("disabled").map(|c| c.text.as_str()), Some("no"));
}

#[test]
fn test_xml_parser_entities_and_comments() {
    let xml = r#"<!-- Comment line -->
    <rules title="Security &amp; NAT">
      <?xml-stylesheet type="text/xsl" href="style.xsl"?>
      <entry name="Rule &lt;1&gt;">
        <desc>Testing &quot;quotes&quot; and &apos;apostrophe&apos;</desc>
      </entry>
    </rules>"#;
    let root = XmlNode::parse(xml).expect("XML parse with entities failed");
    assert_eq!(root.tag, "rules");
    assert_eq!(root.attr("title"), Some("Security & NAT"));
    let entry = root.child("entry").expect("Missing entry");
    assert_eq!(entry.attr("name"), Some("Rule <1>"));
    let desc = entry.child("desc").expect("Missing desc");
    assert_eq!(desc.text, "Testing \"quotes\" and 'apostrophe'");
}

#[test]
fn test_xml_parser_self_closing_and_nested() {
    let xml =
        r#"<vsys><entry name="vsys1"><disabled/><rules><entry name="r1"/></rules></entry></vsys>"#;
    let root = XmlNode::parse(xml).expect("Self-closing parse failed");
    assert_eq!(root.tag, "vsys");
    let vsys1 = root.child("entry").expect("Missing vsys1 entry");
    assert_eq!(vsys1.attr("name"), Some("vsys1"));
    assert!(vsys1.child("disabled").is_some());
    let rules = vsys1.child("rules").expect("Missing rules");
    assert_eq!(rules.child("entry").unwrap().attr("name"), Some("r1"));
}

#[test]
fn test_xml_parser_malformed_handling() {
    let malformed_1 = "<entry><action>allow</entry>";
    assert!(XmlNode::parse(malformed_1).is_err());

    let malformed_2 = "<entry><action>allow";
    assert!(XmlNode::parse(malformed_2).is_err());

    let malformed_3 = "</unexpected>";
    assert!(XmlNode::parse(malformed_3).is_err());
}

#[test]
fn test_audit_clean_baseline_zero_findings() {
    let root = XmlNode::parse(SAMPLE_CLEAN_BASELINE_XML).expect("Clean baseline parse failed");
    let findings = audit_config(&root, None);

    let critical_or_high: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
        .collect();

    assert!(
        critical_or_high.is_empty(),
        "Expected zero critical/high findings on clean baseline, but got: {:?}",
        critical_or_high
    );
}

#[test]
fn test_audit_detects_public_destination_mismatch() {
    let root = XmlNode::parse(SAMPLE_DRIFTED_XML).expect("Drifted parse failed");
    let findings = audit_config(&root, None);

    let dest_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "AUD-DEST-PUB")
        .collect();

    assert_eq!(
        dest_findings.len(),
        1,
        "Expected 1 destination mismatch finding"
    );
    let f = dest_findings[0];
    assert_eq!(f.target, "AllowEcomm-AppID");
    assert_eq!(f.severity, Severity::Critical);
    assert!(
        f.remediation
            .iter()
            .any(|cmd| cmd.contains("destination EcommPrivate"))
    );
}

#[test]
fn test_audit_detects_disabled_scored_rules() {
    let root = XmlNode::parse(SAMPLE_DRIFTED_XML).expect("Drifted parse failed");
    let findings = audit_config(&root, None);

    let dis_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "AUD-DIS-RULE")
        .collect();

    assert_eq!(dis_findings.len(), 1);
    let f = dis_findings[0];
    assert_eq!(f.target, "AllowEmail-AppID");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.remediation.iter().any(|cmd| cmd.contains("disabled no")));
}

#[test]
fn test_audit_detects_redundant_static_nat() {
    let root = XmlNode::parse(SAMPLE_DRIFTED_XML).expect("Drifted parse failed");
    let findings = audit_config(&root, None);

    let nat_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "AUD-RED-NAT")
        .collect();

    assert_eq!(
        nat_findings.len(),
        2,
        "Expected 2 redundant NAT rule findings (Ecomm-StaticNAT and LAN-OutboundPAT)"
    );
    let targets: Vec<&str> = nat_findings.iter().map(|f| f.target.as_str()).collect();
    assert!(targets.contains(&"Ecomm-StaticNAT"));
    assert!(targets.contains(&"LAN-OutboundPAT"));
    for f in nat_findings {
        assert_eq!(f.severity, Severity::High);
        assert!(f.remediation[0].starts_with("delete rulebase nat rules"));
    }
}

#[test]
fn test_audit_detects_rogue_allow_rules() {
    let root = XmlNode::parse(SAMPLE_DRIFTED_XML).expect("Drifted parse failed");
    let findings = audit_config(&root, None);

    let rogue_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "AUD-ROG-ALLOW")
        .collect();

    assert_eq!(
        rogue_findings.len(),
        1,
        "Expected 1 rogue allow rule finding for AllowRedTeamBackdoor"
    );
    let f = rogue_findings[0];
    assert_eq!(f.target, "AllowRedTeamBackdoor");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(
        f.remediation[0],
        "delete rulebase security rules \"AllowRedTeamBackdoor\""
    );
}

#[test]
fn test_audit_detects_permitted_ip_exposure() {
    let root = XmlNode::parse(SAMPLE_DRIFTED_XML).expect("Drifted parse failed");
    let findings = audit_config(&root, None);

    let open_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "AUD-MGMT-OPEN")
        .collect();
    assert_eq!(open_findings.len(), 1);
    assert_eq!(open_findings[0].target, "0.0.0.0/0");
    assert_eq!(open_findings[0].severity, Severity::Critical);

    let sub_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "AUD-MGMT-SUB")
        .collect();
    assert_eq!(sub_findings.len(), 1);
    assert_eq!(sub_findings[0].target, "172.20.240.0/24");
    assert_eq!(sub_findings[0].severity, Severity::Medium);
}

#[test]
fn test_audit_detects_ad_overexposure() {
    let root = XmlNode::parse(SAMPLE_DRIFTED_XML).expect("Drifted parse failed");
    let findings = audit_config(&root, None);

    let ad_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "AUD-AD-EXPOSE")
        .collect();

    assert_eq!(
        ad_findings.len(),
        1,
        "Expected finding for Active Directory overexposure (F1)"
    );
    let f = ad_findings[0];
    assert_eq!(f.target, "AllowAD-AppID");
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.remediation
            .iter()
            .any(|cmd| cmd.contains("dns windows-remote-management"))
    );
}

#[test]
fn test_remediation_script_formatting_and_phases() {
    let mut script = RemediationScript::new();
    script.add("delete rulebase nat rules \"Ecomm-StaticNAT\"");
    script.add("delete rulebase security rules \"AllowRedTeamBackdoor\"");
    script.add("delete rulebase security rules \"AllowEcomm-AppID\" destination");
    script.add("set rulebase security rules \"AllowEcomm-AppID\" destination EcommPrivate");
    script.add("set rulebase security rules \"AllowEmail-AppID\" disabled no");

    let rendered = script.render();

    assert!(
        rendered.starts_with(
            "# =====================================================================\n"
        )
    );
    assert!(rendered.contains("set cli scripting-mode on\nconfigure\n"));
    assert!(rendered.contains("# --- Phase 1: Purge Redundant NAT Rules ---"));
    assert!(rendered.contains("delete rulebase nat rules \"Ecomm-StaticNAT\""));
    assert!(rendered.contains("# --- Phase 2: Purge Rogue / Backdoor Allow Rules ---"));
    assert!(rendered.contains("delete rulebase security rules \"AllowRedTeamBackdoor\""));
    assert!(
        rendered.contains("# --- Phase 3: Correct Inbound Scored Rule Destinations (*Private) ---")
    );
    assert!(
        rendered
            .contains("set rulebase security rules \"AllowEcomm-AppID\" destination EcommPrivate")
    );
    assert!(rendered.contains("# --- Phase 4: Enable Scored Service Rules ---"));
    assert!(rendered.contains("set rulebase security rules \"AllowEmail-AppID\" disabled no"));
    assert!(rendered.contains("commit\n"));
    assert!(rendered.contains("exit\nset cli scripting-mode off\n"));
}

#[test]
fn test_baseline_diff() {
    let clean = XmlNode::parse(SAMPLE_CLEAN_BASELINE_XML).expect("Clean baseline parse failed");
    let drifted = XmlNode::parse(SAMPLE_DRIFTED_XML).expect("Drifted parse failed");

    let diff_findings = diff_baseline(&drifted, &clean);

    // Drifted XML has AllowRedTeamBackdoor which is not in clean baseline
    let extra: Vec<_> = diff_findings
        .iter()
        .filter(|f| f.check_id == "DIFF-EXTRA-RULE")
        .collect();
    assert_eq!(extra.len(), 1);
    assert_eq!(extra[0].target, "AllowRedTeamBackdoor");

    // Drifted XML has AllowEmail-AppID disabled while baseline has it enabled
    let state_diff: Vec<_> = diff_findings
        .iter()
        .filter(|f| f.check_id == "DIFF-STATE-MISMATCH")
        .collect();
    assert_eq!(state_diff.len(), 1);
    assert_eq!(state_diff[0].target, "AllowEmail-AppID");

    // Drifted XML has AllowEcomm-AppID destination EcommPub instead of EcommPrivate
    let dest_diff: Vec<_> = diff_findings
        .iter()
        .filter(|f| f.check_id == "DIFF-DEST-MISMATCH")
        .collect();
    assert_eq!(dest_diff.len(), 1);
    assert_eq!(dest_diff[0].target, "AllowEcomm-AppID");
}

#[test]
fn test_cli_args_parsing() {
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        mode: TestMode,
    }

    #[derive(clap::Subcommand, Debug)]
    enum TestMode {
        PaloAlto(linux_defender::tools::palo_alto::CliArgs),
    }

    let args = [
        "linux-defender",
        "palo-alto",
        "--audit-xml",
        "running-config.xml",
        "--out-remediation",
        "pa_remedy.txt",
        "--team",
        "7",
    ];

    let cli = TestCli::try_parse_from(args).expect("Failed to parse CLI args");
    match cli.mode {
        TestMode::PaloAlto(palo_args) => {
            assert_eq!(
                palo_args.audit_xml,
                Some(PathBuf::from("running-config.xml"))
            );
            assert_eq!(
                palo_args.out_remediation,
                Some(PathBuf::from("pa_remedy.txt"))
            );
            assert_eq!(palo_args.team, Some(7));
            assert_eq!(palo_args.host, "172.20.240.200");
            assert_eq!(palo_args.port, 443);
        }
    }
}

#[test]
fn test_recreated_baseline_known_good_is_clean() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let baseline_path = PathBuf::from(manifest_dir)
        .join("tests/fixtures/palo_alto/baseline_known_good.xml");
    let content = std::fs::read_to_string(&baseline_path)
        .expect("Failed to read baseline_known_good.xml");
    let root = XmlNode::parse(&content).expect("Failed to parse baseline_known_good.xml");

    let findings = audit_config(&root, None);
    assert_eq!(
        findings.len(),
        0,
        "Known-good baseline XML must produce 0 audit findings, got: {:?}",
        findings
    );

    let diff_findings = diff_baseline(&root, &root);
    assert_eq!(
        diff_findings.len(),
        0,
        "Known-good baseline XML diffed against itself must produce 0 findings, got: {:?}",
        diff_findings
    );
}

#[test]
fn test_non_baseline_custom_rule_flagged_without_fix() {
    let xml = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
    <rulebase><security><rules>
      <entry name="AllowICMP">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <service><member>application-default</member></service>
        <application><member>ping</member></application>
        <action>allow</action><disabled>no</disabled>
      </entry>
      <entry name="CustomDenyTraffic">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><application><member>any</member></application>
        <action>deny</action><disabled>no</disabled>
      </entry>
    </rules></security></rulebase>
  </entry></vsys></entry></devices>
</config>"#;
    let root = XmlNode::parse(xml).unwrap();
    let findings = audit_config(&root, None);

    let extra = findings
        .iter()
        .find(|f| f.check_id == "AUD-EXTRA-RULE")
        .expect("Should flag non-baseline custom rule");
    assert_eq!(extra.target, "CustomDenyTraffic");
    assert!(
        extra.remediation.is_empty(),
        "Extra non-allow rule must be flagged without automated deletion command"
    );
}

#[test]
fn test_non_baseline_nat_flagged_without_fix() {
    let xml = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
    <rulebase><nat><rules>
      <entry name="CustomWhiteTeamNAT">
        <from><member>External</member></from><to><member>Internal</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
      </entry>
      <entry name="Ecomm-StaticNAT">
        <from><member>Internal</member></from><to><member>External</member></to>
        <source><member>EcommPriv</member></source><destination><member>any</member></destination>
      </entry>
    </rules></nat></rulebase>
  </entry></vsys></entry></devices>
</config>"#;
    let root = XmlNode::parse(xml).unwrap();
    let findings = audit_config(&root, None);

    // Ecomm-StaticNAT is in script -> has fix
    let red_nat = findings
        .iter()
        .find(|f| f.check_id == "AUD-RED-NAT")
        .expect("Should flag redundant NAT");
    assert_eq!(red_nat.target, "Ecomm-StaticNAT");
    assert_eq!(
        red_nat.remediation,
        vec!["delete rulebase nat rules \"Ecomm-StaticNAT\""]
    );

    // CustomWhiteTeamNAT is in addition to script -> flag only, NO fix
    let extra_nat = findings
        .iter()
        .find(|f| f.check_id == "AUD-EXTRA-NAT")
        .expect("Should flag non-baseline NAT");
    assert_eq!(extra_nat.target, "CustomWhiteTeamNAT");
    assert!(
        extra_nat.remediation.is_empty(),
        "Non-baseline NAT must be flagged without automated deletion command"
    );
}

#[test]
fn test_interface_and_zone_extraction() {
    let xml = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices><entry name="localhost.localdomain">
    <network>
      <interface>
        <ethernet>
          <entry name="ethernet1/1">
            <layer3>
              <ip><entry name="10.0.0.1/24"/></ip>
              <interface-management-profile>allow-ping</interface-management-profile>
            </layer3>
            <comment>WAN Uplink</comment>
            <link-state>up</link-state>
          </entry>
          <entry name="ethernet1/2">
            <layer3>
              <ip><entry name="172.16.0.1/24"/></ip>
            </layer3>
          </entry>
        </ethernet>
      </interface>
    </network>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="External">
          <network><layer3><member>ethernet1/2</member></layer3></network>
        </entry>
        <entry name="untrust">
          <network><layer3><member>ethernet1/1</member></layer3></network>
        </entry>
      </zone>
    </entry></vsys>
  </entry></devices>
</config>"#;
    let root = XmlNode::parse(xml).unwrap();
    let zones = extract_zones(&root);
    assert_eq!(zones.len(), 2);
    assert_eq!(zones[0].name, "External");
    assert_eq!(zones[0].interfaces, vec!["ethernet1/2"]);
    assert_eq!(zones[1].name, "untrust");
    assert_eq!(zones[1].interfaces, vec!["ethernet1/1"]);

    let ifaces = extract_interfaces(&root, &zones);
    assert_eq!(ifaces.len(), 2);
    let if1 = &ifaces[0];
    assert_eq!(if1.name, "ethernet1/1");
    assert_eq!(if1.if_type, "ethernet");
    assert_eq!(if1.mode, "layer3");
    assert_eq!(if1.ip_addresses, vec!["10.0.0.1/24"]);
    assert_eq!(if1.zone.as_deref(), Some("untrust"));
    assert_eq!(if1.mgmt_profile.as_deref(), Some("allow-ping"));
    assert_eq!(if1.comment.as_deref(), Some("WAN Uplink"));
    assert_eq!(if1.link_state.as_deref(), Some("up"));

    let if2 = &ifaces[1];
    assert_eq!(if2.name, "ethernet1/2");
    assert_eq!(if2.zone.as_deref(), Some("External"));
    assert_eq!(if2.mgmt_profile, None);
}

#[test]
fn test_aud_iface_inventory_and_mgmt_exposure() {
    let xml = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices><entry name="localhost.localdomain">
    <network>
      <interface>
        <ethernet>
          <entry name="ethernet1/2">
            <layer3>
              <ip><entry name="172.16.0.1/24"/></ip>
              <interface-management-profile>mgmt-allow</interface-management-profile>
            </layer3>
          </entry>
        </ethernet>
      </interface>
    </network>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="External">
          <network><layer3><member>ethernet1/2</member></layer3></network>
        </entry>
      </zone>
    </entry></vsys>
  </entry></devices>
</config>"#;
    let root = XmlNode::parse(xml).unwrap();
    let findings = audit_config(&root, None);

    // 1. Inventory notification
    let inv = findings
        .iter()
        .find(|f| f.check_id == "AUD-IFACE-SETUP" && f.target == "ethernet1/2")
        .expect("Should produce interface inventory notification");
    assert_eq!(inv.severity, Severity::Info);
    assert!(inv.message.contains("zone=External"));
    assert!(inv.remediation.is_empty());

    // 2. High severity finding for management profile exposure
    let mgmt = findings
        .iter()
        .find(|f| f.check_id == "AUD-IFACE-MGMT")
        .expect("Should flag management profile exposure");
    assert_eq!(mgmt.severity, Severity::High);
    assert_eq!(mgmt.target, "ethernet1/2");
    assert_eq!(
        mgmt.remediation,
        vec!["set network interface ethernet ethernet1/2 layer3 interface-management-profile none"]
    );

    // Verify RemediationScript groups it into Phase 5 (Hardening)
    let mut script = RemediationScript::new();
    script.add(mgmt.remediation[0].clone());
    let rendered = script.render();
    assert!(
        rendered.contains("# --- Phase 5: Hardening & Exposure Reduction ---"),
        "Management profile remediation must be in Phase 5"
    );
    assert!(rendered.contains("set network interface ethernet ethernet1/2 layer3 interface-management-profile none"));
}

#[test]
fn test_aud_iface_no_zone_and_extra_non_baseline() {
    let xml = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices><entry name="localhost.localdomain">
    <network>
      <interface>
        <ethernet>
          <entry name="ethernet1/1">
            <layer3>
              <ip><entry name="10.10.10.1/24"/></ip>
            </layer3>
          </entry>
          <entry name="ethernet1/3">
            <layer3>
              <ip><entry name="172.20.240.254/24"/></ip>
            </layer3>
            <disabled>yes</disabled>
          </entry>
        </ethernet>
      </interface>
    </network>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="External">
          <network><layer3><member>ethernet1/1</member></layer3></network>
        </entry>
      </zone>
    </entry></vsys>
  </entry></devices>
</config>"#;
    let root = XmlNode::parse(xml).unwrap();
    let findings = audit_config(&root, None);

    // ethernet1/1 is non-standard (not 1/2 or 1/3)
    let extra = findings
        .iter()
        .find(|f| f.check_id == "AUD-IFACE-EXTRA" && f.target == "ethernet1/1")
        .expect("Should flag non-baseline ethernet1/1");
    assert_eq!(extra.severity, Severity::Medium);
    assert!(extra.message.contains("Non-baseline interface 'ethernet1/1'"));
    assert!(extra.remediation.is_empty(), "Extra interface flagged without fix");

    // ethernet1/3 is unzoned (not listed in zone)
    let no_zone = findings
        .iter()
        .find(|f| f.check_id == "AUD-IFACE-NO-ZONE" && f.target == "ethernet1/3")
        .expect("Should flag unzoned L3 interface");
    assert_eq!(no_zone.severity, Severity::Medium);
    assert!(no_zone.remediation.is_empty());

    // ethernet1/3 is disabled (critical baseline failure)
    let disabled = findings
        .iter()
        .find(|f| f.check_id == "AUD-IFACE-EXTRA" && f.target == "ethernet1/3")
        .expect("Should flag disabled baseline interface");
    assert_eq!(disabled.severity, Severity::Critical);
    assert_eq!(
        disabled.remediation,
        vec!["set network interface ethernet ethernet1/3 disabled no"]
    );
}

#[test]
fn test_aud_zone_mismatch_detection() {
    let xml = r#"<?xml version="1.0"?>
<config version="11.0.0">
  <devices><entry name="localhost.localdomain">
    <vsys><entry name="vsys1">
      <zone>
        <entry name="External">
          <network><layer3><member>ethernet1/2</member></layer3></network>
        </entry>
        <entry name="Internal">
          <network><layer3><member>ethernet1/3</member></layer3></network>
        </entry>
      </zone>
      <rulebase><security><rules>
        <entry name="AllowValid">
          <from><member>External</member></from><to><member>Internal</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <service><member>any</member></service><application><member>ping</member></application>
          <action>allow</action><disabled>no</disabled>
        </entry>
        <entry name="AllowGhostZone">
          <from><member>PhantomZone</member></from><to><member>Internal</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <service><member>any</member></service><application><member>ping</member></application>
          <action>allow</action><disabled>no</disabled>
        </entry>
      </rules></security></rulebase>
    </entry></vsys>
  </entry></devices>
</config>"#;
    let root = XmlNode::parse(xml).unwrap();
    let findings = audit_config(&root, None);

    let mismatch = findings
        .iter()
        .find(|f| f.check_id == "AUD-ZONE-MISMATCH")
        .expect("Should detect rule referencing undefined zone");
    assert_eq!(mismatch.severity, Severity::High);
    assert_eq!(mismatch.target, "AllowGhostZone:PhantomZone");
    assert!(mismatch.message.contains("references undefined zone 'PhantomZone'"));
    assert!(mismatch.remediation.is_empty());
}
