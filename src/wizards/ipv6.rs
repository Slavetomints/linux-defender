/// IPv6 static address configuration wizard.
///
/// Steps: detect interfaces → select interface → address → prefix →
///        gateway → DNS → summary → execute.
use std::sync::{Arc, Mutex};

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::WizardAction;

/// Detected network management stack on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetStack {
    /// Uses `nmcli` (NetworkManager).
    NetworkManager,
    /// Uses `netplan apply`.
    Netplan,
    /// Uses `/etc/network/interfaces` (ifupdown).
    Interfaces,
    /// Uses `/etc/sysconfig/network-scripts/` (RHEL/CentOS).
    Sysconfig,
}

impl NetStack {
    /// Human-readable label for the detected stack.
    fn label(self) -> &'static str {
        match self {
            NetStack::NetworkManager => "NetworkManager (nmcli)",
            NetStack::Netplan => "netplan",
            NetStack::Interfaces => "/etc/network/interfaces",
            NetStack::Sysconfig => "/etc/sysconfig/network-scripts",
        }
    }
}

/// A form field in the IPv6 configuration wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Network interface selector.
    Interface,
    /// IPv6 address input.
    Address,
    /// Prefix length input (default 64).
    Prefix,
    /// Gateway input (optional).
    Gateway,
    /// DNS server input (optional).
    Dns,
}

impl Field {
    /// All fields in display order.
    const ALL: &'static [Field] = &[
        Field::Interface,
        Field::Address,
        Field::Prefix,
        Field::Gateway,
        Field::Dns,
    ];
    /// Human-readable label for the field.
    fn label(self) -> &'static str {
        match self {
            Field::Interface => "Interface",
            Field::Address => "IPv6 address",
            Field::Prefix => "Prefix length",
            Field::Gateway => "Gateway (optional)",
            Field::Dns => "DNS server (optional)",
        }
    }
    /// Zero-based index of the field in the form layout.
    fn idx(self) -> usize {
        match self {
            Field::Interface => 0,
            Field::Address => 1,
            Field::Prefix => 2,
            Field::Gateway => 3,
            Field::Dns => 4,
        }
    }
}

/// Wizard progress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Filling in the address form.
    Form,
    /// Reviewing the configuration before applying.
    Summary,
    /// Running the network stack commands.
    Executing,
}

/// IPv6 static address configuration wizard state.
pub struct Ipv6Wizard {
    /// Current wizard step.
    step: Step,
    /// Detected network interface names.
    ifaces: Vec<String>,
    /// Index of the selected interface.
    iface_cursor: usize,
    /// IPv6 address entered by the user.
    address: String,
    /// Prefix length entered by the user (default `"64"`).
    prefix: String,
    /// Optional gateway entered by the user.
    gateway: String,
    /// Optional DNS server entered by the user.
    dns: String,
    /// Currently focused form field.
    field: Field,
    /// Detected network management stack.
    stack: NetStack,
    /// Shared log lines streamed from the background thread.
    exec_log: Option<Arc<Mutex<Vec<String>>>>,
    /// Set to `true` by the background thread when execution finishes.
    exec_done: Arc<Mutex<bool>>,
    /// Scroll offset for the execution log.
    log_scroll: usize,
}

impl Ipv6Wizard {
    /// Create a new wizard, detecting network interfaces and stack.
    pub fn new() -> Self {
        let ifaces = detect_interfaces();
        let stack = detect_net_stack();
        Self {
            step: Step::Form,
            ifaces,
            iface_cursor: 0,
            address: String::new(),
            prefix: "64".into(),
            gateway: String::new(),
            dns: String::new(),
            field: Field::Interface,
            stack,
            exec_log: None,
            exec_done: Arc::new(Mutex::new(false)),
            log_scroll: 0,
        }
    }
}

impl Default for Ipv6Wizard {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv6Wizard {
    /// Render the wizard modal over `area`.
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let inner = super::modal_popup(f, area, 70, 85, " Configure Static IPv6 ");
        match self.step {
            Step::Form => self.render_form(f, inner),
            Step::Summary => self.render_summary(f, inner),
            Step::Executing => self.render_executing(f, inner),
        }
    }

    /// Render step 1: the address entry form.
    fn render_form(&self, f: &mut Frame, area: Rect) {
        // header: detected stack + interface list
        // then 4 text input fields
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // interface selector
                Constraint::Length(3), // address
                Constraint::Length(3), // prefix
                Constraint::Length(3), // gateway
                Constraint::Length(3), // dns
                Constraint::Min(0),
                Constraint::Length(2), // help
            ])
            .split(area);

        // interface selector (list scroll in the block)
        {
            let is_active = self.field == Field::Interface;
            let selected = self
                .ifaces
                .get(self.iface_cursor)
                .map(|s| s.as_str())
                .unwrap_or("(none)");
            let stack_tag = format!("  network stack: {}", self.stack.label());
            let disp = format!(" {} {}", selected, stack_tag);
            f.render_widget(
                Paragraph::new(disp).block(
                    Block::default()
                        .title(format!(" {} ", Field::Interface.label()))
                        .borders(Borders::ALL)
                        .border_style(if is_active {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::Blue)
                        }),
                ),
                rows[0],
            );
        }

        let text_fields = [
            (Field::Address, &self.address),
            (Field::Prefix, &self.prefix),
            (Field::Gateway, &self.gateway),
            (Field::Dns, &self.dns),
        ];

        for (i, (fld, val)) in text_fields.iter().enumerate() {
            let active = self.field == *fld;
            let disp = if active {
                format!(" {}_", val)
            } else {
                format!(" {}", val)
            };
            f.render_widget(
                Paragraph::new(disp).block(
                    Block::default()
                        .title(format!(" {} ", fld.label()))
                        .borders(Borders::ALL)
                        .border_style(if active {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::Blue)
                        }),
                ),
                rows[i + 1],
            );
        }

        f.render_widget(
            Paragraph::new(
                " [Tab/↑↓] switch field  [←→] cycle interface  [Enter] summary  [Esc] cancel",
            )
            .style(Style::default().fg(Color::DarkGray)),
            rows[6],
        );
    }

    /// Render step 2: configuration summary before applying.
    fn render_summary(&self, f: &mut Frame, area: Rect) {
        let iface = self
            .ifaces
            .get(self.iface_cursor)
            .map(|s| s.as_str())
            .unwrap_or("(none)");

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Stack:     ", Style::default().fg(Color::DarkGray)),
                Span::raw(self.stack.label()),
            ]),
            Line::from(vec![
                Span::styled("  Interface: ", Style::default().fg(Color::DarkGray)),
                Span::raw(iface),
            ]),
            Line::from(vec![
                Span::styled("  Address:   ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{}/{}", self.address, self.prefix)),
            ]),
        ];

        if !self.gateway.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  Gateway:   ", Style::default().fg(Color::DarkGray)),
                Span::raw(self.gateway.clone()),
            ]));
        }
        if !self.dns.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  DNS:       ", Style::default().fg(Color::DarkGray)),
                Span::raw(self.dns.clone()),
            ]));
        }

        f.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .title(" Review — confirm IPv6 configuration ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(" [Enter] apply  [Esc] cancel")
                .style(Style::default().fg(Color::Yellow)),
            rows[1],
        );
    }

    /// Render step 3: live execution log.
    fn render_executing(&self, f: &mut Frame, area: Rect) {
        if let Some(ref log) = self.exec_log {
            let done = *self.exec_done.lock().unwrap();
            super::render_exec_log(f, area, log, done, self.log_scroll);
        }
    }

    /// Handle a keypress and return whether the wizard should close.
    pub fn handle_key(&mut self, key: KeyCode) -> WizardAction {
        match self.step {
            Step::Form => self.key_form(key),
            Step::Summary => {
                if key == KeyCode::Enter {
                    self.start_execution();
                    self.step = Step::Executing;
                }
            }
            Step::Executing => {
                let done = *self.exec_done.lock().unwrap();
                match key {
                    KeyCode::Up => {
                        if self.log_scroll > 0 {
                            self.log_scroll -= 1;
                        }
                    }
                    KeyCode::Down => {
                        self.log_scroll += 1;
                    }
                    _ if done => {
                        return WizardAction::Close;
                    }
                    _ => {}
                }
            }
        }
        WizardAction::Continue
    }

    /// Handle a keypress while the form is active.
    fn key_form(&mut self, key: KeyCode) {
        let idx = self.field.idx();
        let last = Field::ALL.len() - 1;
        match key {
            KeyCode::Tab | KeyCode::Down => {
                self.field = Field::ALL[(idx + 1) % Field::ALL.len()];
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.field = Field::ALL[if idx == 0 { last } else { idx - 1 }];
            }
            KeyCode::Left => {
                if self.field == Field::Interface && !self.ifaces.is_empty() {
                    self.iface_cursor = self
                        .iface_cursor
                        .checked_sub(1)
                        .unwrap_or(self.ifaces.len() - 1);
                }
            }
            KeyCode::Right => {
                if self.field == Field::Interface && !self.ifaces.is_empty() {
                    self.iface_cursor = (self.iface_cursor + 1) % self.ifaces.len();
                }
            }
            KeyCode::Char(c) if self.field != Field::Interface => {
                let buf = self.active_text_field();
                if buf.len() < 64 {
                    buf.push(c);
                }
            }
            KeyCode::Backspace if self.field != Field::Interface => {
                self.active_text_field().pop();
            }
            KeyCode::Enter if !self.address.is_empty() && !self.ifaces.is_empty() => {
                self.step = Step::Summary;
            }
            _ => {}
        }
    }

    /// Return a mutable reference to the currently focused text input field.
    fn active_text_field(&mut self) -> &mut String {
        match self.field {
            Field::Address => &mut self.address,
            Field::Prefix => &mut self.prefix,
            Field::Gateway => &mut self.gateway,
            Field::Dns => &mut self.dns,
            Field::Interface => &mut self.address, // unreachable in text-input handlers
        }
    }

    /// Spawn a background thread that applies the IPv6 config and streams output.
    fn start_execution(&mut self) {
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::clone(&self.exec_done);
        let lc = Arc::clone(&log);

        let iface = self
            .ifaces
            .get(self.iface_cursor)
            .cloned()
            .unwrap_or_default();
        let addr = self.address.clone();
        let prefix = self.prefix.clone();
        let gw = self.gateway.clone();
        let dns = self.dns.clone();
        let stack = self.stack;

        std::thread::spawn(move || {
            macro_rules! push {
                ($s:expr) => {
                    lc.lock().unwrap().push($s.to_string());
                };
            }

            push!(format!("→ Configuring IPv6 via {}…", stack.label()));
            push!(format!("  Interface : {}", iface));
            push!(format!("  Address   : {}/{}", addr, prefix));
            if !gw.is_empty() {
                push!(format!("  Gateway   : {}", gw));
            }
            if !dns.is_empty() {
                push!(format!("  DNS       : {}", dns));
            }
            push!("");

            match stack {
                NetStack::NetworkManager => {
                    apply_nmcli(&iface, &addr, &prefix, &gw, &dns, &lc);
                }
                NetStack::Netplan => {
                    apply_netplan(&iface, &addr, &prefix, &gw, &dns, &lc);
                }
                NetStack::Interfaces => {
                    apply_interfaces(&iface, &addr, &prefix, &gw, &dns, &lc);
                }
                NetStack::Sysconfig => {
                    apply_sysconfig(&iface, &addr, &prefix, &gw, &dns, &lc);
                }
            }

            push!("");
            push!("══ Done — press any key to close ══");
            *done.lock().unwrap() = true;
        });

        self.exec_log = Some(log);
    }
}

// ── Stack-specific helpers ────────────────────────────────────────────────────

/// Apply the IPv6 config using `nmcli` (NetworkManager).
fn apply_nmcli(
    iface: &str,
    addr: &str,
    prefix: &str,
    gw: &str,
    dns: &str,
    log: &Arc<Mutex<Vec<String>>>,
) {
    let cidr = format!("{}/{}", addr, prefix);
    let mut args = vec![
        "nmcli",
        "connection",
        "modify",
        iface,
        "ipv6.method",
        "manual",
        "ipv6.addresses",
        cidr.as_str(),
    ];
    if !gw.is_empty() {
        args.extend_from_slice(&["ipv6.gateway", gw]);
    }
    if !dns.is_empty() {
        args.extend_from_slice(&["ipv6.dns", dns]);
    }
    super::run_cmd_to_log(&args, log);
    super::run_cmd_to_log(&["nmcli", "connection", "up", iface], log);
}

/// Apply the IPv6 config by writing a netplan YAML file and running `netplan apply`.
fn apply_netplan(
    iface: &str,
    addr: &str,
    prefix: &str,
    gw: &str,
    dns: &str,
    log: &Arc<Mutex<Vec<String>>>,
) {
    let cidr = format!("{}/{}", addr, prefix);
    let mut yaml = format!(
        "network:\n  version: 2\n  ethernets:\n    {}:\n      dhcp6: false\n      addresses:\n        - {}\n",
        iface, cidr
    );
    if !gw.is_empty() {
        yaml.push_str(&format!("      gateway6: {}\n", gw));
    }
    if !dns.is_empty() {
        yaml.push_str(&format!(
            "      nameservers:\n        addresses: [{}]\n",
            dns
        ));
    }
    let path = format!("/etc/netplan/99-ipv6-{}.yaml", iface);
    log.lock().unwrap().push(format!("→ Writing {}…", path));
    match std::fs::write(&path, &yaml) {
        Ok(_) => log.lock().unwrap().push("  ✓ Written".into()),
        Err(e) => {
            log.lock().unwrap().push(format!("  ERROR: {}", e));
            return;
        }
    }
    super::run_cmd_to_log(&["netplan", "apply"], log);
}

/// Apply the IPv6 config by appending a stanza to `/etc/network/interfaces`.
fn apply_interfaces(
    iface: &str,
    addr: &str,
    prefix: &str,
    gw: &str,
    _dns: &str,
    log: &Arc<Mutex<Vec<String>>>,
) {
    let stanza = format!(
        "\niface {} inet6 static\n    address {}\n    netmask {}\n",
        iface, addr, prefix
    );
    let stanza = if !gw.is_empty() {
        format!("{}    gateway {}\n", stanza, gw)
    } else {
        stanza
    };

    log.lock()
        .unwrap()
        .push("→ Appending to /etc/network/interfaces…".into());
    let existing = std::fs::read_to_string("/etc/network/interfaces").unwrap_or_default();
    match std::fs::write("/etc/network/interfaces", existing + &stanza) {
        Ok(_) => log.lock().unwrap().push("  ✓ Written".into()),
        Err(e) => {
            log.lock().unwrap().push(format!("  ERROR: {}", e));
            return;
        }
    }
    super::run_cmd_to_log(
        &[
            "ip",
            "addr",
            "add",
            &format!("{}/{}", addr, prefix),
            "dev",
            iface,
        ],
        log,
    );
    if !gw.is_empty() {
        super::run_cmd_to_log(
            &[
                "ip", "-6", "route", "add", "default", "via", gw, "dev", iface,
            ],
            log,
        );
    }
}

/// Apply the IPv6 config by writing an `ifcfg-*` file under `/etc/sysconfig/network-scripts/`.
fn apply_sysconfig(
    iface: &str,
    addr: &str,
    prefix: &str,
    gw: &str,
    dns: &str,
    log: &Arc<Mutex<Vec<String>>>,
) {
    let path = format!("/etc/sysconfig/network-scripts/ifcfg-{}", iface);
    let mut conf = format!(
        "IPV6INIT=yes\nIPV6ADDR={}/{}\nIPV6_DEFAULTGW={}\n",
        addr, prefix, gw
    );
    if !dns.is_empty() {
        conf.push_str(&format!("DNS2={}\n", dns));
    }

    log.lock()
        .unwrap()
        .push(format!("→ Appending IPv6 settings to {}…", path));
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    match std::fs::write(&path, existing + "\n" + &conf) {
        Ok(_) => log.lock().unwrap().push("  ✓ Written".into()),
        Err(e) => {
            log.lock().unwrap().push(format!("  ERROR: {}", e));
            return;
        }
    }
    super::run_cmd_to_log(
        &[
            "ip",
            "addr",
            "add",
            &format!("{}/{}", addr, prefix),
            "dev",
            iface,
        ],
        log,
    );
}

// ── Detection helpers ─────────────────────────────────────────────────────────

/// Return a list of non-loopback network interface names from `/proc/net/dev`.
fn detect_interfaces() -> Vec<String> {
    let mut ifaces: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n != "lo")
                .collect()
        })
        .unwrap_or_default();
    ifaces.sort();
    if ifaces.is_empty() {
        ifaces.push("eth0".into());
    }
    ifaces
}

/// Probe the host and return the active network management stack.
fn detect_net_stack() -> NetStack {
    if super::cmd_succeeds("which nmcli") {
        NetStack::NetworkManager
    } else if super::cmd_succeeds("which netplan") {
        NetStack::Netplan
    } else if std::path::Path::new("/etc/network/interfaces").exists() {
        NetStack::Interfaces
    } else {
        NetStack::Sysconfig
    }
}
