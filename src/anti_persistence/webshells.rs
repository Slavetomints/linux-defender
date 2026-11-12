//! Webshell detection across PHP, ASP, ASPX, Python, and Ruby.
//!
//! Checks for known named shells first by matching all their distinguishing
//! patterns, then scores files by how many distinct command-execution
//! primitives they contain. Covers all candidate web roots.
//!
//! Only signature matches are auto-removed. Keyword-score hits are reported for
//! a human to verify, and files that are package-owned with an unchanged
//! checksum (vendor code like Roundcube) are skipped entirely, since legit web
//! apps routinely call exec()/proc_open() and read $_GET/$_POST.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::core::pkg::PkgVerifier;
use crate::core::{Action, DefenderContext, Finding, Result, Severity, Verdict, require_root};

/// Candidate web root directories to scan for webshells.
const WEB_ROOTS: &[&str] = &[
    "/var/www/html",
    "/var/www/roundcubemail",
    "/usr/share/roundcube",
    "/var/lib/roundcube",
    "/var/www/html/roundcubemail",
    "/var/www/opencart",
    "/var/www/prestashop",
    "/usr/share/roundcubemail",
    "/srv/http",
    "/srv/www/htdocs",
];

/// A named shell family: every pattern must match (case-insensitive AND).
struct ShellSignature {
    name: &'static str,
    patterns: &'static [&'static str],
}

// ── PHP signatures ────────────────────────────────────────────────────────────

const PHP_SHELLS: &[ShellSignature] = &[
    ShellSignature {
        name: "p0wny-shell",
        patterns: &["p0wny@shell", "$_server['http_host']"],
    },
    ShellSignature {
        name: "b374k",
        patterns: &["b374k", "$auth_pass"],
    },
    ShellSignature {
        name: "c99shell",
        patterns: &["c99shell", "filesman"],
    },
    ShellSignature {
        name: "r57shell",
        patterns: &["r57shell"],
    },
    ShellSignature {
        name: "WSO",
        patterns: &["wso", "wso_ver"],
    },
    ShellSignature {
        name: "weevely",
        patterns: &["@eval(base64_decode", "$kh="],
    },
    ShellSignature {
        name: "alfa-shell",
        patterns: &["alfa shell", "a1fav4r"],
    },
    ShellSignature {
        name: "antichat-shell",
        patterns: &["version 1.3 by grinay"],
    },
    ShellSignature {
        name: "crystal-shell",
        patterns: &["super-crystal and mohajer22", "convert_cyr_string"],
    },
    ShellSignature {
        name: "gamma-webshell",
        patterns: &["webshell::configuration", "webshell-cwd"],
    },
    ShellSignature {
        name: "htterminal",
        patterns: &["hashmd5", "anti-lfi"],
    },
    ShellSignature {
        name: "phpjackal",
        patterns: &["phpjackal", "nima_501@yahoo.com"],
    },
    ShellSignature {
        name: "predator",
        patterns: &["loffi & ls01r"],
    },
    ShellSignature {
        name: "simple-backdoor-dk",
        patterns: &["simple php backdoor by dk", "michaeldaw.org"],
    },
    ShellSignature {
        name: "accept-language-shell",
        patterns: &["passthru(getenv(", "http_accept_language"],
    },
    ShellSignature {
        name: "ncc-shell",
        patterns: &["national cracker crew"],
    },
    ShellSignature {
        name: "gfs-webshell",
        patterns: &["gfs web-shell ver 3.1.7"],
    },
    ShellSignature {
        name: "emperor-hacking-team",
        patterns: &["emperor hacking team"],
    },
    ShellSignature {
        name: "networkfilemanagerphp",
        patterns: &["networkfilemanagerphp for channel #hack.ru"],
    },
    ShellSignature {
        name: "azrailphp",
        patterns: &["azrailphp v1.0"],
    },
    ShellSignature {
        name: "stnc-webshell",
        patterns: &["stnc webshell v", "drmist.ru"],
    },
    ShellSignature {
        name: "worse-linux-shell",
        patterns: &["hack by shany"],
    },
    ShellSignature {
        name: "dxshell",
        patterns: &["dxshell", "dxexecnahuj"],
    },
    ShellSignature {
        name: "angel-shell",
        patterns: &["security angel team [s4t]", "angel_bc"],
    },
    ShellSignature {
        name: "simorgh-simshell",
        patterns: &["simorgh security mgz"],
    },
    ShellSignature {
        name: "ctt-shell",
        patterns: &["cyber terrorism team"],
    },
    ShellSignature {
        name: "egyspider",
        patterns: &["egyspider shell", "egyspider.eu"],
    },
    ShellSignature {
        name: "sniper-sa",
        patterns: &["(c)oded by sniper_sa"],
    },
    ShellSignature {
        name: "beyaz-hacker",
        patterns: &["beyaz_hacker.php", "permission_octal2string"],
    },
    ShellSignature {
        name: "c99madshell",
        patterns: &["c99madshell"],
    },
    ShellSignature {
        name: "liz0zim",
        patterns: &["liz0zim"],
    },
    ShellSignature {
        name: "simattacker",
        patterns: &["simattacker"],
    },
    ShellSignature {
        name: "ayyildiz-ayt",
        patterns: &["ayyildiz tim", "-ayt- shell"],
    },
    ShellSignature {
        name: "cadaver-shell",
        patterns: &["casus 1.5"],
    },
    ShellSignature {
        name: "phantom-shell",
        patterns: &["phantasma"],
    },
    ShellSignature {
        name: "ph-vayv",
        patterns: &["ph vayv"],
    },
    ShellSignature {
        name: "grp-webshell",
        patterns: &["grp webshell"],
    },
    ShellSignature {
        name: "winx-shell",
        patterns: &["winx shell"],
    },
    ShellSignature {
        name: "moroccan-spamers",
        patterns: &["moroccan spamers"],
    },
    ShellSignature {
        name: "safe0ver-shell",
        patterns: &["safe0ver shell"],
    },
    ShellSignature {
        name: "1945-shell",
        patterns: &["1945 shell", "c0ded by : shutdown57"],
    },
    ShellSignature {
        name: "ajax-php-command-shell",
        patterns: &["shellhelp", "$version = \"0.7b\""],
    },
    ShellSignature {
        name: "ak74-team",
        patterns: &["ak-74 security team web shell", "www.ak74-team.net"],
    },
    ShellSignature {
        name: "c0derz-shell",
        patterns: &[".::[c0derz]::. web-shell", "vint21h@c0derz.org.ua"],
    },
    ShellSignature {
        name: "c100-kingdefacer",
        patterns: &["kingdefacer was here", "jo1n@live.com"],
    },
    ShellSignature {
        name: "cgitelnet",
        patterns: &["cgi-telnet version 1.0", "rohitab batra"],
    },
    ShellSignature {
        name: "cyber-shell",
        patterns: &["cyber shell (v 1.0)", "cyber lords, 2002-2006"],
    },
    ShellSignature {
        name: "dc3-priv-shell",
        patterns: &["dc3 security crew", "only for priv8 use"],
    },
    ShellSignature {
        name: "ekin0x-shell",
        patterns: &["ekin0x shell volume 2.1s"],
    },
    ShellSignature {
        name: "ex0shell",
        patterns: &["exoshell volume 2.1s"],
    },
    ShellSignature {
        name: "fatalisztic-fx",
        patterns: &["by fatalisztic_fx", "meister_onthelaw@yahoo.com"],
    },
    ShellSignature {
        name: "g00nshell",
        patterns: &["g00nshell v1.3 final", "724ea055b975621b9d679f7077257bd9"],
    },
    ShellSignature {
        name: "imhabirligi-phpftp",
        patterns: &["imhabirligi phpftp", "imhabirligi@imhabirligi.com"],
    },
    ShellSignature {
        name: "jspwebshell",
        patterns: &["jspwebshell", "[b.c.t] copyright (c) 2006"],
    },
    ShellSignature {
        name: "kacak-grayhatz",
        patterns: &["kacak fso 1.0", "grayhatz hacking team"],
    },
    ShellSignature {
        name: "kadot-universal-shell",
        patterns: &["ka_ushell", "kadot universal shell"],
    },
    ShellSignature {
        name: "kral-blaster",
        patterns: &["kodlama by blaster"],
    },
    ShellSignature {
        name: "loaderz-webshell",
        patterns: &["loader'z web shell v 0.1.0.2", "loader pro-hack.ru"],
    },
    ShellSignature {
        name: "lostdc-shell",
        patterns: &["lostdc shell", "d3vilc0de crew"],
    },
    ShellSignature {
        name: "mackers-phpshell",
        patterns: &["phpshell.php", "max666@iranstars.com"],
    },
    ShellSignature {
        name: "ngh-webcommander",
        patterns: &["webcommander by cr4sh_aka_rkl v0.3.9 ngh edition"],
    },
    ShellSignature {
        name: "nix-remote-webshell",
        patterns: &["nix remote web shell", "dreamerz@mail.ru"],
    },
    ShellSignature {
        name: "ntdaddy",
        patterns: &["ntdaddy v1.9 by obzerve of fux0r inc."],
    },
    ShellSignature {
        name: "php-backdoor-zombie",
        patterns: &["coded by z0mbie [30.08.03]", "freenet.am/~zombie"],
    },
    ShellSignature {
        name: "php-findsock-shell",
        patterns: &["php-findsock-shell", "pentestmonkey@pentestmonkey.net"],
    },
    ShellSignature {
        name: "php-reverse-shell",
        patterns: &["php-reverse-shell - a reverse shell implementation in php"],
    },
    ShellSignature {
        name: "phpremoteview",
        patterns: &["dima@php.spb.ru", "version 04c, 2003-10-23"],
    },
    ShellSignature {
        name: "phpspy2006",
        patterns: &["codz by angel", "security angel team"],
    },
    ShellSignature {
        name: "nshell-v1",
        patterns: &["nshell v1.0"],
    },
    ShellSignature {
        name: "nstview",
        patterns: &["default password for nstview"],
    },
    ShellSignature {
        name: "private-i3lue",
        patterns: &["mail@wacker-welt.de"],
    },
    ShellSignature {
        name: "qsd-php-backdoor",
        patterns: &["daniel berliner - http://www.qsdconsulting.com/"],
    },
    ShellSignature {
        name: "r00t-hackerbox",
        patterns: &["r00t shell", "www.hackerbox.net"],
    },
    ShellSignature {
        name: "r0xem-shell",
        patterns: &["egy_spider shell v2"],
    },
    ShellSignature {
        name: "ru24-postwebshell",
        patterns: &["ru24postwebshell"],
    },
    ShellSignature {
        name: "saudi-shell",
        patterns: &["saudi sh3ll v1.0", "al-swisre"],
    },
    ShellSignature {
        name: "shellzx-mulcishell",
        patterns: &["mulcishell v0.2 - edited by kingdefacer"],
    },
    ShellSignature {
        name: "sincap-shell",
        patterns: &["shopen@aventgrup.net"],
    },
    ShellSignature {
        name: "small-shell-kingdefacer",
        patterns: &["small shell - edited by kingdefacer"],
    },
    ShellSignature {
        name: "soldierofallah",
        patterns: &["$password='alqaeda'"],
    },
    ShellSignature {
        name: "sosyete-bypass",
        patterns: &["sosyete safe mode bypass shell"],
    },
    ShellSignature {
        name: "spygrup-bypass",
        patterns: &["from spygrup.org"],
    },
    ShellSignature {
        name: "stres-bypass",
        patterns: &["stresbypass v1.0", "biyosecurity.com"],
    },
    ShellSignature {
        name: "tryag-kingdefacer",
        patterns: &["tryag.php - edited by kingdefacer", "kingdefacer@msn.com"],
    },
    ShellSignature {
        name: "wordpress-cmsmap-shell",
        patterns: &["plugin name: cmsmap - wordpress shell"],
    },
    ShellSignature {
        name: "wow-shell",
        patterns: &["mailer.claemon@gmail.com"],
    },
    ShellSignature {
        name: "zaco-webshell",
        patterns: &["small php web shell by zaco edited by kingdefacer"],
    },
    ShellSignature {
        name: "zacosmall",
        patterns: &["small php web shell by zaco", "zaco@yandex.ru"],
    },
    ShellSignature {
        name: "zehir-shell",
        patterns: &["powered by z", "by zehir!"],
    },
    ShellSignature {
        name: "aspx-ali-kaptanoglu",
        patterns: &["ali_kaptanoglu@hotmail.com"],
    },
    ShellSignature {
        name: "dq99sh",
        patterns: &["dq99sh 2.0", "by diki"],
    },
    ShellSignature {
        name: "erne-bypass",
        patterns: &["erne safe mode bypass - edited by kingdefacer"],
    },
    ShellSignature {
        name: "fatalerror-shell",
        patterns: &["version 1.0 by fatalerror"],
    },
    ShellSignature {
        name: "g3-gaza-hacker",
        patterns: &["www.gaza-hacker.net"],
    },
    ShellSignature {
        name: "h4ntu-shell",
        patterns: &["h4ntu shell [powered by tsoi]"],
    },
    ShellSignature {
        name: "myshell-digitart",
        patterns: &["shell.php,v 1.1.0 beta 2001/09/23"],
    },
    ShellSignature {
        name: "php-shell-drazz",
        patterns: &["phpshell.php  by macker", "drazz01@hotmail.com"],
    },
    ShellSignature {
        name: "cpanel-aria-kingdefacer",
        patterns: &["aria cpanel cracker version 1.0"],
    },
    ShellSignature {
        name: "lolipop-shell",
        patterns: &["xhackers.txt", "vb hack"],
    },
    ShellSignature {
        name: "megabor-shell",
        patterns: &["bu shell kodlar"],
    },
    ShellSignature {
        name: "php-include-w-shell",
        patterns: &["attacker@0wned.org"],
    },
    ShellSignature {
        name: "phpinj-shell",
        patterns: &["shell.php?cpc=ls"],
    },
];

// ── ASP signatures ────────────────────────────────────────────────────────────

const ASP_SHELLS: &[ShellSignature] = &[
    ShellSignature {
        name: "cmd-asp-5.1",
        patterns: &["brett.moore_at_security-assessment.com", "pchealth\\errorrep\\qheadles"],
    },
    ShellSignature {
        name: "cmdasp",
        patterns: &["maceo @ dogmile.com", "request.form(\".cmd\")"],
    },
    ShellSignature {
        name: "wscript-oneliner",
        patterns: &["createobject(\"wscript.shell\").exec(request.querystring(\"cmd\")).stdout.readall()"],
    },
    ShellSignature {
        name: "asp-net-process-shell",
        patterns: &["system.diagnostics.processstartinfo", "redirectstandardoutput = true"],
    },
];

// ── ASPX signatures ───────────────────────────────────────────────────────────

const ASPX_SHELLS: &[ShellSignature] = &[
    ShellSignature {
        name: "aspxshell-lt",
        patterns: &["aspx shell by lt <lt@mac.hush.com>"],
    },
    ShellSignature {
        name: "rootkit-net-aspx",
        patterns: &["master@rootkit.net.cn", "4d934e4cde0dce1d9b3ecaf84f5672b2"],
    },
    ShellSignature {
        name: "cmdasp-aspx",
        patterns: &["excutecmd", "psi.filename = \"cmd.exe\""],
    },
    ShellSignature {
        name: "soap-asmx-shell",
        patterns: &["<z1>cmd.exe</z1>", "webservice language=\"c#\" class=\"service\""],
    },
];

// ── Python signatures ─────────────────────────────────────────────────────────

const PYTHON_SHELLS: &[ShellSignature] = &[
    ShellSignature {
        name: "pty-spawn-shell",
        patterns: &["import pty", "pty.spawn(\"/bin/bash\")"],
    },
    ShellSignature {
        name: "python-cgi-webshell",
        patterns: &["import subprocess, cgi", "subprocess.getoutput(command)"],
    },
];

// ── Ruby signatures ───────────────────────────────────────────────────────────

const RUBY_SHELLS: &[ShellSignature] = &[
    ShellSignature {
        name: "srwsh-ruby",
        patterns: &["small ruby web shell", "%x(#{cgi.unescape(cgi['cmd'])})"],
    },
    ShellSignature {
        name: "ruby-cgi-exec",
        patterns: &["require 'cgi'", "exec \"/bin/bash\""],
    },
];

// ── Per-language keyword lists ────────────────────────────────────────────────

const PHP_KEYWORDS: &[&str] = &[
    "exec", "passthru", "shell_exec", "system", "proc_open", "popen", "pcntl_exec", "eval",
    // Input vectors -- any file reading from these is a candidate.
    // $_SERVER is deliberately excluded: nearly every PHP app reads it.
    "$_get[", "$_post[", "$_request[", "$_cookie[",
];

const PHP_EXEC_KEYWORDS: &[&str] = &[
    "exec", "passthru", "shell_exec", "system", "proc_open", "popen", "pcntl_exec", "eval",
];

const PHP_INPUT_KEYWORDS: &[&str] = &[
    "$_get[", "$_post[", "$_request[", "$_cookie[",
];

const ASP_KEYWORDS: &[&str] = &[
    "wscript.shell", "createobject", "server.execute", "response.write",
    "scriptengine", "cmd.exe",
    "request.querystring(", "request.form(", "request(",
];

const ASP_EXEC_KEYWORDS: &[&str] = &[
    "wscript.shell", "createobject", "server.execute", "scriptengine", "cmd.exe",
];

const ASP_INPUT_KEYWORDS: &[&str] = &[
    "request.querystring(", "request.form(", "request(",
];

const ASPX_KEYWORDS: &[&str] = &[
    "process.start", "processstartinfo", "cmd.exe", "shell_exec",
    "redirectstandardoutput", "system.diagnostics",
    "request.querystring[", "request.form[", "request[",
];

const ASPX_EXEC_KEYWORDS: &[&str] = &[
    "process.start", "processstartinfo", "redirectstandardoutput", "system.diagnostics",
];

const ASPX_INPUT_KEYWORDS: &[&str] = &[
    "request.querystring[", "request.form[", "request[",
];

const PYTHON_KEYWORDS: &[&str] = &[
    "os.system", "subprocess", "pty.spawn", "commands.getoutput",
    "popen", "exec(", "eval(",
    "request.args.get(", "request.form.get(", "request.args[", "request.form[",
    "cgi.fieldstorage", "os.environ.get(",
];

const PYTHON_EXEC_KEYWORDS: &[&str] = &[
    "os.system", "subprocess", "pty.spawn", "commands.getoutput", "popen", "exec(", "eval(",
];

const PYTHON_INPUT_KEYWORDS: &[&str] = &[
    "request.args.get(", "request.form.get(", "request.args[", "request.form[",
    "cgi.fieldstorage", "os.environ.get(",
];

const RUBY_KEYWORDS: &[&str] = &[
    "exec ", "system(", "%x(", "popen(", "spawn(",
    "params[:", "request.GET[", "params.fetch(",
];

const RUBY_EXEC_KEYWORDS: &[&str] = &["exec ", "system(", "%x(", "popen(", "spawn("];

const RUBY_INPUT_KEYWORDS: &[&str] = &["params[:", "request.get[", "params.fetch("];

// ── Language config ───────────────────────────────────────────────────────────

pub(crate) struct LangConfig {
    extensions: &'static [&'static str],
    signatures: &'static [ShellSignature],
    keywords: &'static [&'static str],
    exec_keywords: &'static [&'static str],
    input_keywords: &'static [&'static str],
    /// Match identifier keywords only as free function calls (`system(`), not
    /// as substrings (`filesystem`) or method calls (`$pdo->exec(`).
    call_match: bool,
    label: &'static str,
}

const LANGUAGES: &[LangConfig] = &[
    LangConfig {
        extensions: &["php", "php3", "php4", "php5", "phtml"],
        signatures: PHP_SHELLS,
        keywords: PHP_KEYWORDS,
        exec_keywords: PHP_EXEC_KEYWORDS,
        input_keywords: PHP_INPUT_KEYWORDS,
        call_match: true,
        label: "PHP",
    },
    LangConfig {
        extensions: &["asp"],
        signatures: ASP_SHELLS,
        keywords: ASP_KEYWORDS,
        exec_keywords: ASP_EXEC_KEYWORDS,
        input_keywords: ASP_INPUT_KEYWORDS,
        call_match: false,
        label: "ASP",
    },
    LangConfig {
        extensions: &["aspx", "asmx", "ashx"],
        signatures: ASPX_SHELLS,
        keywords: ASPX_KEYWORDS,
        exec_keywords: ASPX_EXEC_KEYWORDS,
        input_keywords: ASPX_INPUT_KEYWORDS,
        call_match: false,
        label: "ASPX",
    },
    LangConfig {
        extensions: &["py"],
        signatures: PYTHON_SHELLS,
        keywords: PYTHON_KEYWORDS,
        exec_keywords: PYTHON_EXEC_KEYWORDS,
        input_keywords: PYTHON_INPUT_KEYWORDS,
        call_match: false,
        label: "Python",
    },
    LangConfig {
        extensions: &["rb"],
        signatures: RUBY_SHELLS,
        keywords: RUBY_KEYWORDS,
        exec_keywords: RUBY_EXEC_KEYWORDS,
        input_keywords: RUBY_INPUT_KEYWORDS,
        call_match: false,
        label: "Ruby",
    },
];

// ── Detection types ───────────────────────────────────────────────────────────

/// A web-root file containing webshell primitives.
pub struct SuspiciousFile {
    /// Absolute path to the suspicious file.
    pub location: PathBuf,
    /// Heuristic score; higher = more suspicious.
    pub score: u16,
    /// Matched keyword strings that contributed to the score.
    pub keywords: Vec<String>,
    /// Name of the known shell family if a signature matched.
    pub matched_shell_name: Option<&'static str>,
    /// Language label (PHP, ASP, Python, etc.).
    pub lang_label: &'static str,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Scan all configured web roots for webshells across PHP, ASP, ASPX, Python, and Ruby.
pub fn run(ctx: &DefenderContext) -> Result {
    let is_root = require_root().is_ok();

    let roots_found: Vec<&str> = WEB_ROOTS
        .iter()
        .copied()
        .filter(|r| Path::new(r).exists())
        .collect();

    if roots_found.is_empty() {
        ctx.log_msg("[!] No web roots found, skipping webshell check");
        return Ok(());
    }

    let verifier = PkgVerifier::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut all_shells = Vec::new();
    for root_str in &roots_found {
        let web_root = Path::new(root_str);
        let shells = find_shells(web_root);
        ctx.debug(&format!("Scanned {}, {} hit(s)", root_str, shells.len()));
        for shell in shells {
            // Roots can overlap via symlinks (/var/lib/roundcube -> /usr/share/roundcube).
            let real = fs::canonicalize(&shell.location).unwrap_or_else(|_| shell.location.clone());
            if !seen.insert(real) {
                continue;
            }
            // Keyword-only hits on untouched package files are vendor code, not shells.
            if shell.matched_shell_name.is_none() && verifier.is_pristine(&shell.location) {
                ctx.debug(&format!(
                    "skip {}: package-owned, checksum OK",
                    shell.location.display()
                ));
                continue;
            }
            all_shells.push(shell);
        }
    }

    for shell in all_shells {
        let name_tag = shell
            .matched_shell_name
            .map(|n| format!("{} — ", n))
            .unwrap_or_default();

        let severity = if shell.matched_shell_name.is_some() {
            Severity::Critical
        } else {
            Severity::High
        };

        let mtime_label = shell
            .location
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| ctx.mtime_label(t))
            .unwrap_or_else(|| "unknown".into());

        // Only known signatures are deleted automatically; keyword scores are too
        // noisy to delete on (legit apps call exec() and read $_GET).
        let auto_remove = is_root && shell.matched_shell_name.is_some();

        if auto_remove {
            ctx.log_msg(&format!(
                "[!] {}{}  webshell detected: {} (keywords: {})",
                name_tag,
                shell.lang_label,
                shell.location.display(),
                shell.keywords.join(", "),
            ));
            ctx.log_evidence_file(&shell.location);
            let removed = ctx.remove_path_logged(&shell.location);

            let summary = format!(
                "{}{} webshell REMOVED: {}",
                name_tag,
                shell.lang_label,
                shell.location.display(),
            );
            let detail = format!(
                "path: {}\nlang: {}\nmatched keywords: {}\nremoved: {}",
                shell.location.display(),
                shell.lang_label,
                shell.keywords.join(", "),
                removed,
            );

            let mut finding = Finding::new(severity, "webshells", summary, detail)
                .with_path(shell.location.clone())
                .with_context("path", shell.location.display().to_string())
                .with_context("lang", shell.lang_label)
                .with_context("score", shell.score.to_string())
                .with_context("keywords", shell.keywords.join(", "))
                .with_context("mtime", mtime_label)
                .with_context("removed", removed.to_string())
                .with_verdict(
                    Verdict::Remove,
                    if removed {
                        "File was automatically deleted. Evidence and proof logged above.".to_string()
                    } else {
                        "Deletion attempted but file may still exist — check the log.".to_string()
                    },
                );
            if let Some(name) = shell.matched_shell_name {
                finding = finding.with_context("shell name", name);
            }
            ctx.emit(finding);
        } else {
            let summary = format!(
                "{}suspicious {} (score:{}) at {}",
                name_tag,
                shell.lang_label,
                shell.score,
                shell.location.display()
            );
            let detail = format!(
                "path: {}\nlang: {}\nmatched keywords: {}",
                shell.location.display(),
                shell.lang_label,
                shell.keywords.join(", ")
            );

            ctx.log_evidence_file(&shell.location);

            let verdict = if shell.matched_shell_name.is_some() {
                Verdict::Remove
            } else {
                Verdict::Investigate
            };
            let recommendation = if let Some(name) = shell.matched_shell_name {
                format!(
                    "{} is a known webshell giving the attacker an interactive shell via HTTP. \
                     Delete this file immediately.",
                    name
                )
            } else {
                format!(
                    "This {} file contains {} command-execution primitive(s): {}. \
                     It is not package-owned (or was modified since install). \
                     Verify before deleting.",
                    shell.lang_label,
                    shell.score,
                    shell.keywords.join(", ")
                )
            };

            let mut finding = Finding::new(severity, "webshells", summary, detail)
                .with_path(shell.location.clone())
                .with_context("path", shell.location.display().to_string())
                .with_context("lang", shell.lang_label)
                .with_context("score", shell.score.to_string())
                .with_context("keywords", shell.keywords.join(", "))
                .with_context("mtime", mtime_label)
                .with_verdict(verdict, recommendation);
            if let Some(name) = shell.matched_shell_name {
                finding = finding.with_context("shell name", name);
            }
            if is_root {
                finding = finding.with_action(Action::Delete(shell.location));
            }
            ctx.emit(finding);
        }
    }

    Ok(())
}

/// Scan `root` recursively for webshell primitives across all supported languages.
pub fn find_shells(root: &Path) -> Vec<SuspiciousFile> {
    let mut shells = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let lang = LANGUAGES
            .iter()
            .find(|l| l.extensions.contains(&ext.as_str()));

        let Some(lang) = lang else {
            continue;
        };

        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };

        if let Some(hit) = score_content(path, &content, lang) {
            shells.push(hit);
        }
    }

    shells
}

/// Score one file against a language config, or `None` when nothing matched.
pub(crate) fn score_content(path: &Path, content: &str, lang: &LangConfig) -> Option<SuspiciousFile> {
    let lowered = content.to_lowercase();

    let matched_name = lang
        .signatures
        .iter()
        .find(|sig| sig.patterns.iter().all(|p| lowered.contains(*p)))
        .map(|sig| sig.name);

    let keywords: Vec<String> = lang
        .keywords
        .iter()
        .filter(|kw| keyword_present(&lowered, kw, lang.call_match))
        .map(|kw| (*kw).to_string())
        .collect();

    if keywords.is_empty() && matched_name.is_none() {
        return None;
    }

    let base_score = keywords.len() as u16;

    // Co-occurrence bonus: file accepts URL input AND has an exec primitive -> very likely a shell
    let has_exec = lang
        .exec_keywords
        .iter()
        .any(|kw| keyword_present(&lowered, kw, lang.call_match));
    let has_input = lang.input_keywords.iter().any(|kw| lowered.contains(*kw));
    let bonus: u16 = if has_exec && has_input { 2 } else { 0 };

    Some(SuspiciousFile {
        location: path.to_path_buf(),
        score: base_score + bonus,
        keywords,
        matched_shell_name: matched_name,
        lang_label: lang.label,
    })
}

/// Check whether `kw` appears in `hay`.
///
/// With `call_match`, a plain identifier keyword only counts when used as a
/// free function call: not part of a longer identifier (`filesystem`,
/// `curl_exec`), not a variable (`$exec`), not a method (`->exec`, `::exec`),
/// and followed by optional whitespace then `(`.
fn keyword_present(hay: &str, kw: &str, call_match: bool) -> bool {
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    if !call_match || !kw.bytes().all(is_ident) {
        return hay.contains(kw);
    }
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(off) = hay[from..].find(kw) {
        let start = from + off;
        let end = start + kw.len();
        from = start + 1;
        if start > 0 {
            let prev = bytes[start - 1];
            if is_ident(prev) || prev == b'$' {
                continue;
            }
            if start >= 2 && (&bytes[start - 2..start] == b"->" || &bytes[start - 2..start] == b"::") {
                continue;
            }
        }
        let mut i = end;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'(' {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn php() -> &'static LangConfig {
        LANGUAGES.iter().find(|l| l.label == "PHP").unwrap()
    }

    fn asp() -> &'static LangConfig {
        LANGUAGES.iter().find(|l| l.label == "ASP").unwrap()
    }

    fn python() -> &'static LangConfig {
        LANGUAGES.iter().find(|l| l.label == "Python").unwrap()
    }

    #[test]
    fn clean_php_scores_nothing() {
        assert!(score_content(Path::new("a.php"), "<?php echo 'hi'; ?>", php()).is_none());
    }

    #[test]
    fn counts_each_distinct_php_keyword_once() {
        // system + eval + $_get[ = 3 keywords; exec+input co-occurrence bonus = +2 -> score 5
        let content = "<?php system($_GET['c']); eval($x); system($y); ?>";
        let hit = score_content(Path::new("shell.php"), content, php()).unwrap();
        assert_eq!(hit.score, 5);
        assert!(hit.keywords.contains(&"system".to_string()));
        assert!(hit.keywords.contains(&"eval".to_string()));
        assert!(hit.keywords.contains(&"$_get[".to_string()));
    }

    #[test]
    fn detects_p0wny_by_name() {
        let content = r#"<?php $p0wny@shell; $_SERVER['HTTP_HOST']; system($_GET['c']); ?>"#;
        let hit = score_content(Path::new("x.php"), content, php()).unwrap();
        assert_eq!(hit.matched_shell_name, Some("p0wny-shell"));
    }

    #[test]
    fn detects_wso_by_name() {
        let content = "wso wso_ver eval($_POST['cmd']);";
        let hit = score_content(Path::new("x.php"), content, php()).unwrap();
        assert_eq!(hit.matched_shell_name, Some("WSO"));
    }

    #[test]
    fn detects_asp_wscript_shell() {
        let content = "createobject(\"wscript.shell\").exec(request.querystring(\"cmd\")).stdout.readall()";
        let hit = score_content(Path::new("x.asp"), content, asp()).unwrap();
        assert_eq!(hit.matched_shell_name, Some("wscript-oneliner"));
    }

    #[test]
    fn detects_python_pty_shell() {
        let content = "import pty\npty.spawn(\"/bin/bash\")";
        let hit = score_content(Path::new("x.py"), content, python()).unwrap();
        assert_eq!(hit.matched_shell_name, Some("pty-spawn-shell"));
    }

    #[test]
    fn php_call_matching_ignores_substrings_and_methods() {
        assert!(keyword_present("system($x)", "system", true));
        assert!(keyword_present("@system ($x)", "system", true));
        assert!(!keyword_present("$fs = new filesystem()", "system", true));
        assert!(!keyword_present("$pdo->exec($sql)", "exec", true));
        assert!(!keyword_present("rcube::exec($cmd)", "exec", true));
        assert!(!keyword_present("curl_exec($ch)", "exec", true));
        assert!(!keyword_present("$this->execute()", "exec", true));
        assert!(!keyword_present("// operating system", "system", true));
        assert!(keyword_present("shell_exec($c)", "shell_exec", true));
    }

    #[test]
    fn roundcube_style_vendor_code_does_not_score_as_shell() {
        // Typical web-app shape: reads $_GET/$_POST/$_SERVER, uses DB exec and
        // filesystem helpers, but has no free exec-family call.
        let content = r#"<?php
            $task = $_GET['_task']; $act = $_POST['_action'];
            $host = $_SERVER['HTTP_HOST'];
            $this->db->exec($sql); $fs = new rcube_filesystem();
            $res = $stmt->execute(); $ok = curl_exec($ch);
        ?>"#;
        let hit = score_content(Path::new("index.php"), content, php()).unwrap();
        assert!(hit.score < 3, "score {} keywords {:?}", hit.score, hit.keywords);
    }

    #[test]
    fn extension_dispatch_covers_all_languages() {
        let all_exts: Vec<&str> = LANGUAGES.iter().flat_map(|l| l.extensions.iter().copied()).collect();
        for ext in &["php", "asp", "aspx", "py", "rb"] {
            assert!(all_exts.contains(ext), "extension {} not covered", ext);
        }
    }
}
