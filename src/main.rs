use eframe::egui::{self, Color32, Key, Modifiers, RichText};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CVE_CACHE_TTL_SECS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Exposure {
    External,
    Local,
    Other,
}

#[derive(Debug, Clone)]
struct PortEntry {
    protocol: String,
    state: String,
    local_addr: String,
    port: String,
    exposure: Exposure,
    process: String,
    pid: String,
}

#[derive(Debug, Clone)]
struct PackageEntry {
    source: String,
    name: String,
    current_ver: String,
    new_ver: String,
}

#[derive(Debug, Clone)]
struct DesktopEntryItem {
    name: String,
    session_type: String,
    binary: String,
    active: bool,
    source_path: String,
}

#[derive(Debug, Clone)]
struct AppImageEntry {
    name: String,
    size_human: String,
    executable: bool,
    path: String,
}

#[derive(Debug, Clone)]
struct FlatpakEntry {
    app_id: String,
    name: String,
    version: String,
    branch: String,
    origin: String,
    installation: String,
}

#[derive(Debug, Clone)]
struct CveVulnerabilityEntry {
    package: String,
    severity: String,
    status: String,
    fixed_ver: String,
    cves: String,
    detail: String,
}

#[derive(Debug, Clone)]
struct CveResult {
    entries: Vec<CveVulnerabilityEntry>,
    note: Option<String>,
    from_cache: bool,
}

#[derive(Debug, Clone, Default)]
struct AuditSnapshot {
    ports: Vec<PortEntry>,
    ports_warning: Option<String>,
    packages: Vec<PackageEntry>,
    package_notes: Vec<String>,
    desktops: Vec<DesktopEntryItem>,
    session_summary: String,
    appimages: Vec<AppImageEntry>,
    flatpaks: Vec<FlatpakEntry>,
    flatpak_note: Option<String>,
    vulnerabilities: Vec<CveVulnerabilityEntry>,
    vulnerability_note: Option<String>,
    last_updated_unix: u64,
}

enum WorkerEvent {
    FullSnapshot(AuditSnapshot),
    PackagesCacheUpdated {
        packages: Vec<PackageEntry>,
        package_notes: Vec<String>,
        updated_unix: u64,
    },
    CvesUpdated {
        result: CveResult,
        updated_unix: u64,
    },
    AppImagesUpdated(Vec<AppImageEntry>),
    FlatpaksUpdated {
        flatpaks: Vec<FlatpakEntry>,
        note: Option<String>,
    },
    ActionResult {
        message: String,
        is_error: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Ports,
    Packages,
    Vulnerabilities,
    Desktops,
    AppImages,
    Flatpaks,
}

struct ArchCollectors;

impl ArchCollectors {
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn command_exists(bin: &str) -> bool {
        env::var_os("PATH")
            .map(|paths| {
                env::split_paths(&paths).any(|dir| {
                    let candidate = dir.join(bin);
                    candidate.is_file() && Self::is_executable(&candidate)
                })
            })
            .unwrap_or(false)
    }

    fn is_executable(path: &Path) -> bool {
        fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    fn classify_bind(addr: &str) -> Exposure {
        let clean = addr.trim();
        if matches!(clean, "0.0.0.0" | "*" | "[::]" | "::") {
            Exposure::External
        } else if clean.starts_with("127.") || matches!(clean, "[::1]" | "::1" | "localhost") {
            Exposure::Local
        } else {
            Exposure::Other
        }
    }

    fn split_addr_port(endpoint: &str) -> (String, String) {
        if let Some(rest) = endpoint.strip_prefix('[') {
            if let Some((ipv6, after)) = rest.split_once("]:") {
                return (format!("[{}]", ipv6), after.to_string());
            }
        }
        if let Some((addr, port)) = endpoint.rsplit_once(':') {
            return (addr.to_string(), port.to_string());
        }
        (endpoint.to_string(), "-".to_string())
    }

    fn run_with_timeout(
        cmd: &str,
        args: &[&str],
        timeout_secs: u64,
    ) -> Result<std::process::Output, String> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Falha ao iniciar '{}': {}", cmd, e))?;

        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return child
                        .wait_with_output()
                        .map_err(|e| format!("Falha ao coletar saída de '{}': {}", cmd, e));
                }
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!("Timeout ({}s) ao executar '{}'", timeout_secs, cmd));
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(format!("Erro aguardando '{}': {}", cmd, e)),
            }
        }
    }

    fn collect_open_ports() -> (Vec<PortEntry>, Option<String>) {
        let mut entries = Vec::new();
        let mut warning = None;

        if Self::command_exists("ss") {
            match Self::run_with_timeout("ss", &["-tulnpH"], 8) {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let mut hidden_pids = false;

                    for line in stdout.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() < 5 {
                            continue;
                        }
                        let protocol = parts[0].to_uppercase();
                        let state = parts[1].to_string();
                        let (local_addr, port) = Self::split_addr_port(parts[4]);
                        let exposure = Self::classify_bind(&local_addr);

                        let proc_raw = if parts.len() > 6 {
                            parts[6..].join(" ")
                        } else {
                            String::new()
                        };

                        let proc_names = Self::extract_quoted_names(&proc_raw);
                        let pids = Self::extract_pids(&proc_raw);

                        let (process, pid) = if !proc_names.is_empty() {
                            (
                                proc_names.join(", "),
                                if pids.is_empty() {
                                    "-".to_string()
                                } else {
                                    pids.join(", ")
                                },
                            )
                        } else {
                            hidden_pids = true;
                            ("oculto (sem root)".to_string(), "-".to_string())
                        };

                        entries.push(PortEntry {
                            protocol,
                            state,
                            local_addr,
                            port,
                            exposure,
                            process,
                            pid,
                        });
                    }

                    let is_root = unsafe { libc_geteuid() } == 0;
                    if hidden_pids && !is_root {
                        warning = Some(
                            "Alguns processos pertencem a outros usuários/root. Execute com sudo para ver todos os PIDs."
                                .to_string(),
                        );
                    }
                }
                Err(err) => {
                    warning = Some(format!("{} — usando fallback /proc/net.", err));
                    entries = Self::collect_ports_proc_fallback();
                }
            }
        } else {
            warning = Some("Comando 'ss' (iproute2) não encontrado; usando /proc/net.".to_string());
            entries = Self::collect_ports_proc_fallback();
        }

        entries.sort_by(|a, b| {
            let prio = |e: &Exposure| match e {
                Exposure::External => 0,
                Exposure::Other => 1,
                Exposure::Local => 2,
            };
            let pa = a.port.parse::<u32>().unwrap_or(99_999);
            let pb = b.port.parse::<u32>().unwrap_or(99_999);
            prio(&a.exposure)
                .cmp(&prio(&b.exposure))
                .then(pa.cmp(&pb))
                .then(a.protocol.cmp(&b.protocol))
        });

        (entries, warning)
    }

    fn extract_quoted_names(raw: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '"' {
                let mut current = String::new();
                for inner in chars.by_ref() {
                    if inner == '"' {
                        if !current.is_empty() && !names.contains(&current) {
                            names.push(current);
                        }
                        break;
                    }
                    current.push(inner);
                }
            }
        }
        names
    }

    fn extract_pids(raw: &str) -> Vec<String> {
        let mut pids = Vec::new();
        for token in raw.split(|c: char| !c.is_ascii_alphanumeric() && c != '=') {
            if let Some(val) = token.strip_prefix("pid=") {
                if !val.is_empty() && val.chars().all(|c| c.is_ascii_digit()) {
                    let s = val.to_string();
                    if !pids.contains(&s) {
                        pids.push(s);
                    }
                }
            }
        }
        pids
    }

    fn collect_ports_proc_fallback() -> Vec<PortEntry> {
        let mut out = Vec::new();
        for (proto, path, is_v6) in [
            ("TCP", "/proc/net/tcp", false),
            ("TCP6", "/proc/net/tcp6", true),
        ] {
            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 4 || cols[3] != "0A" {
                    continue;
                }
                let Some((hex_ip, hex_port)) = cols[1].split_once(':') else {
                    continue;
                };
                let Ok(port_num) = u16::from_str_radix(hex_port, 16) else {
                    continue;
                };
                let addr = if !is_v6 {
                    u32::from_str_radix(hex_ip, 16)
                        .map(|raw| Ipv4Addr::from(u32::from_le(raw)).to_string())
                        .unwrap_or_else(|_| hex_ip.to_string())
                } else if hex_ip.chars().all(|c| c == '0') {
                    "[::]".to_string()
                } else {
                    let _ = Ipv6Addr::from([0; 16]);
                    "[::1]".to_string()
                };
                let exposure = Self::classify_bind(&addr);
                out.push(PortEntry {
                    protocol: proto.to_string(),
                    state: "LISTEN".to_string(),
                    local_addr: addr,
                    port: port_num.to_string(),
                    exposure,
                    process: "N/D (/proc/net)".to_string(),
                    pid: "-".to_string(),
                });
            }
        }
        out
    }

    fn collect_outdated_packages() -> (Vec<PackageEntry>, Vec<String>) {
        let mut pkgs = Vec::new();
        let mut notes = Vec::new();

        if Self::command_exists("checkupdates") {
            match Self::run_with_timeout("checkupdates", &[], 25) {
                Ok(output) => {
                    let code = output.status.code().unwrap_or(1);
                    if code == 0 || code == 2 {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for line in stdout.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 4 && parts[2] == "->" {
                                pkgs.push(PackageEntry {
                                    source: "Oficial".to_string(),
                                    name: parts[0].to_string(),
                                    current_ver: parts[1].to_string(),
                                    new_ver: parts[3].to_string(),
                                });
                            }
                        }
                    } else {
                        notes.push(
                            "checkupdates retornou erro (verifique rede/mirrors).".to_string(),
                        );
                    }
                }
                Err(e) => notes.push(e),
            }
        } else {
            notes.push(
                "Instale 'pacman-contrib' para checar pacotes oficiais (checkupdates).".to_string(),
            );
        }

        let aur_helper = if Self::command_exists("paru") {
            Some("paru")
        } else if Self::command_exists("yay") {
            Some("yay")
        } else {
            None
        };

        if let Some(helper) = aur_helper {
            match Self::run_with_timeout(helper, &["-Qua"], 25) {
                Ok(output) => {
                    let code = output.status.code().unwrap_or(1);
                    if code == 0 || code == 1 {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for line in stdout.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 4 && parts[2] == "->" {
                                pkgs.push(PackageEntry {
                                    source: format!("AUR ({})", helper),
                                    name: parts[0].to_string(),
                                    current_ver: parts[1].to_string(),
                                    new_ver: parts[3].to_string(),
                                });
                            }
                        }
                    }
                }
                Err(e) => notes.push(e),
            }
        } else {
            notes.push("Nenhum helper AUR (paru/yay) detectado.".to_string());
        }

        (pkgs, notes)
    }

    fn cve_cache_path() -> PathBuf {
        let base = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        base.join(".cache/arch-auditor/cves.cache")
    }

    fn sanitize_field(s: &str) -> String {
        s.replace('\t', " ").replace(['\r', '\n'], " ")
    }

    fn read_cve_cache(allow_expired: bool) -> Option<CveResult> {
        let path = Self::cve_cache_path();
        let content = fs::read_to_string(&path).ok()?;
        let mut lines = content.lines();
        let ts: u64 = lines.next()?.trim().parse().ok()?;
        let now = Self::now_unix();
        let age = now.saturating_sub(ts);

        if !allow_expired && age > CVE_CACHE_TTL_SECS {
            return None;
        }

        let mut entries = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 5 {
                entries.push(CveVulnerabilityEntry {
                    package: cols[0].to_string(),
                    severity: cols[1].to_string(),
                    status: cols[2].to_string(),
                    fixed_ver: cols[3].to_string(),
                    cves: cols[4].to_string(),
                    detail: cols.get(5).unwrap_or(&"").to_string(),
                });
            }
        }

        let msg = if age <= CVE_CACHE_TTL_SECS {
            format!(
                "Cache local válido ({}s / TTL {}s) — {}",
                age,
                CVE_CACHE_TTL_SECS,
                path.display()
            )
        } else {
            format!(
                "Exibindo cache expirado ({}s atrás) por falha ou ausência de rede/arch-audit.",
                age
            )
        };

        Some(CveResult {
            entries,
            note: Some(msg),
            from_cache: true,
        })
    }

    fn write_cve_cache(entries: &[CveVulnerabilityEntry], ts: u64) {
        let path = Self::cve_cache_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut buf = format!("{}\n", ts);
        for e in entries {
            buf.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\n",
                Self::sanitize_field(&e.package),
                Self::sanitize_field(&e.severity),
                Self::sanitize_field(&e.status),
                Self::sanitize_field(&e.fixed_ver),
                Self::sanitize_field(&e.cves),
                Self::sanitize_field(&e.detail),
            ));
        }
        let _ = fs::write(&path, buf);
    }

    fn clean_pkg_name(raw: &str) -> String {
        raw.split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches(':')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
            .collect()
    }

    fn parse_arch_audit_line(line: &str) -> Option<CveVulnerabilityEntry> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let pkg = Self::clean_pkg_name(trimmed);
        if pkg.is_empty() {
            return None;
        }

        let cves: Vec<String> = trimmed
            .split_whitespace()
            .filter_map(|t| {
                let clean = t.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
                if clean.starts_with("CVE-") && clean.len() > 8 {
                    Some(clean.to_uppercase())
                } else {
                    None
                }
            })
            .collect();

        let lower = trimmed.to_lowercase();
        let severity = if lower.contains("high severity")
            || lower.contains("high risk")
            || lower.contains("critical")
            || lower.contains("(high)")
        {
            "High"
        } else if lower.contains("medium severity")
            || lower.contains("medium risk")
            || lower.contains("(medium)")
        {
            "Medium"
        } else if lower.contains("low severity")
            || lower.contains("low risk")
            || lower.contains("(low)")
        {
            "Low"
        } else if !cves.is_empty() {
            "Medium"
        } else {
            "Unknown"
        }
        .to_string();

        let (status, fixed_ver) = if lower.contains("not fixed")
            || lower.contains("unfixed")
            || lower.contains("vulnerable")
        {
            ("Vulnerável".to_string(), "Sem correção".to_string())
        } else if lower.contains("fixed") {
            let ver = trimmed
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .find(|w| w[0].eq_ignore_ascii_case("fixed"))
                .map(|w| w[1].trim_matches(|c: char| matches!(c, ',' | ';' | ')' | '.')))
                .filter(|s| !s.is_empty())
                .unwrap_or("Atualizar pacote")
                .to_string();
            ("Correção disponível".to_string(), ver)
        } else {
            ("Reportado".to_string(), "Ver advisory".to_string())
        };

        let cve_str = if !cves.is_empty() {
            cves.join(", ")
        } else {
            format!("Advisory de {}", pkg)
        };

        Some(CveVulnerabilityEntry {
            package: pkg,
            severity,
            status,
            fixed_ver,
            cves: cve_str,
            detail: trimmed.to_string(),
        })
    }

    fn advisory_url_from_query(query: &str, fallback_pkg: &str) -> String {
        for token in query.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
            let upper = token.trim().to_uppercase();
            if (upper.starts_with("CVE-") && upper.len() > 8)
                || (upper.starts_with("ASA-") && upper.len() > 4)
                || (upper.starts_with("AVG-") && upper.len() > 4)
            {
                return format!("https://security.archlinux.org/{}", upper);
            }
        }

        let pkg = Self::clean_pkg_name(fallback_pkg);
        if !pkg.is_empty() && !pkg.eq_ignore_ascii_case("advisory") {
            return format!("https://security.archlinux.org/advisory?q={}", pkg);
        }

        "https://security.archlinux.org/advisory".to_string()
    }

    fn collect_cve_vulnerabilities(force_refresh: bool) -> CveResult {
        if !force_refresh {
            if let Some(cached) = Self::read_cve_cache(false) {
                return cached;
            }
        }

        if !Self::command_exists("arch-audit") {
            if let Some(mut stale) = Self::read_cve_cache(true) {
                stale.note = Some(
                    "arch-audit não encontrado; exibindo último cache local disponível."
                        .to_string(),
                );
                return stale;
            }
            return CveResult {
                entries: Vec::new(),
                note: Some(
                    "Utilitário 'arch-audit' não encontrado. Instale com: sudo pacman -S arch-audit"
                        .to_string(),
                ),
                from_cache: false,
            };
        }

        match Self::run_with_timeout("arch-audit", &[], 30) {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

                let mut entries = Vec::new();
                for line in stdout.lines() {
                    if let Some(item) = Self::parse_arch_audit_line(line) {
                        entries.push(item);
                    }
                }

                if entries.is_empty() && !output.status.success() {
                    if let Some(mut stale) = Self::read_cve_cache(true) {
                        stale.note = Some(format!(
                            "Falha ao consultar arch-audit ({}) — exibindo cache local.",
                            if stderr.is_empty() {
                                "verifique rede/security.archlinux.org"
                            } else {
                                &stderr
                            }
                        ));
                        return stale;
                    }
                    return CveResult {
                        entries: Vec::new(),
                        note: Some(format!(
                            "Falha ao executar arch-audit ({})",
                            if stderr.is_empty() {
                                "sem saída ou sem conexão com security.archlinux.org"
                            } else {
                                &stderr
                            }
                        )),
                        from_cache: false,
                    };
                }

                entries.sort_by(|a, b| {
                    let rank = |s: &str| match s.to_lowercase().as_str() {
                        "high" | "critical" => 0,
                        "medium" => 1,
                        "low" => 2,
                        _ => 3,
                    };
                    rank(&a.severity)
                        .cmp(&rank(&b.severity))
                        .then(a.package.to_lowercase().cmp(&b.package.to_lowercase()))
                });

                let now = Self::now_unix();
                Self::write_cve_cache(&entries, now);

                let note = if entries.is_empty() {
                    Some(
                        "Nenhuma vulnerabilidade CVE reportada pelo arch-audit (cache salvo)."
                            .to_string(),
                    )
                } else {
                    Some(format!(
                        "{} registro(s) via arch-audit — cache em ~/.cache/arch-auditor/cves.cache (TTL {}s).",
                        entries.len(),
                        CVE_CACHE_TTL_SECS
                    ))
                };

                CveResult {
                    entries,
                    note,
                    from_cache: false,
                }
            }
            Err(err) => {
                if let Some(mut stale) = Self::read_cve_cache(true) {
                    stale.note = Some(format!("{} — exibindo cache local.", err));
                    return stale;
                }
                CveResult {
                    entries: Vec::new(),
                    note: Some(err),
                    from_cache: false,
                }
            }
        }
    }

    // fn advisory_url_from_query(query: &str, fallback_pkg: &str) -> String {
    //     for token in query.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
    //         let upper = token.trim().to_uppercase();
    //         if upper.starts_with("CVE-") && upper.len() > 8 {
    //             return format!("https://security.archlinux.org/{}", upper);
    //         }
    //     }
    //     let pkg = query.trim();
    //     if !pkg.is_empty() {
    //         format!("https://security.archlinux.org/packages/{}/", pkg)
    //     } else {
    //         format!("https://security.archlinux.org/packages/{}/", fallback_pkg)
    //     }
    // }

    fn advisory_url(entry: &CveVulnerabilityEntry) -> String {
        Self::advisory_url_from_query(&entry.cves, &entry.package)
    }

    fn open_in_browser(url: &str) -> Result<(), String> {
        if !Self::command_exists("xdg-open") {
            return Err("Comando 'xdg-open' não encontrado (instale 'xdg-utils').".to_string());
        }
        Command::new("xdg-open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("Falha ao abrir '{}' com xdg-open: {}", url, e))
    }

    fn collect_wms_and_des() -> (Vec<DesktopEntryItem>, String) {
        let current_desktop = env::var("XDG_CURRENT_DESKTOP")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                env::var("DESKTOP_SESSION")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            })
            .unwrap_or_else(|| "Desconhecida / TTY".to_string());

        let session_type = env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "N/D".to_string());
        let summary = format!("Sessão Atual: {} ({})", current_desktop, session_type);
        let active_lower = current_desktop.to_lowercase();

        let mut map: HashMap<String, DesktopEntryItem> = HashMap::new();

        let session_dirs = [
            ("/usr/share/wayland-sessions", "Wayland"),
            ("/usr/share/xsessions", "X11"),
        ];

        for (dir_str, s_type) in session_dirs {
            let dir = Path::new(dir_str);
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                    continue;
                }
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("sessao")
                    .to_string();

                let mut name = stem.clone();
                let mut exec_bin = "-".to_string();

                if let Ok(content) = fs::read_to_string(&path) {
                    for line in content.lines() {
                        if let Some(val) = line.strip_prefix("Name=") {
                            let trimmed = val.trim();
                            if !trimmed.is_empty() {
                                name = trimmed.to_string();
                            }
                        } else if let Some(val) = line.strip_prefix("Exec=") {
                            if let Some(first_token) = val.split_whitespace().next() {
                                exec_bin = first_token.to_string();
                            }
                        }
                    }
                }

                let active = name.to_lowercase().contains(&active_lower)
                    || stem.to_lowercase().contains(&active_lower);

                let key = format!("{}-{}", name.to_lowercase(), s_type);
                map.insert(
                    key,
                    DesktopEntryItem {
                        name,
                        session_type: s_type.to_string(),
                        binary: exec_bin,
                        active,
                        source_path: path.display().to_string(),
                    },
                );
            }
        }

        let known_bins: [(&str, &str, &str); 20] = [
            ("hyprland", "Hyprland", "Wayland"),
            ("sway", "Sway", "Wayland"),
            ("river", "River", "Wayland"),
            ("wayfire", "Wayfire", "Wayland"),
            ("niri", "Niri", "Wayland"),
            ("labwc", "Labwc", "Wayland"),
            ("i3", "i3wm", "X11"),
            ("bspwm", "bspwm", "X11"),
            ("dwm", "dwm", "X11"),
            ("qtile", "Qtile", "X11/Wayland"),
            ("awesome", "AwesomeWM", "X11"),
            ("openbox", "Openbox", "X11"),
            ("fluxbox", "Fluxbox", "X11"),
            ("xmonad", "XMonad", "X11"),
            ("herbstluftwm", "herbstluftwm", "X11"),
            ("gnome-shell", "GNOME", "Wayland/X11"),
            ("plasmashell", "KDE Plasma", "Wayland/X11"),
            ("xfce4-session", "XFCE", "X11"),
            ("cinnamon", "Cinnamon", "X11"),
            ("lxqt-session", "LXQt", "X11"),
        ];

        for (bin, friendly, s_type) in known_bins {
            if !Self::command_exists(bin) {
                continue;
            }
            let already = map.values().any(|item| {
                item.name.to_lowercase().contains(&friendly.to_lowercase())
                    || item.binary.contains(bin)
            });
            if !already {
                let active =
                    friendly.to_lowercase().contains(&active_lower) || bin.contains(&active_lower);
                map.insert(
                    format!("bin-{}", bin),
                    DesktopEntryItem {
                        name: friendly.to_string(),
                        session_type: s_type.to_string(),
                        binary: format!("/usr/bin/{}", bin),
                        active,
                        source_path: "Binário (/usr/bin)".to_string(),
                    },
                );
            }
        }

        let mut list: Vec<DesktopEntryItem> = map.into_values().collect();
        list.sort_by(|a, b| {
            b.active
                .cmp(&a.active)
                .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        (list, summary)
    }

    fn human_size(bytes: u64) -> String {
        let mut val = bytes as f64;
        for unit in ["B", "KiB", "MiB", "GiB"] {
            if val < 1024.0 {
                return format!("{:.1} {}", val, unit);
            }
            val /= 1024.0;
        }
        format!("{:.1} TiB", val)
    }

    fn collect_appimages() -> Vec<AppImageEntry> {
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
            roots.push(home.join("Applications"));
            roots.push(home.join("Downloads"));
            roots.push(home.join("Desktop"));
            roots.push(home.join(".local/bin"));
        }
        roots.push(PathBuf::from("/opt"));

        let mut results = Vec::new();
        let mut seen_canonical: HashSet<PathBuf> = HashSet::new();

        for root in roots {
            if !root.is_dir() {
                continue;
            }
            Self::walk_appimages(&root, 0, &mut seen_canonical, &mut results);
        }

        results.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        results
    }

    fn walk_appimages(
        dir: &Path,
        depth: usize,
        seen_canonical: &mut HashSet<PathBuf>,
        out: &mut Vec<AppImageEntry>,
    ) {
        if depth > 4 {
            return;
        }
        let Ok(canon) = fs::canonicalize(dir) else {
            return;
        };
        if !seen_canonical.insert(canon) {
            return;
        }

        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }

            if meta.is_dir() {
                let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if !name.starts_with('.') && name != "node_modules" && name != "__pycache__" {
                    Self::walk_appimages(&path, depth + 1, seen_canonical, out);
                }
            } else if meta.is_file() {
                let fname = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if fname.to_lowercase().ends_with(".appimage") {
                    let exec = meta.permissions().mode() & 0o111 != 0;
                    out.push(AppImageEntry {
                        name: fname,
                        size_human: Self::human_size(meta.len()),
                        executable: exec,
                        path: path.display().to_string(),
                    });
                }
            }
        }
    }

    fn make_appimage_executable(file_path: &str) -> Result<String, String> {
        let p = Path::new(file_path);
        let meta = fs::metadata(p).map_err(|e| format!("Falha ao ler '{}': {}", file_path, e))?;
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o755);
        fs::set_permissions(p, perms)
            .map_err(|e| format!("Falha ao aplicar +x em '{}': {}", file_path, e))?;
        Ok(format!(
            "Permissão executável (+x) aplicada em {}",
            file_path
        ))
    }

    fn install_local_appimage(source_str: &str) -> Result<String, String> {
        let trimmed = source_str.trim().trim_matches('"');
        if trimmed.is_empty() {
            return Err("Informe o caminho de um arquivo .AppImage.".to_string());
        }
        let src = Path::new(trimmed);
        if !src.is_file() {
            return Err(format!("Arquivo não encontrado: {}", src.display()));
        }
        let fname = src
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "Nome de arquivo inválido.".to_string())?;
        if !fname.to_lowercase().ends_with(".appimage") {
            return Err("O arquivo selecionado deve terminar com .AppImage.".to_string());
        }

        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "Variável HOME não definida.".to_string())?;
        let dest_dir = home.join("Applications");
        fs::create_dir_all(&dest_dir)
            .map_err(|e| format!("Falha ao criar '{}': {}", dest_dir.display(), e))?;

        let dest_path = dest_dir.join(fname);
        fs::copy(src, &dest_path)
            .map_err(|e| format!("Falha ao copiar para '{}': {}", dest_path.display(), e))?;

        let meta = fs::metadata(&dest_path)
            .map_err(|e| format!("Falha ao ler metadados de '{}': {}", dest_path.display(), e))?;
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o755);
        fs::set_permissions(&dest_path, perms)
            .map_err(|e| format!("Falha ao definir +x em '{}': {}", dest_path.display(), e))?;

        Ok(format!(
            "AppImage instalado em {} (+x habilitado).",
            dest_path.display()
        ))
    }

    fn collect_flatpaks() -> (Vec<FlatpakEntry>, Option<String>) {
        if !Self::command_exists("flatpak") {
            return (
                Vec::new(),
                Some("Flatpak não está instalado neste sistema.".to_string()),
            );
        }

        match Self::run_with_timeout(
            "flatpak",
            &[
                "list",
                "--app",
                "--columns=application,name,version,branch,origin,installation",
            ],
            10,
        ) {
            Ok(output) => {
                if !output.status.success() {
                    let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    return (
                        Vec::new(),
                        Some(format!("Erro ao executar flatpak list: {}", err)),
                    );
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut list = Vec::new();
                for line in stdout.lines() {
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() >= 2 {
                        list.push(FlatpakEntry {
                            app_id: cols[0].trim().to_string(),
                            name: cols[1].trim().to_string(),
                            version: cols
                                .get(2)
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .unwrap_or("-")
                                .to_string(),
                            branch: cols
                                .get(3)
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .unwrap_or("-")
                                .to_string(),
                            origin: cols
                                .get(4)
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .unwrap_or("-")
                                .to_string(),
                            installation: cols
                                .get(5)
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .unwrap_or("-")
                                .to_string(),
                        });
                    }
                }
                if list.is_empty() {
                    (
                        Vec::new(),
                        Some("Nenhum aplicativo Flatpak instalado.".to_string()),
                    )
                } else {
                    (list, None)
                }
            }
            Err(e) => (Vec::new(), Some(e)),
        }
    }

    fn install_flatpak_app(
        app_id_raw: &str,
        remote_raw: &str,
        user_scope: bool,
    ) -> Result<String, String> {
        let app_id = app_id_raw.trim();
        let remote = if remote_raw.trim().is_empty() {
            "flathub"
        } else {
            remote_raw.trim()
        };

        if app_id.is_empty() {
            return Err("Informe um Application ID válido (ex.: org.mozilla.firefox).".to_string());
        }
        if !Self::command_exists("flatpak") {
            return Err(
                "Comando 'flatpak' não encontrado. Instale com: sudo pacman -S flatpak".to_string(),
            );
        }

        let scope_flag = if user_scope { "--user" } else { "--system" };
        let output = Self::run_with_timeout(
            "flatpak",
            &["install", scope_flag, "-y", remote, app_id],
            180,
        )?;

        if output.status.success() {
            Ok(format!(
                "Flatpak '{}' instalado via '{}' ({}).",
                app_id,
                remote,
                if user_scope { "usuário" } else { "sistema" }
            ))
        } else {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let out = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !err.is_empty() { err } else { out };
            Err(format!("Falha ao instalar '{}': {}", app_id, detail))
        }
    }

    fn collect_all(force_cve_refresh: bool) -> AuditSnapshot {
        let (ports, ports_warning) = Self::collect_open_ports();
        let (desktops, session_summary) = Self::collect_wms_and_des();
        let appimages = Self::collect_appimages();
        let (flatpaks, flatpak_note) = Self::collect_flatpaks();
        let (packages, package_notes) = Self::collect_outdated_packages();
        let cve_res = Self::collect_cve_vulnerabilities(force_cve_refresh);

        AuditSnapshot {
            ports,
            ports_warning,
            packages,
            package_notes,
            desktops,
            session_summary,
            appimages,
            flatpaks,
            flatpak_note,
            vulnerabilities: cve_res.entries,
            vulnerability_note: cve_res.note,
            last_updated_unix: Self::now_unix(),
        }
    }

    fn build_summary_markdown(snap: &AuditSnapshot, ts: u64) -> String {
        let mut md = String::new();
        md.push_str("# Resumo de Auditoria — Arch Linux\n\n");
        md.push_str(&format!("- **Timestamp (UNIX):** `{}`\n", ts));
        if !snap.session_summary.is_empty() {
            md.push_str(&format!("- **Sessão:** {}\n", snap.session_summary));
        }

        let external_ports: Vec<&PortEntry> = snap
            .ports
            .iter()
            .filter(|p| p.exposure == Exposure::External)
            .collect();

        md.push_str(&format!(
            "- **Portas Abertas:** {} total | **{} externas (`0.0.0.0` / `[::]`)**\n",
            snap.ports.len(),
            external_ports.len()
        ));
        md.push_str(&format!(
            "- **Pacotes Desatualizados:** {}\n",
            snap.packages.len()
        ));
        md.push_str(&format!(
            "- **Vulnerabilidades (CVEs):** {}\n",
            snap.vulnerabilities.len()
        ));
        md.push_str(&format!(
            "- **WMs / Ambientes Detectados:** {}\n",
            snap.desktops.len()
        ));
        md.push_str(&format!("- **AppImages:** {}\n", snap.appimages.len()));
        md.push_str(&format!("- **Flatpaks:** {}\n\n", snap.flatpaks.len()));

        md.push_str("## 1. Portas Externas em Escuta (0.0.0.0 / [::])\n\n");
        if external_ports.is_empty() {
            md.push_str("Nenhuma porta em `0.0.0.0` ou `[::]` detectada.\n\n");
        } else {
            md.push_str("| Proto | Endereço | Porta | Processo | PID | Estado |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for p in external_ports {
                md.push_str(&format!(
                    "| {} | `{}` | `{}` | {} | {} | {} |\n",
                    p.protocol, p.local_addr, p.port, p.process, p.pid, p.state
                ));
            }
            md.push('\n');
        }

        md.push_str("## 2. Pacotes Desatualizados\n\n");
        if snap.packages.is_empty() {
            md.push_str("Nenhum pacote desatualizado listado.\n\n");
        } else {
            md.push_str("| Origem | Pacote | Versão Atual | Nova Versão |\n");
            md.push_str("| :--- | :--- | :--- | :--- |\n");
            for pkg in &snap.packages {
                md.push_str(&format!(
                    "| {} | `{}` | `{}` | `{}` |\n",
                    pkg.source, pkg.name, pkg.current_ver, pkg.new_ver
                ));
            }
            md.push('\n');
        }

        md.push_str("## 3. Vulnerabilidades Conhecidas (CVEs)\n\n");
        if snap.vulnerabilities.is_empty() {
            md.push_str(
                snap.vulnerability_note
                    .as_deref()
                    .unwrap_or("Nenhuma vulnerabilidade CVE listada.\n"),
            );
            md.push_str("\n\n");
        } else {
            md.push_str("| Pacote | Severidade | Status | Correção | CVEs | Advisory |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for v in &snap.vulnerabilities {
                let url = Self::advisory_url(v);
                md.push_str(&format!(
                    "| `{}` | {} | {} | `{}` | {} | [Link]({}) |\n",
                    v.package, v.severity, v.status, v.fixed_ver, v.cves, url
                ));
            }
            md.push('\n');
        }

        md.push_str("## 4. WMs e Ambientes Gráficos\n\n");
        for d in &snap.desktops {
            let tag = if d.active { " (ATIVA)" } else { "" };
            md.push_str(&format!(
                "- **{}**{} — {} (`{}`)\n",
                d.name, tag, d.session_type, d.binary
            ));
        }
        md.push('\n');

        md.push_str("## 5. AppImages\n\n");
        if snap.appimages.is_empty() {
            md.push_str("Nenhum `.AppImage` encontrado nos diretórios padrão.\n\n");
        } else {
            for app in &snap.appimages {
                let perm = if app.executable { "+x" } else { "sem +x" };
                md.push_str(&format!(
                    "- `{}` ({}, {}) — `{}`\n",
                    app.name, app.size_human, perm, app.path
                ));
            }
            md.push('\n');
        }

        md.push_str("## 6. Flatpaks\n\n");
        if snap.flatpaks.is_empty() {
            md.push_str("Nenhum Flatpak instalado ou `flatpak` indisponível.\n");
        } else {
            for fp in &snap.flatpaks {
                md.push_str(&format!(
                    "- **{}** (`{}`) — v{} [{} / {}]\n",
                    fp.name, fp.app_id, fp.version, fp.origin, fp.installation
                ));
            }
        }

        md
    }

    fn export_summary(snap: &AuditSnapshot) -> Result<PathBuf, String> {
        let ts = Self::now_unix();
        let base_dir = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let out_path = base_dir.join(format!("arch-audit-resumo-{}.md", ts));
        let content = Self::build_summary_markdown(snap, ts);
        fs::write(&out_path, content)
            .map_err(|e| format!("Falha ao salvar resumo em '{}': {}", out_path.display(), e))?;
        Ok(out_path)
    }
}

unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

struct ArchAuditorApp {
    data: AuditSnapshot,
    active_tab: ActiveTab,
    filter: String,
    only_external_ports: bool,
    only_high_cve: bool,
    cve_lookup_input: String,
    appimage_source_input: String,
    flatpak_id_input: String,
    flatpak_remote_input: String,
    flatpak_user_scope: bool,
    loading_full: bool,
    loading_pkg_cache: bool,
    loading_cves: bool,
    loading_action: bool,
    status_message: Option<(String, bool)>,
    rx: Option<Receiver<WorkerEvent>>,
}

impl ArchAuditorApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(15, 20, 25);
        visuals.window_fill = Color32::from_rgb(15, 20, 25);
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(22, 27, 34);
        cc.egui_ctx.set_visuals(visuals);

        let mut style = (*cc.egui_ctx.global_style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        cc.egui_ctx.set_global_style(style);

        let mut app = Self {
            data: AuditSnapshot::default(),
            active_tab: ActiveTab::Ports,
            filter: String::new(),
            only_external_ports: false,
            only_high_cve: false,
            cve_lookup_input: String::new(),
            appimage_source_input: String::new(),
            flatpak_id_input: String::new(),
            flatpak_remote_input: "flathub".to_string(),
            flatpak_user_scope: true,
            loading_full: false,
            loading_pkg_cache: false,
            loading_cves: false,
            loading_action: false,
            status_message: None,
            rx: None,
        };
        app.start_full_refresh(false);
        app
    }

    fn ensure_channel(&mut self) -> mpsc::Sender<WorkerEvent> {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        tx
    }

    fn start_full_refresh(&mut self, force_cve: bool) {
        let tx = self.ensure_channel();
        self.loading_full = true;
        self.status_message = Some((
            "Executando auditoria completa do sistema...".to_string(),
            false,
        ));

        thread::spawn(move || {
            let snap = ArchCollectors::collect_all(force_cve);
            let _ = tx.send(WorkerEvent::FullSnapshot(snap));
        });
    }

    fn start_pkg_cache_refresh(&mut self) {
        if self.loading_pkg_cache {
            return;
        }
        let tx = self.ensure_channel();
        self.loading_pkg_cache = true;
        self.status_message = Some((
            "Atualizando cache de pacotes desatualizados (checkupdates / AUR)...".to_string(),
            false,
        ));

        thread::spawn(move || {
            let (packages, package_notes) = ArchCollectors::collect_outdated_packages();
            let _ = tx.send(WorkerEvent::PackagesCacheUpdated {
                packages,
                package_notes,
                updated_unix: ArchCollectors::now_unix(),
            });
        });
    }

    fn start_cve_refresh(&mut self, force_refresh: bool) {
        if self.loading_cves {
            return;
        }
        let tx = self.ensure_channel();
        self.loading_cves = true;
        self.status_message = Some((
            "Atualizando vulnerabilidades CVE via arch-audit...".to_string(),
            false,
        ));

        thread::spawn(move || {
            let result = ArchCollectors::collect_cve_vulnerabilities(force_refresh);
            let _ = tx.send(WorkerEvent::CvesUpdated {
                result,
                updated_unix: ArchCollectors::now_unix(),
            });
        });
    }

    fn start_install_appimage(&mut self, source_path: String) {
        let tx = self.ensure_channel();
        self.loading_action = true;
        self.status_message = Some((
            "Instalando AppImage em ~/Applications...".to_string(),
            false,
        ));

        thread::spawn(
            move || match ArchCollectors::install_local_appimage(&source_path) {
                Ok(msg) => {
                    let _ = tx.send(WorkerEvent::ActionResult {
                        message: msg,
                        is_error: false,
                    });
                    let list = ArchCollectors::collect_appimages();
                    let _ = tx.send(WorkerEvent::AppImagesUpdated(list));
                }
                Err(err) => {
                    let _ = tx.send(WorkerEvent::ActionResult {
                        message: err,
                        is_error: true,
                    });
                }
            },
        );
    }

    fn start_chmod_appimage(&mut self, file_path: String) {
        let tx = self.ensure_channel();
        self.loading_action = true;
        self.status_message = Some((format!("Aplicando +x em {}...", file_path), false));

        thread::spawn(
            move || match ArchCollectors::make_appimage_executable(&file_path) {
                Ok(msg) => {
                    let _ = tx.send(WorkerEvent::ActionResult {
                        message: msg,
                        is_error: false,
                    });
                    let list = ArchCollectors::collect_appimages();
                    let _ = tx.send(WorkerEvent::AppImagesUpdated(list));
                }
                Err(err) => {
                    let _ = tx.send(WorkerEvent::ActionResult {
                        message: err,
                        is_error: true,
                    });
                }
            },
        );
    }

    fn start_install_flatpak(&mut self, app_id: String, remote: String, user_scope: bool) {
        let tx = self.ensure_channel();
        self.loading_action = true;
        self.status_message = Some((
            format!(
                "Instalando Flatpak '{}' via '{}'...",
                app_id.trim(),
                remote.trim()
            ),
            false,
        ));

        thread::spawn(move || {
            match ArchCollectors::install_flatpak_app(&app_id, &remote, user_scope) {
                Ok(msg) => {
                    let _ = tx.send(WorkerEvent::ActionResult {
                        message: msg,
                        is_error: false,
                    });
                    let (flatpaks, note) = ArchCollectors::collect_flatpaks();
                    let _ = tx.send(WorkerEvent::FlatpaksUpdated { flatpaks, note });
                }
                Err(err) => {
                    let _ = tx.send(WorkerEvent::ActionResult {
                        message: err,
                        is_error: true,
                    });
                }
            }
        });
    }

    fn trigger_export(&mut self, ctx: &egui::Context) {
        let ts = ArchCollectors::now_unix();
        let md = ArchCollectors::build_summary_markdown(&self.data, ts);
        ctx.copy_text(md);

        match ArchCollectors::export_summary(&self.data) {
            Ok(path) => {
                self.status_message = Some((
                    format!(
                        "Resumo salvo em {} e copiado para a área de transferência.",
                        path.display()
                    ),
                    false,
                ));
            }
            Err(err) => {
                self.status_message = Some((err, true));
            }
        }
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(WorkerEvent::FullSnapshot(snap)) => {
                    self.data = snap;
                    self.loading_full = false;
                    self.loading_pkg_cache = false;
                    self.loading_cves = false;
                    self.loading_action = false;
                    self.rx = None;
                    self.status_message = Some(("Auditoria concluída.".to_string(), false));
                }
                Ok(WorkerEvent::PackagesCacheUpdated {
                    packages,
                    package_notes,
                    updated_unix,
                }) => {
                    self.data.packages = packages;
                    self.data.package_notes = package_notes;
                    self.data.last_updated_unix = updated_unix;
                    self.loading_pkg_cache = false;
                    self.rx = None;
                    self.status_message = Some((
                        format!(
                            "Cache de pacotes atualizado ({} pendente(s)).",
                            self.data.packages.len()
                        ),
                        false,
                    ));
                }
                Ok(WorkerEvent::CvesUpdated {
                    result,
                    updated_unix,
                }) => {
                    self.data.vulnerabilities = result.entries;
                    self.data.vulnerability_note = result.note;
                    self.data.last_updated_unix = updated_unix;
                    self.loading_cves = false;
                    self.rx = None;
                    self.status_message = Some((
                        format!(
                            "CVEs atualizadas ({} registro(s){}).",
                            self.data.vulnerabilities.len(),
                            if result.from_cache { ", cache" } else { "" }
                        ),
                        false,
                    ));
                }
                Ok(WorkerEvent::AppImagesUpdated(list)) => {
                    self.data.appimages = list;
                    self.loading_action = false;
                    self.rx = None;
                }
                Ok(WorkerEvent::FlatpaksUpdated { flatpaks, note }) => {
                    self.data.flatpaks = flatpaks;
                    self.data.flatpak_note = note;
                    self.loading_action = false;
                    self.rx = None;
                }
                Ok(WorkerEvent::ActionResult { message, is_error }) => {
                    self.status_message = Some((message, is_error));
                    if is_error {
                        self.loading_action = false;
                        self.rx = None;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if self.loading_full
                        || self.loading_pkg_cache
                        || self.loading_cves
                        || self.loading_action
                    {
                        ctx.request_repaint_after(Duration::from_millis(120));
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.loading_full = false;
                    self.loading_pkg_cache = false;
                    self.loading_cves = false;
                    self.loading_action = false;
                    self.rx = None;
                }
            }
        }
    }

    fn handle_shortcuts(&mut self, ui: &mut egui::Ui, filter_id: egui::Id) {
        let ctx = ui.ctx();

        ctx.input(|i| {
            if i.modifiers.contains(Modifiers::CTRL) && i.key_pressed(Key::F) {
                ctx.memory_mut(|m| m.request_focus(filter_id));
            }
            if i.modifiers.contains(Modifiers::CTRL) && i.key_pressed(Key::U) {
                self.start_pkg_cache_refresh();
            }
            if i.modifiers.contains(Modifiers::CTRL)
                && i.modifiers.contains(Modifiers::SHIFT)
                && i.key_pressed(Key::C)
            {
                self.start_cve_refresh(true);
            }
            if i.modifiers.contains(Modifiers::CTRL) && i.key_pressed(Key::E) {
                self.trigger_export(ctx);
            }
            if i.key_pressed(Key::Escape) {
                self.filter.clear();
            }
        });
    }

    fn matches_filter(&self, haystack: &str) -> bool {
        let q = self.filter.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        haystack.to_lowercase().contains(&q)
    }

    fn render_metric_card(
        &mut self,
        ui: &mut egui::Ui,
        title: &str,
        value: usize,
        accent: Color32,
        target_tab: ActiveTab,
    ) {
        let selected = self.active_tab == target_tab;
        let fill = if selected {
            Color32::from_rgb(28, 38, 50)
        } else {
            Color32::from_rgb(22, 27, 34)
        };
        let stroke = if selected {
            egui::Stroke::new(1.5, accent)
        } else {
            egui::Stroke::new(1.0, Color32::from_rgb(48, 54, 61))
        };

        let frame = egui::Frame::NONE
            .fill(fill)
            .stroke(stroke)
            //.rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::symmetric(10, 5));

        let resp = frame.show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(title)
                        .size(11.0)
                        .color(Color32::from_rgb(139, 148, 158)),
                );
                ui.label(
                    RichText::new(value.to_string())
                        .size(15.0)
                        .strong()
                        .color(accent),
                );
            });
        });

        if resp.response.interact(egui::Sense::click()).clicked() {
            self.active_tab = target_tab;
        }
    }

    fn render_ports_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.only_external_ports,
                RichText::new("Mostrar apenas binds externos (0.0.0.0 / [::])").strong(),
            );
        });

        if let Some(warn) = &self.data.ports_warning {
            ui.colored_label(Color32::from_rgb(210, 153, 34), format!("⚠ {}", warn));
        }

        ui.add_space(6.0);

        if self.data.ports.is_empty() {
            ui.label(
                RichText::new("Nenhuma porta em escuta encontrada para o filtro atual.")
                    .color(Color32::from_rgb(139, 148, 158)),
            );
            return;
        }

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("ports_grid")
                .striped(true)
                .spacing([14.0, 6.0])
                .show(ui, |ui| {
                    for header in [
                        "Exposição",
                        "Proto",
                        "Endereço Local",
                        "Porta",
                        "Processo",
                        "PID",
                        "Estado",
                    ] {
                        ui.strong(header);
                    }
                    ui.end_row();

                    for p in &self.data.ports {
                        if self.only_external_ports && p.exposure != Exposure::External {
                            continue;
                        }
                        let row_blob = format!(
                            "{} {} {} {} {}",
                            p.protocol, p.local_addr, p.port, p.process, p.pid
                        );
                        if !self.matches_filter(&row_blob) {
                            continue;
                        }

                        let (badge_txt, badge_color, addr_color) = match p.exposure {
                            Exposure::External => (
                                "⚠ EXTERNA (0.0.0.0/[::])",
                                Color32::from_rgb(255, 123, 114),
                                Color32::from_rgb(255, 166, 87),
                            ),
                            Exposure::Local => (
                                "● LOCAL",
                                Color32::from_rgb(63, 185, 80),
                                Color32::from_rgb(139, 148, 158),
                            ),
                            Exposure::Other => (
                                "◈ INTERFACE",
                                Color32::from_rgb(121, 192, 255),
                                Color32::from_rgb(121, 192, 255),
                            ),
                        };

                        ui.label(RichText::new(badge_txt).color(badge_color).strong());
                        ui.label(&p.protocol);
                        ui.label(RichText::new(&p.local_addr).color(addr_color).monospace());
                        ui.label(
                            RichText::new(&p.port)
                                .color(badge_color)
                                .strong()
                                .monospace(),
                        );
                        ui.label(RichText::new(&p.process).strong());
                        ui.label(RichText::new(&p.pid).monospace());
                        ui.label(&p.state);
                        ui.end_row();
                    }
                });
        });
    }

    fn render_packages_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.loading_pkg_cache && !self.loading_full,
                    egui::Button::new("📦 Atualizar Cache de Pacotes (Ctrl+U)"),
                )
                .clicked()
            {
                self.start_pkg_cache_refresh();
            }
            if self.loading_pkg_cache {
                ui.spinner();
                ui.label("Consultando checkupdates / AUR...");
            }
        });

        ui.add_space(4.0);

        if self.data.packages.is_empty() {
            ui.label(
                RichText::new("Nenhum pacote desatualizado encontrado ou lista vazia.")
                    .color(Color32::from_rgb(63, 185, 80)),
            );
        } else {
            ui.label(
                RichText::new(format!(
                    "{} pacote(s) desatualizado(s).",
                    self.data.packages.len()
                ))
                .color(Color32::from_rgb(210, 153, 34))
                .strong(),
            );
        }

        for note in &self.data.package_notes {
            ui.label(RichText::new(format!("• {}", note)).color(Color32::from_rgb(139, 148, 158)));
        }

        ui.add_space(6.0);

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("packages_grid")
                .striped(true)
                .spacing([14.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Origem", "Pacote", "Versão Atual", "Nova Versão"] {
                        ui.strong(h);
                    }
                    ui.end_row();

                    for pkg in &self.data.packages {
                        let blob = format!(
                            "{} {} {} {}",
                            pkg.source, pkg.name, pkg.current_ver, pkg.new_ver
                        );
                        if !self.matches_filter(&blob) {
                            continue;
                        }
                        let src_color = if pkg.source == "Oficial" {
                            Color32::from_rgb(23, 147, 209)
                        } else {
                            Color32::from_rgb(210, 168, 255)
                        };
                        ui.label(RichText::new(&pkg.source).color(src_color).strong());
                        ui.label(RichText::new(&pkg.name).strong().monospace());
                        ui.label(RichText::new(&pkg.current_ver).monospace());
                        ui.label(
                            RichText::new(&pkg.new_ver)
                                .color(Color32::from_rgb(63, 185, 80))
                                .strong()
                                .monospace(),
                        );
                        ui.end_row();
                    }
                });
        });
    }

    fn render_vulnerabilities_tab(&mut self, ui: &mut egui::Ui) {
        let mut url_to_open: Option<String> = None;

        let quick_frame = egui::Frame::NONE
            .fill(Color32::from_rgb(22, 27, 34))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(48, 54, 61)))
            //.rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::same(10));

        quick_frame.show(ui, |ui| {
            ui.strong("Abrir CVE ou Pacote diretamente no security.archlinux.org");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.cve_lookup_input)
                        .hint_text("Ex.: CVE-2024-3094 ou openssl")
                        .desired_width(240.0),
                );
                if ui.button("↗ Abrir no Navegador").clicked() {
                    let q = self.cve_lookup_input.trim();
                    if q.is_empty() {
                        self.status_message = Some((
                            "Digite um CVE (ex.: CVE-2024-3094) ou nome de pacote.".to_string(),
                            true,
                        ));
                    } else {
                        url_to_open = Some(ArchCollectors::advisory_url_from_query(q, q));
                    }
                }
                if ui
                    .small_button("Exemplo CVE")
                    .on_hover_text("Preenche CVE-2024-3094 para teste")
                    .clicked()
                {
                    self.cve_lookup_input = "CVE-2024-3094".to_string();
                }
            });
        });

        ui.add_space(6.0);

        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.loading_cves && !self.loading_full,
                    egui::Button::new("🛡 Atualizar CVEs (Ctrl+Shift+C)"),
                )
                .clicked()
            {
                self.start_cve_refresh(true);
            }
            if self.loading_cves {
                ui.spinner();
                ui.label("Consultando arch-audit...");
            }
            ui.checkbox(
                &mut self.only_high_cve,
                RichText::new("Apenas High / Critical").strong(),
            );
        });

        if let Some(note) = &self.data.vulnerability_note {
            ui.colored_label(Color32::from_rgb(139, 148, 158), format!("ℹ {}", note));
        }

        ui.add_space(6.0);

        if self.data.vulnerabilities.is_empty() {
            ui.label(
                RichText::new(
                    "Nenhuma vulnerabilidade CVE listada no momento. Use o campo acima para abrir um CVE/pacote diretamente ou clique em 'Atualizar CVEs'.",
                )
                .color(Color32::from_rgb(139, 148, 158)),
            );
        } else {
            egui::ScrollArea::both().show(ui, |ui| {
                egui::Grid::new("cves_grid")
                    .striped(true)
                    .spacing([14.0, 6.0])
                    .show(ui, |ui| {
                        for h in [
                            "Severidade",
                            "Pacote",
                            "Status",
                            "Correção",
                            "CVEs / Detalhe",
                            "Advisory",
                        ] {
                            ui.strong(h);
                        }
                        ui.end_row();

                        for v in &self.data.vulnerabilities {
                            let sev_low = v.severity.to_lowercase();
                            if self.only_high_cve && !(sev_low == "high" || sev_low == "critical") {
                                continue;
                            }
                            let blob = format!(
                                "{} {} {} {} {} {}",
                                v.package, v.severity, v.status, v.fixed_ver, v.cves, v.detail
                            );
                            if !self.matches_filter(&blob) {
                                continue;
                            }

                            let sev_color = match sev_low.as_str() {
                                "high" | "critical" => Color32::from_rgb(255, 123, 114),
                                "medium" => Color32::from_rgb(210, 153, 34),
                                "low" => Color32::from_rgb(121, 192, 255),
                                _ => Color32::from_rgb(139, 148, 158),
                            };

                            ui.label(RichText::new(&v.severity).color(sev_color).strong());
                            ui.label(RichText::new(&v.package).strong().monospace());
                            ui.label(&v.status);
                            ui.label(RichText::new(&v.fixed_ver).monospace());
                            ui.label(RichText::new(&v.cves).color(sev_color).monospace())
                                .on_hover_text(&v.detail);

                            let url = ArchCollectors::advisory_url(v);
                            if ui
                                .button("↗ Abrir Advisory")
                                .on_hover_text(format!("Abrir {} via xdg-open", url))
                                .clicked()
                            {
                                url_to_open = Some(url);
                            }
                            ui.end_row();
                        }
                    });
            });
        }

        if let Some(url) = url_to_open {
            match ArchCollectors::open_in_browser(&url) {
                Ok(()) => {
                    self.status_message = Some((format!("Abrindo {} via xdg-open...", url), false));
                }
                Err(err) => {
                    self.status_message = Some((err, true));
                }
            }
        }
    }

    fn render_desktops_tab(&self, ui: &mut egui::Ui) {
        if !self.data.session_summary.is_empty() {
            ui.label(
                RichText::new(&self.data.session_summary)
                    .color(Color32::from_rgb(23, 147, 209))
                    .strong(),
            );
            ui.add_space(6.0);
        }

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("desktops_grid")
                .striped(true)
                .spacing([14.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Status", "Ambiente / WM", "Sessão", "Executável", "Origem"] {
                        ui.strong(h);
                    }
                    ui.end_row();

                    for d in &self.data.desktops {
                        let blob = format!(
                            "{} {} {} {}",
                            d.name, d.session_type, d.binary, d.source_path
                        );
                        if !self.matches_filter(&blob) {
                            continue;
                        }

                        if d.active {
                            ui.label(
                                RichText::new("★ ATIVA")
                                    .color(Color32::from_rgb(63, 185, 80))
                                    .strong(),
                            );
                        } else {
                            ui.label(
                                RichText::new("Instalado").color(Color32::from_rgb(139, 148, 158)),
                            );
                        }
                        ui.label(RichText::new(&d.name).strong());
                        ui.label(&d.session_type);
                        ui.label(RichText::new(&d.binary).monospace());
                        ui.label(
                            RichText::new(&d.source_path).color(Color32::from_rgb(139, 148, 158)),
                        );
                        ui.end_row();
                    }
                });
        });
    }

    fn render_appimages_tab(&mut self, ui: &mut egui::Ui) {
        let frame = egui::Frame::NONE
            .fill(Color32::from_rgb(22, 27, 34))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(48, 54, 61)))
            //.rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::same(10));

        frame.show(ui, |ui| {
            ui.strong("Instalar AppImage local em ~/Applications (+x)");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.appimage_source_input)
                        .hint_text("/caminho/para/aplicativo.AppImage")
                        .desired_width(360.0),
                );
                if ui
                    .add_enabled(
                        !self.loading_action && !self.loading_full,
                        egui::Button::new("⬇ Instalar AppImage"),
                    )
                    .clicked()
                {
                    let src = self.appimage_source_input.clone();
                    self.start_install_appimage(src);
                }
            });
        });

        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Diretórios monitorados: ~/Applications, ~/Downloads, ~/Desktop, ~/.local/bin e /opt",
            )
            .color(Color32::from_rgb(139, 148, 158)),
        );
        ui.add_space(6.0);

        let mut chmod_target: Option<String> = None;

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("appimages_grid")
                .striped(true)
                .spacing([14.0, 6.0])
                .show(ui, |ui| {
                    for h in [
                        "Permissão (+x)",
                        "Arquivo",
                        "Tamanho",
                        "Caminho Completo",
                        "Ação",
                    ] {
                        ui.strong(h);
                    }
                    ui.end_row();

                    for app in &self.data.appimages {
                        let blob = format!("{} {}", app.name, app.path);
                        if !self.matches_filter(&blob) {
                            continue;
                        }
                        if app.executable {
                            ui.label(
                                RichText::new("✔ Executável (+x)")
                                    .color(Color32::from_rgb(63, 185, 80))
                                    .strong(),
                            );
                        } else {
                            ui.label(
                                RichText::new("✖ Sem +x")
                                    .color(Color32::from_rgb(210, 153, 34))
                                    .strong(),
                            );
                        }
                        ui.label(RichText::new(&app.name).strong());
                        ui.label(RichText::new(&app.size_human).monospace());
                        ui.label(RichText::new(&app.path).monospace());

                        if !app.executable {
                            if ui.small_button("Habilitar +x").clicked() {
                                chmod_target = Some(app.path.clone());
                            }
                        } else {
                            ui.label(
                                RichText::new("Pronto").color(Color32::from_rgb(139, 148, 158)),
                            );
                        }
                        ui.end_row();
                    }
                });
        });

        if let Some(p) = chmod_target {
            self.start_chmod_appimage(p);
        }
    }

    fn render_flatpaks_tab(&mut self, ui: &mut egui::Ui) {
        let frame = egui::Frame::NONE
            .fill(Color32::from_rgb(22, 27, 34))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(48, 54, 61)))
            //.rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::same(10));

        frame.show(ui, |ui| {
            ui.strong("Instalar aplicativo Flatpak");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.flatpak_id_input)
                        .hint_text("Application ID (ex.: org.mozilla.firefox)")
                        .desired_width(260.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.flatpak_remote_input)
                        .hint_text("Remote (ex.: flathub)")
                        .desired_width(130.0),
                );
                ui.checkbox(&mut self.flatpak_user_scope, "Escopo --user");
                if ui
                    .add_enabled(
                        !self.loading_action && !self.loading_full,
                        egui::Button::new("📦 Instalar Flatpak"),
                    )
                    .clicked()
                {
                    let app_id = self.flatpak_id_input.clone();
                    let remote = self.flatpak_remote_input.clone();
                    let scope = self.flatpak_user_scope;
                    self.start_install_flatpak(app_id, remote, scope);
                }
            });
        });

        ui.add_space(6.0);

        if let Some(note) = &self.data.flatpak_note {
            ui.label(RichText::new(note).color(Color32::from_rgb(139, 148, 158)));
        } else {
            ui.label(
                RichText::new(format!(
                    "{} aplicativo(s) Flatpak instalado(s).",
                    self.data.flatpaks.len()
                ))
                .strong(),
            );
        }

        ui.add_space(6.0);

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("flatpaks_grid")
                .striped(true)
                .spacing([14.0, 6.0])
                .show(ui, |ui| {
                    for h in [
                        "Nome",
                        "Application ID",
                        "Versão",
                        "Branch",
                        "Repositório",
                        "Escopo",
                    ] {
                        ui.strong(h);
                    }
                    ui.end_row();

                    for fp in &self.data.flatpaks {
                        let blob = format!(
                            "{} {} {} {}",
                            fp.name, fp.app_id, fp.origin, fp.installation
                        );
                        if !self.matches_filter(&blob) {
                            continue;
                        }
                        ui.label(RichText::new(&fp.name).strong());
                        ui.label(RichText::new(&fp.app_id).monospace());
                        ui.label(RichText::new(&fp.version).monospace());
                        ui.label(&fp.branch);
                        ui.label(&fp.origin);
                        ui.label(&fp.installation);
                        ui.end_row();
                    }
                });
        });
    }
}

impl eframe::App for ArchAuditorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_worker(ui.ctx());
        let filter_id = egui::Id::unique("search_filter_input");
        self.handle_shortcuts(ui, filter_id);

        let external_count = self
            .data
            .ports
            .iter()
            .filter(|p| p.exposure == Exposure::External)
            .count();
        let cve_count = self.data.vulnerabilities.len();
        let pkg_count = self.data.packages.len();
        let wm_count = self.data.desktops.len();
        let app_count = self.data.appimages.len();
        let fp_count = self.data.flatpaks.len();
        let any_busy =
            self.loading_full || self.loading_pkg_cache || self.loading_cves || self.loading_action;

        egui::Panel::top("top_panel").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("󰣇 ARCH VISUAL AUDITOR")
                        .color(Color32::from_rgb(23, 147, 209))
                        .strong()
                        .size(16.0),
                );
                ui.add_space(8.0);

                let exp_color = if external_count > 0 {
                    Color32::from_rgb(255, 123, 114)
                } else {
                    Color32::from_rgb(63, 185, 80)
                };
                self.render_metric_card(
                    ui,
                    "EXTERNAS",
                    external_count,
                    exp_color,
                    ActiveTab::Ports,
                );
                self.render_metric_card(
                    ui,
                    "UPDATES",
                    pkg_count,
                    Color32::from_rgb(210, 153, 34),
                    ActiveTab::Packages,
                );
                self.render_metric_card(
                    ui,
                    "CVEs",
                    cve_count,
                    if cve_count > 0 {
                        Color32::from_rgb(255, 123, 114)
                    } else {
                        Color32::from_rgb(63, 185, 80)
                    },
                    ActiveTab::Vulnerabilities,
                );
                self.render_metric_card(
                    ui,
                    "WMs/DEs",
                    wm_count,
                    Color32::from_rgb(121, 192, 255),
                    ActiveTab::Desktops,
                );
                self.render_metric_card(
                    ui,
                    "APPIMAGES",
                    app_count,
                    Color32::from_rgb(210, 168, 255),
                    ActiveTab::AppImages,
                );
                self.render_metric_card(
                    ui,
                    "FLATPAKS",
                    fp_count,
                    Color32::from_rgb(63, 185, 80),
                    ActiveTab::Flatpaks,
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!any_busy, egui::Button::new("📄 Exportar (Ctrl+E)"))
                        .clicked()
                    {
                        self.trigger_export(ui.ctx());
                    }
                    if ui
                        .add_enabled(!any_busy, egui::Button::new("🛡 CVEs"))
                        .on_hover_text("Atualizar exclusivamente CVEs (Ctrl+Shift+C)")
                        .clicked()
                    {
                        self.start_cve_refresh(true);
                    }
                    if ui
                        .add_enabled(!any_busy, egui::Button::new("📦 Cache (Ctrl+U)"))
                        .clicked()
                    {
                        self.start_pkg_cache_refresh();
                    }
                    if ui
                        .add_enabled(!any_busy, egui::Button::new("↻ Tudo"))
                        .clicked()
                    {
                        self.start_full_refresh(false);
                    }
                    if any_busy {
                        ui.spinner();
                    }
                });
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, ActiveTab::Ports, "Portas Abertas");
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::Packages,
                    "Pacotes Desatualizados",
                );
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::Vulnerabilities,
                    "Vulnerabilidades (CVEs)",
                );
                ui.selectable_value(&mut self.active_tab, ActiveTab::Desktops, "WMs & Ambientes");
                ui.selectable_value(&mut self.active_tab, ActiveTab::AppImages, "AppImages");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Flatpaks, "Flatpaks");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Limpar (Esc)").clicked() {
                        self.filter.clear();
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .id(filter_id)
                            .hint_text("Buscar na lista (Ctrl+F)...")
                            .desired_width(220.0),
                    );
                });
            });
            ui.add_space(4.0);
        });

        egui::Panel::bottom("bottom_status_panel").show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some((msg, is_err)) = &self.status_message {
                    let color = if *is_err {
                        Color32::from_rgb(255, 123, 114)
                    } else {
                        Color32::from_rgb(139, 148, 158)
                    };
                    ui.label(RichText::new(msg).color(color));
                } else {
                    ui.label(
                        RichText::new(
                            "Pronto — Ctrl+F buscar | Ctrl+U cache pacotes | Ctrl+Shift+C CVEs | Ctrl+E exportar",
                        )
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| match self.active_tab {
            ActiveTab::Ports => self.render_ports_tab(ui),
            ActiveTab::Packages => self.render_packages_tab(ui),
            ActiveTab::Vulnerabilities => self.render_vulnerabilities_tab(ui),
            ActiveTab::Desktops => self.render_desktops_tab(ui),
            ActiveTab::AppImages => self.render_appimages_tab(ui),
            ActiveTab::Flatpaks => self.render_flatpaks_tab(ui),
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 740.0])
            .with_min_inner_size([860.0, 500.0])
            .with_title("Arch Linux Visual System Auditor (eframe)"),
        ..Default::default()
    };

    eframe::run_native(
        "Arch Linux Visual System Auditor",
        options,
        Box::new(|cc| Ok(Box::new(ArchAuditorApp::new(cc)))),
    )
}
