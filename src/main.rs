use eframe::egui::{self, Color32, Key, Modifiers, RichText};
use egui_extras::{Column, TableBuilder};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ───────────────────────────── Tema ─────────────────────────────

const CVE_CACHE_TTL_SECS: u64 = 600;
const PORTS_AUTO_REFRESH: Duration = Duration::from_secs(5);

const BG: Color32 = Color32::from_rgb(15, 20, 25);
const CARD: Color32 = Color32::from_rgb(22, 27, 34);
const CARD_SEL: Color32 = Color32::from_rgb(28, 38, 50);
const BORDER: Color32 = Color32::from_rgb(48, 54, 61);
const MUTED: Color32 = Color32::from_rgb(139, 148, 158);
const RED: Color32 = Color32::from_rgb(255, 123, 114);
const ORANGE: Color32 = Color32::from_rgb(210, 153, 34);
const AMBER: Color32 = Color32::from_rgb(255, 166, 87);
const GREEN: Color32 = Color32::from_rgb(63, 185, 80);
const BLUE: Color32 = Color32::from_rgb(121, 192, 255);
const PURPLE: Color32 = Color32::from_rgb(210, 168, 255);
const ARCH: Color32 = Color32::from_rgb(23, 147, 209);

// ───────────────────────────── Modelos ─────────────────────────────

fn make_search(parts: &[&str]) -> String {
    parts.join(" ").to_lowercase()
}

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
    search: String,
}

impl PortEntry {
    fn new(
        protocol: String,
        state: String,
        local_addr: String,
        port: String,
        exposure: Exposure,
        process: String,
        pid: String,
    ) -> Self {
        let search = make_search(&[
            protocol.as_str(),
            state.as_str(),
            local_addr.as_str(),
            port.as_str(),
            process.as_str(),
            pid.as_str(),
        ]);
        Self {
            protocol,
            state,
            local_addr,
            port,
            exposure,
            process,
            pid,
            search,
        }
    }
}

#[derive(Debug, Clone)]
struct PackageEntry {
    source: String,
    name: String,
    current_ver: String,
    new_ver: String,
    search: String,
}

impl PackageEntry {
    fn new(source: String, name: String, current_ver: String, new_ver: String) -> Self {
        let search = make_search(&[
            source.as_str(),
            name.as_str(),
            current_ver.as_str(),
            new_ver.as_str(),
        ]);
        Self {
            source,
            name,
            current_ver,
            new_ver,
            search,
        }
    }
}

#[derive(Debug, Clone)]
struct DesktopEntryItem {
    name: String,
    session_type: String,
    binary: String,
    active: bool,
    source_path: String,
    search: String,
}

impl DesktopEntryItem {
    fn new(
        name: String,
        session_type: String,
        binary: String,
        active: bool,
        source_path: String,
    ) -> Self {
        let search = make_search(&[
            name.as_str(),
            session_type.as_str(),
            binary.as_str(),
            source_path.as_str(),
        ]);
        Self {
            name,
            session_type,
            binary,
            active,
            source_path,
            search,
        }
    }
}

#[derive(Debug, Clone)]
struct AppImageEntry {
    name: String,
    size_human: String,
    executable: bool,
    path: String,
    search: String,
}

impl AppImageEntry {
    fn new(name: String, size_human: String, executable: bool, path: String) -> Self {
        let search = make_search(&[name.as_str(), path.as_str()]);
        Self {
            name,
            size_human,
            executable,
            path,
            search,
        }
    }
}

#[derive(Debug, Clone)]
struct FlatpakEntry {
    app_id: String,
    name: String,
    version: String,
    branch: String,
    origin: String,
    installation: String,
    search: String,
}

impl FlatpakEntry {
    fn new(
        app_id: String,
        name: String,
        version: String,
        branch: String,
        origin: String,
        installation: String,
    ) -> Self {
        let search = make_search(&[
            name.as_str(),
            app_id.as_str(),
            origin.as_str(),
            installation.as_str(),
        ]);
        Self {
            app_id,
            name,
            version,
            branch,
            origin,
            installation,
            search,
        }
    }
}

#[derive(Debug, Clone)]
struct CveVulnerabilityEntry {
    package: String,
    severity: String,
    status: String,
    fixed_ver: String,
    cves: String,
    detail: String,
    search: String,
}

impl CveVulnerabilityEntry {
    fn new(
        package: String,
        severity: String,
        status: String,
        fixed_ver: String,
        cves: String,
        detail: String,
    ) -> Self {
        let search = make_search(&[
            package.as_str(),
            severity.as_str(),
            status.as_str(),
            fixed_ver.as_str(),
            cves.as_str(),
            detail.as_str(),
        ]);
        Self {
            package,
            severity,
            status,
            fixed_ver,
            cves,
            detail,
            search,
        }
    }
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
    Ports {
        ports: Vec<PortEntry>,
        warning: Option<String>,
    },
    Packages {
        packages: Vec<PackageEntry>,
        notes: Vec<String>,
        updated_unix: u64,
    },
    Cves {
        result: CveResult,
        updated_unix: u64,
    },
    Desktops {
        desktops: Vec<DesktopEntryItem>,
        summary: String,
    },
    AppImages(Vec<AppImageEntry>),
    Flatpaks {
        flatpaks: Vec<FlatpakEntry>,
        note: Option<String>,
    },
    ActionDone {
        message: String,
        is_error: bool,
    },
}

/// Envia eventos da thread de trabalho e acorda a UI imediatamente.
#[derive(Clone)]
struct Emitter {
    tx: Sender<WorkerEvent>,
    ctx: egui::Context,
}

impl Emitter {
    fn send(&self, ev: WorkerEvent) {
        let _ = self.tx.send(ev);
        self.ctx.request_repaint();
    }
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

impl ActiveTab {
    const ALL: [ActiveTab; 6] = [
        ActiveTab::Ports,
        ActiveTab::Packages,
        ActiveTab::Vulnerabilities,
        ActiveTab::Desktops,
        ActiveTab::AppImages,
        ActiveTab::Flatpaks,
    ];

    fn key(self) -> &'static str {
        match self {
            ActiveTab::Ports => "ports",
            ActiveTab::Packages => "packages",
            ActiveTab::Vulnerabilities => "cves",
            ActiveTab::Desktops => "desktops",
            ActiveTab::AppImages => "appimages",
            ActiveTab::Flatpaks => "flatpaks",
        }
    }

    fn from_key(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.key() == s)
    }

    fn label(self) -> &'static str {
        match self {
            ActiveTab::Ports => "Portas abertas",
            ActiveTab::Packages => "Pacotes desatualizados",
            ActiveTab::Vulnerabilities => "Vulnerabilidades (CVEs)",
            ActiveTab::Desktops => "WMs e ambientes",
            ActiveTab::AppImages => "AppImages",
            ActiveTab::Flatpaks => "Flatpaks",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SortState {
    col: Option<usize>,
    asc: bool,
}

struct Status {
    text: String,
    is_error: bool,
    at: Instant,
}

#[derive(Clone)]
enum Confirm {
    AppImage(String),
    DeleteAppImage {
        path: String,
    },
    UninstallFlatpak {
        app_id: String,
        name: String,
        installation: String,
    },
    Flatpak {
        app_id: String,
        remote: String,
        user_scope: bool,
    },
}

// ───────────────────────────── Utilidades ─────────────────────────────

fn fmt_ago(secs: u64) -> String {
    if secs < 5 {
        "agora mesmo".to_string()
    } else if secs < 60 {
        format!("há {} s", secs)
    } else if secs < 3600 {
        format!("há {} min", secs / 60)
    } else if secs < 86_400 {
        format!("há {} h", secs / 3600)
    } else {
        format!("há {} d", secs / 86_400)
    }
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}

fn sev_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn is_high_severity(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "critical" | "high")
}

fn sev_color(s: &str) -> Color32 {
    match s.to_lowercase().as_str() {
        "critical" | "high" => RED,
        "medium" => ORANGE,
        "low" => BLUE,
        _ => MUTED,
    }
}

fn valid_flatpak_token(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

// ───────────────────────────── Coletores ─────────────────────────────

struct ArchCollectors;

impl ArchCollectors {
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn home() -> PathBuf {
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
    }

    fn cache_dir() -> PathBuf {
        Self::home().join(".cache/arch-auditor")
    }

    fn is_root() -> bool {
        fs::metadata("/proc/self")
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
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

    /// Executa um comando com timeout. stdout/stderr são lidos em threads para
    /// que o processo nunca bloqueie por pipe cheio (> 64 KB).
    fn run_with_timeout(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<Output, String> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Falha ao iniciar '{}': {}", cmd, e))?;

        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();

        let out_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(s) = stdout_pipe.as_mut() {
                let _ = s.read_to_end(&mut buf);
            }
            buf
        });
        let err_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(s) = stderr_pipe.as_mut() {
                let _ = s.read_to_end(&mut buf);
            }
            buf
        });

        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let stdout = out_handle.join().unwrap_or_default();
                    let stderr = err_handle.join().unwrap_or_default();
                    return Ok(Output {
                        status,
                        stdout,
                        stderr,
                    });
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!("Timeout ({}s) ao executar '{}'", timeout_secs, cmd));
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(format!("Erro aguardando '{}': {}", cmd, e)),
            }
        }
    }

    // ── Portas ──

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

                        entries.push(PortEntry::new(
                            protocol, state, local_addr, port, exposure, process, pid,
                        ));
                    }

                    if hidden_pids && !Self::is_root() {
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

    /// /proc/net/tcp imprime o u32 em ordem do host; os bytes em memória já estão
    /// em ordem de rede, então `to_ne_bytes` devolve o endereço correto.
    fn decode_ipv4(hex: &str) -> String {
        u32::from_str_radix(hex, 16)
            .map(|raw| Ipv4Addr::from(raw.to_ne_bytes()).to_string())
            .unwrap_or_else(|_| hex.to_string())
    }

    fn decode_ipv6(hex: &str) -> String {
        if hex.len() != 32 || !hex.is_ascii() {
            return format!("[{}]", hex);
        }
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let Ok(word) = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16) else {
                return format!("[{}]", hex);
            };
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        format!("[{}]", Ipv6Addr::from(bytes))
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
                let addr = if is_v6 {
                    Self::decode_ipv6(hex_ip)
                } else {
                    Self::decode_ipv4(hex_ip)
                };
                let exposure = Self::classify_bind(&addr);
                out.push(PortEntry::new(
                    proto.to_string(),
                    "LISTEN".to_string(),
                    addr,
                    port_num.to_string(),
                    exposure,
                    "N/D (/proc/net)".to_string(),
                    "-".to_string(),
                ));
            }
        }
        out
    }

    // ── Pacotes ──

    /// Retorna (pacotes, notas, consulta_oficial_ok).
    fn collect_outdated_packages() -> (Vec<PackageEntry>, Vec<String>, bool) {
        let mut pkgs = Vec::new();
        let mut notes = Vec::new();
        let mut official_ok = false;

        if Self::command_exists("checkupdates") {
            match Self::run_with_timeout("checkupdates", &[], 25) {
                Ok(output) => {
                    let code = output.status.code().unwrap_or(1);
                    if code == 0 || code == 2 {
                        official_ok = true;
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for line in stdout.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 4 && parts[2] == "->" {
                                pkgs.push(PackageEntry::new(
                                    "Oficial".to_string(),
                                    parts[0].to_string(),
                                    parts[1].to_string(),
                                    parts[3].to_string(),
                                ));
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
                                pkgs.push(PackageEntry::new(
                                    format!("AUR ({})", helper),
                                    parts[0].to_string(),
                                    parts[1].to_string(),
                                    parts[3].to_string(),
                                ));
                            }
                        }
                    }
                }
                Err(e) => notes.push(e),
            }
        } else {
            notes.push("Nenhum helper AUR (paru/yay) detectado.".to_string());
        }

        (pkgs, notes, official_ok)
    }

    fn pkg_cache_path() -> PathBuf {
        Self::cache_dir().join("packages.cache")
    }

    fn write_pkg_cache(pkgs: &[PackageEntry], ts: u64) {
        let path = Self::pkg_cache_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut buf = format!("{}\n", ts);
        for p in pkgs {
            buf.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                Self::sanitize_field(&p.source),
                Self::sanitize_field(&p.name),
                Self::sanitize_field(&p.current_ver),
                Self::sanitize_field(&p.new_ver),
            ));
        }
        let _ = fs::write(path, buf);
    }

    fn read_pkg_cache() -> Option<(Vec<PackageEntry>, u64)> {
        let content = fs::read_to_string(Self::pkg_cache_path()).ok()?;
        let mut lines = content.lines();
        let ts: u64 = lines.next()?.trim().parse().ok()?;
        let mut list = Vec::new();
        for line in lines {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 4 {
                list.push(PackageEntry::new(
                    cols[0].to_string(),
                    cols[1].to_string(),
                    cols[2].to_string(),
                    cols[3].to_string(),
                ));
            }
        }
        Some((list, ts))
    }

    /// Coleta pacotes; grava cache em sucesso e cai para o cache em falha.
    fn collect_packages_cached() -> (Vec<PackageEntry>, Vec<String>, u64) {
        let (pkgs, mut notes, ok) = Self::collect_outdated_packages();
        let now = Self::now_unix();
        if ok {
            Self::write_pkg_cache(&pkgs, now);
            return (pkgs, notes, now);
        }
        if let Some((cached, ts)) = Self::read_pkg_cache() {
            notes.push(format!(
                "Falha ao consultar pacotes oficiais; exibindo cache ({}).",
                fmt_ago(now.saturating_sub(ts))
            ));
            return (cached, notes, ts);
        }
        (pkgs, notes, now)
    }

    // ── CVEs ──

    fn cve_cache_path() -> PathBuf {
        Self::cache_dir().join("cves.cache")
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
                entries.push(CveVulnerabilityEntry::new(
                    cols[0].to_string(),
                    cols[1].to_string(),
                    cols[2].to_string(),
                    cols[3].to_string(),
                    cols[4].to_string(),
                    cols.get(5).unwrap_or(&"").to_string(),
                ));
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
                "Exibindo cache expirado ({}) por falha ou ausência de rede/arch-audit.",
                fmt_ago(age)
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

    /// Formato padrão do arch-audit:
    ///   "Package nginx is affected by CVE-2021-1, CVE-2021-2. High risk! Update to 1.2.3-1!"
    fn parse_arch_audit_line(line: &str) -> Option<CveVulnerabilityEntry> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let raw: Vec<&str> = trimmed.split_whitespace().collect();
        let first = *raw.first()?;
        let name_tok = if first.eq_ignore_ascii_case("package") {
            *raw.get(1)?
        } else {
            first
        };
        let pkg = Self::clean_pkg_name(name_tok);
        if pkg.is_empty() {
            return None;
        }

        let norm: Vec<String> = raw
            .iter()
            .map(|t| {
                t.trim_matches(|c: char| !c.is_ascii_alphanumeric())
                    .to_lowercase()
            })
            .collect();

        let cves: Vec<String> = raw
            .iter()
            .filter_map(|t| {
                let clean = t.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
                if clean.to_uppercase().starts_with("CVE-") && clean.len() > 8 {
                    Some(clean.to_uppercase())
                } else {
                    None
                }
            })
            .collect();

        // Severidade: "<nível> risk" / "<nível> severity" (palavras inteiras, sem falsos positivos).
        let mut severity = "Unknown";
        for w in norm.windows(2) {
            if matches!(w[1].as_str(), "risk" | "severity") {
                severity = match w[0].as_str() {
                    "critical" => "Critical",
                    "high" => "High",
                    "medium" => "Medium",
                    "low" => "Low",
                    _ => continue,
                };
                break;
            }
        }
        if severity == "Unknown" {
            let lower = trimmed.to_lowercase();
            severity = if lower.contains("(critical)") {
                "Critical"
            } else if lower.contains("(high)") {
                "High"
            } else if lower.contains("(medium)") {
                "Medium"
            } else if lower.contains("(low)") {
                "Low"
            } else {
                "Unknown"
            };
        }

        // Versão corrigida: "Update to <versão>"
        let fixed = norm
            .windows(2)
            .position(|w| w[0] == "update" && w[1] == "to")
            .and_then(|i| raw.get(i + 2))
            .map(|v| {
                v.trim_matches(|c: char| matches!(c, '!' | '.' | ',' | ';' | '(' | ')'))
                    .to_string()
            })
            .filter(|v| !v.is_empty());

        let (status, fixed_ver) = match fixed {
            Some(v) => ("Correção disponível".to_string(), v),
            None => ("Vulnerável".to_string(), "Sem correção".to_string()),
        };

        let cve_str = if !cves.is_empty() {
            cves.join(", ")
        } else {
            format!("Advisory de {}", pkg)
        };

        Some(CveVulnerabilityEntry::new(
            pkg,
            severity.to_string(),
            status,
            fixed_ver,
            cve_str,
            trimmed.to_string(),
        ))
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

    fn advisory_url(entry: &CveVulnerabilityEntry) -> String {
        Self::advisory_url_from_query(&entry.cves, &entry.package)
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

                let mut entries: Vec<CveVulnerabilityEntry> = stdout
                    .lines()
                    .filter_map(Self::parse_arch_audit_line)
                    .collect();

                if entries.is_empty() && !output.status.success() && !stderr.is_empty() {
                    if let Some(mut stale) = Self::read_cve_cache(true) {
                        stale.note = Some(format!(
                            "Falha ao consultar arch-audit ({}) — exibindo cache local.",
                            stderr
                        ));
                        return stale;
                    }
                    return CveResult {
                        entries: Vec::new(),
                        note: Some(format!("Falha ao executar arch-audit ({})", stderr)),
                        from_cache: false,
                    };
                }

                entries.sort_by(|a, b| {
                    sev_rank(&a.severity)
                        .cmp(&sev_rank(&b.severity))
                        .then(a.package.to_lowercase().cmp(&b.package.to_lowercase()))
                });

                Self::write_cve_cache(&entries, Self::now_unix());

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

    // ── WMs / DEs ──

    fn collect_wms_and_des() -> (Vec<DesktopEntryItem>, String) {
        let xdg_current = env::var("XDG_CURRENT_DESKTOP")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let desktop_session = env::var("DESKTOP_SESSION")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let current_desktop = xdg_current
            .clone()
            .or(desktop_session.clone())
            .unwrap_or_else(|| "Desconhecida / TTY".to_string());

        let session_type = env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "N/D".to_string());
        let summary = format!("Sessão atual: {} ({})", current_desktop, session_type);

        // Tokens do desktop ativo (XDG_CURRENT_DESKTOP pode ser "KDE", "GNOME:GNOME-Classic", etc.)
        let mut active_tokens: Vec<String> = Vec::new();
        for src in [xdg_current, desktop_session].into_iter().flatten() {
            for tok in src.split(':') {
                let mut t = tok.trim().to_lowercase();
                if t.is_empty() {
                    continue;
                }
                if t == "kde" {
                    t = "plasma".to_string();
                }
                if !active_tokens.contains(&t) {
                    active_tokens.push(t);
                }
            }
        }
        let is_active = |haystacks: &[&str]| -> bool {
            active_tokens.iter().any(|tok| {
                haystacks
                    .iter()
                    .any(|h| h.to_lowercase().contains(tok.as_str()))
            })
        };

        let mut map: HashMap<String, DesktopEntryItem> = HashMap::new();

        let session_dirs = [
            ("/usr/share/wayland-sessions", "Wayland"),
            ("/usr/share/xsessions", "X11"),
        ];

        for (dir_str, s_type) in session_dirs {
            let Ok(entries) = fs::read_dir(Path::new(dir_str)) else {
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

                let active = is_active(&[name.as_str(), stem.as_str(), exec_bin.as_str()])
                    && (session_type.eq_ignore_ascii_case(s_type)
                        || session_type == "N/D"
                        || session_type == "tty");

                let key = format!("{}-{}", name.to_lowercase(), s_type);
                map.insert(
                    key,
                    DesktopEntryItem::new(
                        name,
                        s_type.to_string(),
                        exec_bin,
                        active,
                        path.display().to_string(),
                    ),
                );
            }
        }

        const KNOWN_BINS: &[(&str, &str, &str)] = &[
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

        for (bin, friendly, s_type) in KNOWN_BINS {
            if !Self::command_exists(bin) {
                continue;
            }
            let already = map.values().any(|item| {
                item.name.to_lowercase().contains(&friendly.to_lowercase())
                    || item.binary.contains(bin)
            });
            if !already {
                let active = is_active(&[friendly, bin]);
                map.insert(
                    format!("bin-{}", bin),
                    DesktopEntryItem::new(
                        friendly.to_string(),
                        s_type.to_string(),
                        format!("/usr/bin/{}", bin),
                        active,
                        "Binário (/usr/bin)".to_string(),
                    ),
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

    // ── AppImages ──

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
        let home = Self::home();
        let roots: Vec<PathBuf> = vec![
            home.join("Applications"),
            home.join("Downloads"),
            home.join("Desktop"),
            home.join(".local/bin"),
            PathBuf::from("/opt"),
        ];

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
                    out.push(AppImageEntry::new(
                        fname,
                        Self::human_size(meta.len()),
                        exec,
                        path.display().to_string(),
                    ));
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

        let dest_dir = Self::home().join("Applications");
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

    // ── Flatpak ──

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
                        let col = |i: usize| -> String {
                            cols.get(i)
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .unwrap_or("-")
                                .to_string()
                        };
                        list.push(FlatpakEntry::new(
                            cols[0].trim().to_string(),
                            cols[1].trim().to_string(),
                            col(2),
                            col(3),
                            col(4),
                            col(5),
                        ));
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
        if !valid_flatpak_token(app_id) || !valid_flatpak_token(remote) {
            return Err(
                "Application ID e remote só podem conter letras, números, '.', '_' e '-' (e não podem começar com '-')."
                    .to_string(),
            );
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

    // ── Executar / remover apps ──

    /// Inicia um processo desacoplado (não morre ao fechar o auditor).
    fn spawn_detached(cmd: &str, args: &[&str], cwd: Option<&Path>) -> Result<(), String> {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new(cmd);
        c.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        if let Some(d) = cwd {
            c.current_dir(d);
        }
        let mut child = c
            .spawn()
            .map_err(|e| format!("Falha ao iniciar '{}': {}", cmd, e))?;
        thread::spawn(move || {
            let _ = child.wait(); // evita processo zumbi
        });
        Ok(())
    }

    fn run_flatpak_app(app_id: &str) -> Result<String, String> {
        if !valid_flatpak_token(app_id) {
            return Err("Application ID inválido.".to_string());
        }
        if !Self::command_exists("flatpak") {
            return Err("Comando 'flatpak' não encontrado.".to_string());
        }
        Self::spawn_detached("flatpak", &["run", app_id], None)?;
        Ok(format!("Iniciando Flatpak '{}'...", app_id))
    }

    fn run_appimage(path: &str) -> Result<String, String> {
        let p = Path::new(path);
        if !p.is_file() {
            return Err(format!("Arquivo não encontrado: {}", path));
        }
        if !Self::is_executable(p) {
            return Err("O AppImage está sem +x. Use 'Habilitar +x' primeiro.".to_string());
        }
        Self::spawn_detached(path, &[], p.parent())?;
        Ok(format!("Iniciando {}...", path))
    }

    fn uninstall_flatpak_app(app_id: &str, installation: &str) -> Result<String, String> {
        if !valid_flatpak_token(app_id) {
            return Err("Application ID inválido.".to_string());
        }
        let scope = match installation.trim() {
            "user" => "--user".to_string(),
            "system" => "--system".to_string(),
            other if valid_flatpak_token(other) => format!("--installation={}", other),
            _ => return Err("Escopo de instalação desconhecido.".to_string()),
        };
        if !Self::command_exists("flatpak") {
            return Err("Comando 'flatpak' não encontrado.".to_string());
        }
        let output =
            Self::run_with_timeout("flatpak", &["uninstall", scope.as_str(), "-y", app_id], 120)?;
        if output.status.success() {
            Ok(format!("Flatpak '{}' desinstalado.", app_id))
        } else {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(format!("Falha ao desinstalar '{}': {}", app_id, err))
        }
    }

    fn delete_appimage(path: &str) -> Result<String, String> {
        let p = Path::new(path);
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.to_lowercase().ends_with(".appimage") {
            return Err("Só é possível excluir arquivos .AppImage.".to_string());
        }
        let meta =
            fs::symlink_metadata(p).map_err(|e| format!("Falha ao ler '{}': {}", path, e))?;
        if !meta.is_file() {
            return Err("O alvo não é um arquivo regular.".to_string());
        }
        if Self::command_exists("gio") {
            if let Ok(out) = Self::run_with_timeout("gio", &["trash", path], 15) {
                if out.status.success() {
                    return Ok(format!("'{}' movido para a lixeira.", name));
                }
            }
        }
        fs::remove_file(p).map_err(|e| format!("Falha ao excluir '{}': {}", path, e))?;
        Ok(format!("'{}' removido permanentemente.", name))
    }

    // ── Exportação ──

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
                    p.protocol,
                    p.local_addr,
                    p.port,
                    md_escape(&p.process),
                    p.pid,
                    p.state
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
                    .unwrap_or("Nenhuma vulnerabilidade CVE listada."),
            );
            md.push_str("\n\n");
        } else {
            md.push_str("| Pacote | Severidade | Status | Correção | CVEs | Advisory |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for v in &snap.vulnerabilities {
                let url = Self::advisory_url(v);
                md.push_str(&format!(
                    "| `{}` | {} | {} | `{}` | {} | [Link]({}) |\n",
                    v.package,
                    v.severity,
                    v.status,
                    v.fixed_ver,
                    md_escape(&v.cves),
                    url
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
        let out_path = Self::home().join(format!("arch-audit-resumo-{}.md", ts));
        let content = Self::build_summary_markdown(snap, ts);
        fs::write(&out_path, content)
            .map_err(|e| format!("Falha ao salvar resumo em '{}': {}", out_path.display(), e))?;
        Ok(out_path)
    }
}

// ───────────────────────────── Helpers de UI ─────────────────────────────

fn card_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(CARD)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(10))
}

fn empty_state(ui: &mut egui::Ui, text: &str) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new(text).color(MUTED));
    });
}

fn count_label(ui: &mut egui::Ui, shown: usize, total: usize) {
    ui.label(
        RichText::new(format!("Mostrando {} de {}", shown, total))
            .color(MUTED)
            .small(),
    );
}

fn sort_header(ui: &mut egui::Ui, title: &str, idx: usize, sort: &mut SortState) {
    let arrow = match sort.col {
        Some(c) if c == idx => {
            if sort.asc {
                " ▲"
            } else {
                " ▼"
            }
        }
        _ => "",
    };
    let resp = ui
        .add(
            egui::Label::new(RichText::new(format!("{}{}", title, arrow)).strong())
                .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("Clique para ordenar");
    if resp.clicked() {
        if sort.col == Some(idx) {
            sort.asc = !sort.asc;
        } else {
            sort.col = Some(idx);
            sort.asc = true;
        }
    }
}

// ───────────────────────────── App ─────────────────────────────

struct ArchAuditorApp {
    data: AuditSnapshot,
    active_tab: ActiveTab,
    filter: String,
    only_external_ports: bool,
    only_high_cve: bool,
    auto_refresh_ports: bool,
    cve_lookup_input: String,
    appimage_source_input: String,
    flatpak_id_input: String,
    flatpak_remote_input: String,
    flatpak_user_scope: bool,

    loading_ports: bool,
    loading_pkgs: bool,
    loading_cves: bool,
    loading_desktops: bool,
    loading_appimages: bool,
    loading_flatpaks: bool,
    loading_action: bool,
    full_running: bool,

    status: Option<Status>,
    confirm: Option<Confirm>,
    ports_sort: SortState,
    pkgs_sort: SortState,
    cves_sort: SortState,
    last_ports_refresh: Instant,

    rx: Receiver<WorkerEvent>,
    emitter: Emitter,
}

impl ArchAuditorApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::apply_theme(&cc.egui_ctx);

        let (tx, rx) = mpsc::channel();
        let emitter = Emitter {
            tx,
            ctx: cc.egui_ctx.clone(),
        };

        let mut app = Self {
            data: AuditSnapshot::default(),
            active_tab: ActiveTab::Ports,
            filter: String::new(),
            only_external_ports: false,
            only_high_cve: false,
            auto_refresh_ports: false,
            cve_lookup_input: String::new(),
            appimage_source_input: String::new(),
            flatpak_id_input: String::new(),
            flatpak_remote_input: "flathub".to_string(),
            flatpak_user_scope: true,
            loading_ports: false,
            loading_pkgs: false,
            loading_cves: false,
            loading_desktops: false,
            loading_appimages: false,
            loading_flatpaks: false,
            loading_action: false,
            full_running: false,
            status: None,
            confirm: None,
            ports_sort: SortState::default(),
            pkgs_sort: SortState::default(),
            cves_sort: SortState::default(),
            last_ports_refresh: Instant::now(),
            rx,
            emitter,
        };

        app.load_settings(cc.storage);

        // Mostra imediatamente o último cache de pacotes enquanto o refresh roda.
        if let Some((pkgs, ts)) = ArchCollectors::read_pkg_cache() {
            let age = ArchCollectors::now_unix().saturating_sub(ts);
            app.data.packages = pkgs;
            app.data.package_notes = vec![format!(
                "Exibindo cache ({}) — atualizando em segundo plano...",
                fmt_ago(age)
            )];
            app.data.last_updated_unix = ts;
        }

        app.start_full_refresh(false);
        app
    }

    fn apply_theme(ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG;
        visuals.window_fill = BG;
        visuals.extreme_bg_color = Color32::from_rgb(13, 17, 23);
        visuals.faint_bg_color = Color32::from_rgb(20, 26, 33);
        visuals.widgets.noninteractive.bg_fill = CARD;
        ctx.set_visuals(visuals);

        let mut style = (*ctx.global_style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        ctx.set_global_style(style);
    }

    // ── Persistência (requer a feature "persistence" do eframe; sem ela é ignorada) ──

    fn load_settings(&mut self, storage: Option<&dyn eframe::Storage>) {
        let Some(st) = storage else {
            return;
        };
        if let Some(t) = st
            .get_string("tab")
            .and_then(|s| ActiveTab::from_key(s.as_str()))
        {
            self.active_tab = t;
        }
        let flag = |key: &str| st.get_string(key).map(|s| s == "1");
        self.only_external_ports = flag("only_external").unwrap_or(false);
        self.only_high_cve = flag("only_high").unwrap_or(false);
        self.auto_refresh_ports = flag("auto_ports").unwrap_or(false);
        self.flatpak_user_scope = flag("flatpak_user").unwrap_or(true);
        if let Some(r) = st.get_string("flatpak_remote") {
            if !r.trim().is_empty() {
                self.flatpak_remote_input = r;
            }
        }
    }

    // ── Estado / status ──

    fn any_data_loading(&self) -> bool {
        self.loading_ports
            || self.loading_pkgs
            || self.loading_cves
            || self.loading_desktops
            || self.loading_appimages
            || self.loading_flatpaks
    }

    fn any_busy(&self) -> bool {
        self.any_data_loading() || self.loading_action
    }

    fn set_status(&mut self, text: impl Into<String>, is_error: bool) {
        self.status = Some(Status {
            text: text.into(),
            is_error,
            at: Instant::now(),
        });
    }

    /// Mensagem de início só aparece em refresh individual (a auditoria completa tem a sua).
    fn note_start(&mut self, text: &str) {
        if !self.full_running {
            self.set_status(text, false);
        }
    }

    fn bump_updated(&mut self, ts: u64) {
        self.data.last_updated_unix = self.data.last_updated_unix.max(ts);
    }

    fn expire_status(&mut self, ctx: &egui::Context) {
        if self.any_busy() {
            return;
        }
        let Some((is_error, age)) = self.status.as_ref().map(|s| (s.is_error, s.at.elapsed()))
        else {
            return;
        };
        let ttl = Duration::from_secs(if is_error { 15 } else { 8 });
        if age >= ttl {
            self.status = None;
        } else {
            ctx.request_repaint_after(ttl - age);
        }
    }

    // ── Disparo de tarefas (todas usam o mesmo canal) ──

    fn start_full_refresh(&mut self, force_cve: bool) {
        self.full_running = true;
        self.set_status("Executando auditoria completa do sistema...", false);
        self.start_ports_refresh();
        self.start_desktops_refresh();
        self.start_appimages_refresh();
        self.start_flatpaks_refresh();
        self.start_pkgs_refresh();
        self.start_cve_refresh(force_cve);
    }

    fn start_ports_refresh(&mut self) {
        if self.loading_ports {
            return;
        }
        self.loading_ports = true;
        self.last_ports_refresh = Instant::now();
        let em = self.emitter.clone();
        thread::spawn(move || {
            let (ports, warning) = ArchCollectors::collect_open_ports();
            em.send(WorkerEvent::Ports { ports, warning });
        });
    }

    fn start_pkgs_refresh(&mut self) {
        if self.loading_pkgs {
            return;
        }
        self.loading_pkgs = true;
        self.note_start("Atualizando pacotes desatualizados (checkupdates / AUR)...");
        let em = self.emitter.clone();
        thread::spawn(move || {
            let (packages, notes, updated_unix) = ArchCollectors::collect_packages_cached();
            em.send(WorkerEvent::Packages {
                packages,
                notes,
                updated_unix,
            });
        });
    }

    fn start_cve_refresh(&mut self, force_refresh: bool) {
        if self.loading_cves {
            return;
        }
        self.loading_cves = true;
        self.note_start("Atualizando vulnerabilidades CVE via arch-audit...");
        let em = self.emitter.clone();
        thread::spawn(move || {
            let result = ArchCollectors::collect_cve_vulnerabilities(force_refresh);
            em.send(WorkerEvent::Cves {
                result,
                updated_unix: ArchCollectors::now_unix(),
            });
        });
    }

    fn start_desktops_refresh(&mut self) {
        if self.loading_desktops {
            return;
        }
        self.loading_desktops = true;
        let em = self.emitter.clone();
        thread::spawn(move || {
            let (desktops, summary) = ArchCollectors::collect_wms_and_des();
            em.send(WorkerEvent::Desktops { desktops, summary });
        });
    }

    fn start_appimages_refresh(&mut self) {
        if self.loading_appimages {
            return;
        }
        self.loading_appimages = true;
        let em = self.emitter.clone();
        thread::spawn(move || {
            em.send(WorkerEvent::AppImages(ArchCollectors::collect_appimages()));
        });
    }

    fn start_flatpaks_refresh(&mut self) {
        if self.loading_flatpaks {
            return;
        }
        self.loading_flatpaks = true;
        let em = self.emitter.clone();
        thread::spawn(move || {
            let (flatpaks, note) = ArchCollectors::collect_flatpaks();
            em.send(WorkerEvent::Flatpaks { flatpaks, note });
        });
    }

    fn start_install_appimage(&mut self, source_path: String) {
        self.loading_action = true;
        self.set_status("Instalando AppImage em ~/Applications...", false);
        let em = self.emitter.clone();
        thread::spawn(
            move || match ArchCollectors::install_local_appimage(&source_path) {
                Ok(message) => {
                    em.send(WorkerEvent::ActionDone {
                        message,
                        is_error: false,
                    });
                    em.send(WorkerEvent::AppImages(ArchCollectors::collect_appimages()));
                }
                Err(message) => em.send(WorkerEvent::ActionDone {
                    message,
                    is_error: true,
                }),
            },
        );
    }

    fn start_chmod_appimage(&mut self, file_path: String) {
        self.loading_action = true;
        self.set_status(format!("Aplicando +x em {}...", file_path), false);
        let em = self.emitter.clone();
        thread::spawn(
            move || match ArchCollectors::make_appimage_executable(&file_path) {
                Ok(message) => {
                    em.send(WorkerEvent::ActionDone {
                        message,
                        is_error: false,
                    });
                    em.send(WorkerEvent::AppImages(ArchCollectors::collect_appimages()));
                }
                Err(message) => em.send(WorkerEvent::ActionDone {
                    message,
                    is_error: true,
                }),
            },
        );
    }

    fn start_install_flatpak(&mut self, app_id: String, remote: String, user_scope: bool) {
        self.loading_action = true;
        self.set_status(
            format!(
                "Instalando Flatpak '{}' via '{}'...",
                app_id.trim(),
                remote.trim()
            ),
            false,
        );
        let em = self.emitter.clone();
        thread::spawn(move || {
            match ArchCollectors::install_flatpak_app(&app_id, &remote, user_scope) {
                Ok(message) => {
                    em.send(WorkerEvent::ActionDone {
                        message,
                        is_error: false,
                    });
                    let (flatpaks, note) = ArchCollectors::collect_flatpaks();
                    em.send(WorkerEvent::Flatpaks { flatpaks, note });
                }
                Err(message) => em.send(WorkerEvent::ActionDone {
                    message,
                    is_error: true,
                }),
            }
        });
    }

    fn run_appimage_now(&mut self, path: &str) {
        match ArchCollectors::run_appimage(path) {
            Ok(m) => self.set_status(m, false),
            Err(e) => self.set_status(e, true),
        }
    }

    fn run_flatpak_now(&mut self, app_id: &str) {
        match ArchCollectors::run_flatpak_app(app_id) {
            Ok(m) => self.set_status(m, false),
            Err(e) => self.set_status(e, true),
        }
    }

    fn start_delete_appimage(&mut self, path: String) {
        self.loading_action = true;
        self.set_status("Removendo AppImage...", false);
        let em = self.emitter.clone();
        thread::spawn(move || match ArchCollectors::delete_appimage(&path) {
            Ok(message) => {
                em.send(WorkerEvent::ActionDone {
                    message,
                    is_error: false,
                });
                em.send(WorkerEvent::AppImages(ArchCollectors::collect_appimages()));
            }
            Err(message) => em.send(WorkerEvent::ActionDone {
                message,
                is_error: true,
            }),
        });
    }

    fn start_uninstall_flatpak(&mut self, app_id: String, installation: String) {
        self.loading_action = true;
        self.set_status(format!("Desinstalando Flatpak '{}'...", app_id), false);
        let em = self.emitter.clone();
        thread::spawn(move || {
            match ArchCollectors::uninstall_flatpak_app(&app_id, &installation) {
                Ok(message) => {
                    em.send(WorkerEvent::ActionDone {
                        message,
                        is_error: false,
                    });
                    let (flatpaks, note) = ArchCollectors::collect_flatpaks();
                    em.send(WorkerEvent::Flatpaks { flatpaks, note });
                }
                Err(message) => em.send(WorkerEvent::ActionDone {
                    message,
                    is_error: true,
                }),
            }
        });
    }

    fn trigger_export(&mut self, ctx: &egui::Context) {
        let ts = ArchCollectors::now_unix();
        let md = ArchCollectors::build_summary_markdown(&self.data, ts);
        ctx.copy_text(md);

        match ArchCollectors::export_summary(&self.data) {
            Ok(path) => self.set_status(
                format!(
                    "Resumo salvo em {} e copiado para a área de transferência.",
                    path.display()
                ),
                false,
            ),
            Err(err) => self.set_status(err, true),
        }
    }

    // ── Eventos dos workers ──

    fn poll_worker(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            self.apply_event(ev);
        }
    }

    fn apply_event(&mut self, ev: WorkerEvent) {
        match ev {
            WorkerEvent::Ports { ports, warning } => {
                self.data.ports = ports;
                self.data.ports_warning = warning;
                self.loading_ports = false;
                self.bump_updated(ArchCollectors::now_unix());
            }
            WorkerEvent::Packages {
                packages,
                notes,
                updated_unix,
            } => {
                self.data.packages = packages;
                self.data.package_notes = notes;
                self.loading_pkgs = false;
                self.bump_updated(updated_unix);
                if !self.full_running {
                    let n = self.data.packages.len();
                    self.set_status(
                        format!("Cache de pacotes atualizado ({} pendente(s)).", n),
                        false,
                    );
                }
            }
            WorkerEvent::Cves {
                result,
                updated_unix,
            } => {
                self.data.vulnerabilities = result.entries;
                self.data.vulnerability_note = result.note;
                self.loading_cves = false;
                self.bump_updated(updated_unix);
                if !self.full_running {
                    let n = self.data.vulnerabilities.len();
                    self.set_status(
                        format!(
                            "CVEs atualizadas ({} registro(s){}).",
                            n,
                            if result.from_cache { ", cache" } else { "" }
                        ),
                        false,
                    );
                }
            }
            WorkerEvent::Desktops { desktops, summary } => {
                self.data.desktops = desktops;
                self.data.session_summary = summary;
                self.loading_desktops = false;
            }
            WorkerEvent::AppImages(list) => {
                self.data.appimages = list;
                self.loading_appimages = false;
            }
            WorkerEvent::Flatpaks { flatpaks, note } => {
                self.data.flatpaks = flatpaks;
                self.data.flatpak_note = note;
                self.loading_flatpaks = false;
            }
            WorkerEvent::ActionDone { message, is_error } => {
                self.loading_action = false;
                self.set_status(message, is_error);
            }
        }

        if self.full_running && !self.any_data_loading() {
            self.full_running = false;
            self.set_status("Auditoria concluída.", false);
        }
    }

    // ── Entrada: atalhos, drag & drop, auto-refresh ──

    fn handle_shortcuts(&mut self, ctx: &egui::Context, filter_id: egui::Id) {
        let keys = [
            Key::Num1,
            Key::Num2,
            Key::Num3,
            Key::Num4,
            Key::Num5,
            Key::Num6,
        ];
        let (focus, upd, cves, export, all, esc, tab_idx) = ctx.input_mut(|i| {
            let tab_idx = keys.iter().position(|k| i.consume_key(Modifiers::CTRL, *k));
            (
                i.consume_key(Modifiers::CTRL, Key::F),
                i.consume_key(Modifiers::CTRL, Key::U),
                i.consume_key(Modifiers::CTRL | Modifiers::SHIFT, Key::C),
                i.consume_key(Modifiers::CTRL, Key::E),
                i.consume_key(Modifiers::NONE, Key::F5),
                i.key_pressed(Key::Escape),
                tab_idx,
            )
        });

        if focus {
            ctx.memory_mut(|m| m.request_focus(filter_id));
        }
        if upd {
            self.start_pkgs_refresh();
        }
        if cves {
            self.start_cve_refresh(true);
        }
        if export {
            self.trigger_export(ctx);
        }
        if all && !self.any_busy() {
            self.start_full_refresh(false);
        }
        if let Some(i) = tab_idx {
            self.active_tab = ActiveTab::ALL[i];
        }
        if esc {
            if self.confirm.is_some() {
                self.confirm = None;
            } else {
                self.filter.clear();
            }
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if let Some(p) = dropped
            .into_iter()
            .find(|p| p.to_string_lossy().to_lowercase().ends_with(".appimage"))
        {
            self.appimage_source_input = p.display().to_string();
            self.active_tab = ActiveTab::AppImages;
            self.set_status(
                "AppImage recebido — clique em Instalar para copiar para ~/Applications.",
                false,
            );
        }
    }

    fn maybe_auto_refresh_ports(&mut self, ctx: &egui::Context) {
        if !(self.auto_refresh_ports && self.active_tab == ActiveTab::Ports) {
            return;
        }
        let elapsed = self.last_ports_refresh.elapsed();
        if elapsed >= PORTS_AUTO_REFRESH {
            self.start_ports_refresh();
            ctx.request_repaint_after(PORTS_AUTO_REFRESH);
        } else {
            ctx.request_repaint_after(PORTS_AUTO_REFRESH - elapsed);
        }
    }

    // ── Cards / abas ──

    fn tab_loading(&self, tab: ActiveTab) -> bool {
        match tab {
            ActiveTab::Ports => self.loading_ports,
            ActiveTab::Packages => self.loading_pkgs,
            ActiveTab::Vulnerabilities => self.loading_cves,
            ActiveTab::Desktops => self.loading_desktops,
            ActiveTab::AppImages => self.loading_appimages,
            ActiveTab::Flatpaks => self.loading_flatpaks,
        }
    }

    fn tab_card_info(&self, tab: ActiveTab) -> (&'static str, String, Color32) {
        let loading = self.tab_loading(tab);
        let fmt = |n: usize| -> String {
            if loading && n == 0 {
                "…".to_string()
            } else {
                n.to_string()
            }
        };
        match tab {
            ActiveTab::Ports => {
                let total = self.data.ports.len();
                let ext = self
                    .data
                    .ports
                    .iter()
                    .filter(|p| p.exposure == Exposure::External)
                    .count();
                let value = if loading && total == 0 {
                    "…".to_string()
                } else {
                    format!("{} ext · {}", ext, total)
                };
                ("PORTAS", value, if ext > 0 { RED } else { GREEN })
            }
            ActiveTab::Packages => {
                let n = self.data.packages.len();
                ("PACOTES", fmt(n), if n > 0 { ORANGE } else { GREEN })
            }
            ActiveTab::Vulnerabilities => {
                let n = self.data.vulnerabilities.len();
                ("CVEs", fmt(n), if n > 0 { RED } else { GREEN })
            }
            ActiveTab::Desktops => ("WMs / DEs", fmt(self.data.desktops.len()), BLUE),
            ActiveTab::AppImages => ("APPIMAGES", fmt(self.data.appimages.len()), PURPLE),
            ActiveTab::Flatpaks => ("FLATPAKS", fmt(self.data.flatpaks.len()), GREEN),
        }
    }

    fn render_tab_card(&mut self, ui: &mut egui::Ui, tab: ActiveTab) {
        let (title, value, accent) = self.tab_card_info(tab);
        let selected = self.active_tab == tab;

        let frame = egui::Frame::NONE
            .fill(if selected { CARD_SEL } else { CARD })
            .stroke(if selected {
                egui::Stroke::new(1.5, accent)
            } else {
                egui::Stroke::new(1.0, BORDER)
            })
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(12, 6));

        let resp = frame.show(ui, |ui| {
            ui.set_min_width(92.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(title).size(11.0).color(MUTED));
                ui.label(RichText::new(value).size(15.0).strong().color(accent));
            });
        });

        let idx = ActiveTab::ALL.iter().position(|t| *t == tab).unwrap_or(0) + 1;
        let resp = resp
            .response
            .interact(egui::Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text(format!("{} (Ctrl+{})", tab.label(), idx));
        if resp.clicked() {
            self.active_tab = tab;
        }
    }

    // ── Aba: Portas ──

    fn render_ports_tab(&mut self, ui: &mut egui::Ui) {
        let q = self.filter.trim().to_lowercase();

        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.only_external_ports,
                RichText::new("Somente binds externos (0.0.0.0 / [::])").strong(),
            );
            ui.checkbox(&mut self.auto_refresh_ports, "Auto-atualizar (5 s)");
            if self.loading_ports {
                ui.spinner();
            }
        });

        if let Some(warn) = &self.data.ports_warning {
            ui.colored_label(ORANGE, format!("⚠ {}", warn));
        }

        let only_ext = self.only_external_ports;
        let mut rows: Vec<&PortEntry> = self
            .data
            .ports
            .iter()
            .filter(|p| !only_ext || p.exposure == Exposure::External)
            .filter(|p| q.is_empty() || p.search.contains(&q))
            .collect();

        count_label(ui, rows.len(), self.data.ports.len());
        ui.add_space(4.0);

        if self.data.ports.is_empty() {
            empty_state(
                ui,
                if self.loading_ports {
                    "Coletando portas em escuta..."
                } else {
                    "Nenhuma porta em escuta encontrada."
                },
            );
            return;
        }
        if rows.is_empty() {
            empty_state(ui, "Nenhum resultado para o filtro atual.");
            return;
        }

        if let Some(col) = self.ports_sort.col {
            match col {
                0 => rows.sort_by_key(|p| match p.exposure {
                    Exposure::External => 0,
                    Exposure::Other => 1,
                    Exposure::Local => 2,
                }),
                1 => rows.sort_by(|a, b| a.protocol.cmp(&b.protocol)),
                2 => rows.sort_by(|a, b| a.local_addr.cmp(&b.local_addr)),
                3 => rows.sort_by_key(|p| p.port.parse::<u32>().unwrap_or(u32::MAX)),
                4 => rows.sort_by_cached_key(|p| p.process.to_lowercase()),
                5 => rows.sort_by_key(|p| {
                    p.pid
                        .split(',')
                        .next()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .unwrap_or(u32::MAX)
                }),
                6 => rows.sort_by(|a, b| a.state.cmp(&b.state)),
                _ => {}
            }
            if !self.ports_sort.asc {
                rows.reverse();
            }
        }

        let sort = &mut self.ports_sort;
        ui.push_id("ports_table", |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(170.0))
                .column(Column::auto().at_least(50.0))
                .column(Column::auto().at_least(120.0))
                .column(Column::auto().at_least(60.0))
                .column(Column::auto().at_least(140.0))
                .column(Column::auto().at_least(60.0))
                .column(Column::remainder())
                .header(26.0, |mut header| {
                    for (i, t) in [
                        "Exposição",
                        "Proto",
                        "Endereço local",
                        "Porta",
                        "Processo",
                        "PID",
                        "Estado",
                    ]
                    .iter()
                    .enumerate()
                    {
                        header.col(|ui| sort_header(ui, t, i, sort));
                    }
                })
                .body(|body| {
                    body.rows(24.0, rows.len(), |mut row| {
                        let p = rows[row.index()];
                        let (badge_txt, badge_color, addr_color) = match p.exposure {
                            Exposure::External => ("⚠ EXTERNA (0.0.0.0/[::])", RED, AMBER),
                            Exposure::Local => ("● LOCAL", GREEN, MUTED),
                            Exposure::Other => ("◈ INTERFACE", BLUE, BLUE),
                        };
                        row.col(|ui| {
                            ui.label(RichText::new(badge_txt).color(badge_color).strong());
                        });
                        row.col(|ui| {
                            ui.label(&p.protocol);
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&p.local_addr).color(addr_color).monospace());
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(&p.port)
                                    .color(badge_color)
                                    .strong()
                                    .monospace(),
                            );
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&p.process).strong());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&p.pid).monospace());
                        });
                        row.col(|ui| {
                            ui.label(&p.state);
                        });
                        row.response().context_menu(|ui| {
                            if ui.button("Copiar porta").clicked() {
                                ui.ctx().copy_text(p.port.clone());
                                ui.close();
                            }
                            if ui.button("Copiar endereço:porta").clicked() {
                                ui.ctx().copy_text(format!("{}:{}", p.local_addr, p.port));
                                ui.close();
                            }
                            if ui.button("Copiar PID").clicked() {
                                ui.ctx().copy_text(p.pid.clone());
                                ui.close();
                            }
                            if ui.button("Copiar processo").clicked() {
                                ui.ctx().copy_text(p.process.clone());
                                ui.close();
                            }
                        });
                    });
                });
        });
    }

    // ── Aba: Pacotes ──

    fn render_packages_tab(&mut self, ui: &mut egui::Ui) {
        let q = self.filter.trim().to_lowercase();

        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.loading_pkgs,
                    egui::Button::new("Atualizar pacotes (Ctrl+U)"),
                )
                .clicked()
            {
                self.start_pkgs_refresh();
            }
            if self.loading_pkgs {
                ui.spinner();
                ui.label("Consultando checkupdates / AUR...");
            }
        });

        if self.data.packages.is_empty() {
            if !self.loading_pkgs {
                ui.label(RichText::new("Nenhum pacote desatualizado encontrado.").color(GREEN));
            }
        } else {
            ui.label(
                RichText::new(format!(
                    "{} pacote(s) desatualizado(s).",
                    self.data.packages.len()
                ))
                .color(ORANGE)
                .strong(),
            );
        }
        for note in &self.data.package_notes {
            ui.label(RichText::new(format!("• {}", note)).color(MUTED));
        }

        let mut rows: Vec<&PackageEntry> = self
            .data
            .packages
            .iter()
            .filter(|p| q.is_empty() || p.search.contains(&q))
            .collect();

        if !self.data.packages.is_empty() {
            count_label(ui, rows.len(), self.data.packages.len());
        }
        ui.add_space(4.0);

        if self.data.packages.is_empty() {
            return;
        }
        if rows.is_empty() {
            empty_state(ui, "Nenhum resultado para o filtro atual.");
            return;
        }

        if let Some(col) = self.pkgs_sort.col {
            match col {
                0 => rows.sort_by(|a, b| a.source.cmp(&b.source)),
                1 => rows.sort_by_cached_key(|p| p.name.to_lowercase()),
                2 => rows.sort_by(|a, b| a.current_ver.cmp(&b.current_ver)),
                3 => rows.sort_by(|a, b| a.new_ver.cmp(&b.new_ver)),
                _ => {}
            }
            if !self.pkgs_sort.asc {
                rows.reverse();
            }
        }

        let sort = &mut self.pkgs_sort;
        ui.push_id("packages_table", |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(110.0))
                .column(Column::auto().at_least(220.0))
                .column(Column::auto().at_least(150.0))
                .column(Column::remainder())
                .header(26.0, |mut header| {
                    for (i, t) in ["Origem", "Pacote", "Versão atual", "Nova versão"]
                        .iter()
                        .enumerate()
                    {
                        header.col(|ui| sort_header(ui, t, i, sort));
                    }
                })
                .body(|body| {
                    body.rows(24.0, rows.len(), |mut row| {
                        let pkg = rows[row.index()];
                        let src_color = if pkg.source == "Oficial" {
                            ARCH
                        } else {
                            PURPLE
                        };
                        row.col(|ui| {
                            ui.label(RichText::new(&pkg.source).color(src_color).strong());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&pkg.name).strong().monospace());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&pkg.current_ver).monospace());
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(&pkg.new_ver)
                                    .color(GREEN)
                                    .strong()
                                    .monospace(),
                            );
                        });
                        row.response().context_menu(|ui| {
                            if ui.button("Copiar nome do pacote").clicked() {
                                ui.ctx().copy_text(pkg.name.clone());
                                ui.close();
                            }
                            if ui.button("Copiar nova versão").clicked() {
                                ui.ctx().copy_text(pkg.new_ver.clone());
                                ui.close();
                            }
                        });
                    });
                });
        });
    }

    // ── Aba: CVEs ──

    fn render_vulnerabilities_tab(&mut self, ui: &mut egui::Ui) {
        let q = self.filter.trim().to_lowercase();
        let mut url_to_open: Option<String> = None;

        card_frame().show(ui, |ui| {
            ui.strong("Abrir CVE ou pacote diretamente no security.archlinux.org");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.cve_lookup_input)
                        .hint_text("Ex.: CVE-2024-3094 ou openssl")
                        .desired_width(260.0),
                );
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if ui.button("↗ Abrir no navegador").clicked() || enter {
                    let q = self.cve_lookup_input.trim().to_string();
                    if q.is_empty() {
                        self.set_status(
                            "Digite um CVE (ex.: CVE-2024-3094) ou nome de pacote.",
                            true,
                        );
                    } else {
                        url_to_open = Some(ArchCollectors::advisory_url_from_query(&q, &q));
                    }
                }
                if ui
                    .small_button("Exemplo")
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
                    !self.loading_cves,
                    egui::Button::new("Atualizar CVEs (Ctrl+Shift+C)"),
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
            ui.colored_label(MUTED, format!("ℹ {}", note));
        }

        let only_high = self.only_high_cve;
        let mut rows: Vec<&CveVulnerabilityEntry> = self
            .data
            .vulnerabilities
            .iter()
            .filter(|v| !only_high || is_high_severity(&v.severity))
            .filter(|v| q.is_empty() || v.search.contains(&q))
            .collect();

        if !self.data.vulnerabilities.is_empty() {
            count_label(ui, rows.len(), self.data.vulnerabilities.len());
        }
        ui.add_space(4.0);

        if self.data.vulnerabilities.is_empty() {
            empty_state(
                ui,
                if self.loading_cves {
                    "Consultando vulnerabilidades..."
                } else {
                    "Nenhuma vulnerabilidade CVE listada. Use o campo acima ou clique em 'Atualizar CVEs'."
                },
            );
        } else if rows.is_empty() {
            empty_state(ui, "Nenhum resultado para o filtro atual.");
        } else {
            if let Some(col) = self.cves_sort.col {
                match col {
                    0 => rows.sort_by_key(|v| sev_rank(&v.severity)),
                    1 => rows.sort_by_cached_key(|v| v.package.to_lowercase()),
                    2 => rows.sort_by(|a, b| a.status.cmp(&b.status)),
                    3 => rows.sort_by(|a, b| a.fixed_ver.cmp(&b.fixed_ver)),
                    4 => rows.sort_by(|a, b| a.cves.cmp(&b.cves)),
                    _ => {}
                }
                if !self.cves_sort.asc {
                    rows.reverse();
                }
            }

            let sort = &mut self.cves_sort;
            ui.push_id("cves_table", |ui| {
                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::auto().at_least(90.0))
                    .column(Column::auto().at_least(150.0))
                    .column(Column::auto().at_least(130.0))
                    .column(Column::auto().at_least(110.0))
                    .column(Column::auto().at_least(220.0).clip(true))
                    .column(Column::remainder())
                    .header(26.0, |mut header| {
                        for (i, t) in ["Severidade", "Pacote", "Status", "Correção", "CVEs"]
                            .iter()
                            .enumerate()
                        {
                            header.col(|ui| sort_header(ui, t, i, sort));
                        }
                        header.col(|ui| {
                            ui.strong("Advisory");
                        });
                    })
                    .body(|body| {
                        body.rows(24.0, rows.len(), |mut row| {
                            let v = rows[row.index()];
                            let color = sev_color(&v.severity);
                            row.col(|ui| {
                                ui.label(RichText::new(&v.severity).color(color).strong());
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(&v.package).strong().monospace());
                            });
                            row.col(|ui| {
                                ui.label(&v.status);
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(&v.fixed_ver).monospace());
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(&v.cves).color(color).monospace())
                                    .on_hover_text(&v.detail);
                            });
                            row.col(|ui| {
                                let url = ArchCollectors::advisory_url(v);
                                if ui
                                    .small_button("↗ Abrir")
                                    .on_hover_text(format!("Abrir {} via xdg-open", url))
                                    .clicked()
                                {
                                    url_to_open = Some(url);
                                }
                            });
                            row.response().context_menu(|ui| {
                                if ui.button("Copiar pacote").clicked() {
                                    ui.ctx().copy_text(v.package.clone());
                                    ui.close();
                                }
                                if ui.button("Copiar CVEs").clicked() {
                                    ui.ctx().copy_text(v.cves.clone());
                                    ui.close();
                                }
                                if ui.button("Copiar link do advisory").clicked() {
                                    ui.ctx().copy_text(ArchCollectors::advisory_url(v));
                                    ui.close();
                                }
                            });
                        });
                    });
            });
        }

        if let Some(url) = url_to_open {
            match ArchCollectors::open_in_browser(&url) {
                Ok(()) => self.set_status(format!("Abrindo {} via xdg-open...", url), false),
                Err(err) => self.set_status(err, true),
            }
        }
    }

    // ── Aba: WMs / DEs ──

    fn render_desktops_tab(&self, ui: &mut egui::Ui) {
        let q = self.filter.trim().to_lowercase();

        if !self.data.session_summary.is_empty() {
            ui.label(
                RichText::new(&self.data.session_summary)
                    .color(ARCH)
                    .strong(),
            );
        }

        let rows: Vec<&DesktopEntryItem> = self
            .data
            .desktops
            .iter()
            .filter(|d| q.is_empty() || d.search.contains(&q))
            .collect();

        count_label(ui, rows.len(), self.data.desktops.len());
        ui.add_space(4.0);

        if self.data.desktops.is_empty() {
            empty_state(
                ui,
                if self.loading_desktops {
                    "Procurando WMs e ambientes..."
                } else {
                    "Nenhum WM/DE detectado."
                },
            );
            return;
        }
        if rows.is_empty() {
            empty_state(ui, "Nenhum resultado para o filtro atual.");
            return;
        }

        ui.push_id("desktops_table", |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(90.0))
                .column(Column::auto().at_least(180.0))
                .column(Column::auto().at_least(100.0))
                .column(Column::auto().at_least(180.0))
                .column(Column::remainder())
                .header(26.0, |mut header| {
                    for t in ["Status", "Ambiente / WM", "Sessão", "Executável", "Origem"] {
                        header.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|body| {
                    body.rows(24.0, rows.len(), |mut row| {
                        let d = rows[row.index()];
                        row.col(|ui| {
                            if d.active {
                                ui.label(RichText::new("★ ATIVA").color(GREEN).strong());
                            } else {
                                ui.label(RichText::new("Instalado").color(MUTED));
                            }
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&d.name).strong());
                        });
                        row.col(|ui| {
                            ui.label(&d.session_type);
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&d.binary).monospace());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&d.source_path).color(MUTED));
                        });
                    });
                });
        });
    }

    // ── Aba: AppImages ──

    fn render_appimages_tab(&mut self, ui: &mut egui::Ui) {
        let q = self.filter.trim().to_lowercase();
        let mut request_install: Option<String> = None;

        card_frame().show(ui, |ui| {
            ui.strong("Instalar AppImage local em ~/Applications (+x)");
            ui.label(
                RichText::new("Dica: arraste um arquivo .AppImage para a janela.")
                    .color(MUTED)
                    .small(),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.appimage_source_input)
                        .hint_text("/caminho/para/aplicativo.AppImage")
                        .desired_width(380.0),
                );
                if ui
                    .add_enabled(
                        !self.loading_action,
                        egui::Button::new("⬇ Instalar AppImage"),
                    )
                    .clicked()
                {
                    request_install = Some(
                        self.appimage_source_input
                            .trim()
                            .trim_matches('"')
                            .to_string(),
                    );
                }
            });
        });

        if let Some(src) = request_install {
            if src.is_empty() {
                self.set_status("Informe o caminho de um arquivo .AppImage.", true);
            } else {
                self.confirm = Some(Confirm::AppImage(src));
            }
        }

        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Diretórios monitorados: ~/Applications, ~/Downloads, ~/Desktop, ~/.local/bin e /opt",
            )
            .color(MUTED),
        );

        let rows: Vec<&AppImageEntry> = self
            .data
            .appimages
            .iter()
            .filter(|a| q.is_empty() || a.search.contains(&q))
            .collect();

        count_label(ui, rows.len(), self.data.appimages.len());
        ui.add_space(4.0);

        let mut chmod_target: Option<String> = None;
        let mut run_target: Option<String> = None;
        let mut delete_target: Option<String> = None;

        if self.data.appimages.is_empty() {
            empty_state(
                ui,
                if self.loading_appimages {
                    "Procurando AppImages..."
                } else {
                    "Nenhum .AppImage encontrado nos diretórios monitorados."
                },
            );
        } else if rows.is_empty() {
            empty_state(ui, "Nenhum resultado para o filtro atual.");
        } else {
            ui.push_id("appimages_table", |ui| {
                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::auto().at_least(130.0))
                    .column(Column::auto().at_least(200.0))
                    .column(Column::auto().at_least(80.0))
                    .column(Column::auto().at_least(260.0).clip(true))
                    .column(Column::remainder())
                    .header(26.0, |mut header| {
                        for t in [
                            "Permissão",
                            "Arquivo",
                            "Tamanho",
                            "Caminho completo",
                            "Ação",
                        ] {
                            header.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(26.0, rows.len(), |mut row| {
                            let app = rows[row.index()];
                            row.col(|ui| {
                                if app.executable {
                                    ui.label(RichText::new("✔ Executável").color(GREEN).strong());
                                } else {
                                    ui.label(RichText::new("✖ Sem +x").color(ORANGE).strong());
                                }
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(&app.name).strong());
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(&app.size_human).monospace());
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(&app.path).monospace());
                            });
                            row.col(|ui| {
                                if app.executable {
                                    if ui.small_button("Executar").clicked() {
                                        run_target = Some(app.path.clone());
                                    }
                                } else if ui.small_button("Habilitar +x").clicked() {
                                    chmod_target = Some(app.path.clone());
                                }
                                if ui.small_button("Excluir").clicked() {
                                    delete_target = Some(app.path.clone());
                                }
                            });
                            row.response().context_menu(|ui| {
                                if app.executable && ui.button("Executar").clicked() {
                                    run_target = Some(app.path.clone());
                                    ui.close();
                                }
                                if ui.button("Excluir...").clicked() {
                                    delete_target = Some(app.path.clone());
                                    ui.close();
                                }
                                ui.separator();
                                if ui.button("Copiar caminho").clicked() {
                                    ui.ctx().copy_text(app.path.clone());
                                    ui.close();
                                }
                                if ui.button("Copiar nome").clicked() {
                                    ui.ctx().copy_text(app.name.clone());
                                    ui.close();
                                }
                            });
                        });
                    });
            });
        }

        if let Some(p) = run_target {
            self.run_appimage_now(&p);
        }
        if let Some(p) = chmod_target {
            self.start_chmod_appimage(p);
        }
        if let Some(p) = delete_target {
            self.confirm = Some(Confirm::DeleteAppImage { path: p });
        }
    }

    // ── Aba: Flatpaks ──

    fn render_flatpaks_tab(&mut self, ui: &mut egui::Ui) {
        let q = self.filter.trim().to_lowercase();
        let mut request_install: Option<(String, String, bool)> = None;

        card_frame().show(ui, |ui| {
            ui.strong("Instalar aplicativo Flatpak");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.flatpak_id_input)
                        .hint_text("Application ID (ex.: org.mozilla.firefox)")
                        .desired_width(280.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.flatpak_remote_input)
                        .hint_text("Remote (ex.: flathub)")
                        .desired_width(130.0),
                );
                ui.checkbox(&mut self.flatpak_user_scope, "Escopo --user");
                if ui
                    .add_enabled(!self.loading_action, egui::Button::new("Instalar Flatpak"))
                    .clicked()
                {
                    request_install = Some((
                        self.flatpak_id_input.trim().to_string(),
                        self.flatpak_remote_input.trim().to_string(),
                        self.flatpak_user_scope,
                    ));
                }
            });
        });

        if let Some((app_id, remote, user_scope)) = request_install {
            let remote = if remote.is_empty() {
                "flathub".to_string()
            } else {
                remote
            };
            if app_id.is_empty() {
                self.set_status(
                    "Informe um Application ID válido (ex.: org.mozilla.firefox).",
                    true,
                );
            } else if !valid_flatpak_token(&app_id) || !valid_flatpak_token(&remote) {
                self.set_status(
                    "Application ID/remote inválido: use apenas letras, números, '.', '_' e '-'.",
                    true,
                );
            } else {
                self.confirm = Some(Confirm::Flatpak {
                    app_id,
                    remote,
                    user_scope,
                });
            }
        }

        ui.add_space(6.0);

        if let Some(note) = &self.data.flatpak_note {
            ui.label(RichText::new(note).color(MUTED));
        } else {
            ui.label(
                RichText::new(format!(
                    "{} aplicativo(s) Flatpak instalado(s).",
                    self.data.flatpaks.len()
                ))
                .strong(),
            );
        }

        let rows: Vec<&FlatpakEntry> = self
            .data
            .flatpaks
            .iter()
            .filter(|f| q.is_empty() || f.search.contains(&q))
            .collect();

        if !self.data.flatpaks.is_empty() {
            count_label(ui, rows.len(), self.data.flatpaks.len());
        }
        ui.add_space(4.0);

        if self.data.flatpaks.is_empty() {
            if self.loading_flatpaks {
                empty_state(ui, "Consultando Flatpaks...");
            }
            return;
        }
        if rows.is_empty() {
            empty_state(ui, "Nenhum resultado para o filtro atual.");
            return;
        }

        let mut run_flatpak: Option<String> = None;
        let mut uninstall_flatpak: Option<(String, String, String)> = None; // (id, nome, escopo)

        ui.push_id("flatpaks_table", |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(160.0))
                .column(Column::auto().at_least(240.0))
                .column(Column::auto().at_least(90.0))
                .column(Column::auto().at_least(80.0))
                .column(Column::auto().at_least(100.0))
                .column(Column::auto().at_least(80.0))
                .column(Column::remainder())
                .header(26.0, |mut header| {
                    for t in [
                        "Nome",
                        "Application ID",
                        "Versão",
                        "Branch",
                        "Repositório",
                        "Escopo",
                        "Ações",
                    ] {
                        header.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|body| {
                    body.rows(24.0, rows.len(), |mut row| {
                        let fp = rows[row.index()];
                        row.col(|ui| {
                            ui.label(RichText::new(&fp.name).strong());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&fp.app_id).monospace());
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&fp.version).monospace());
                        });
                        row.col(|ui| {
                            ui.label(&fp.branch);
                        });
                        row.col(|ui| {
                            ui.label(&fp.origin);
                        });
                        row.col(|ui| {
                            ui.label(&fp.installation);
                        });
                        row.col(|ui| {
                            if ui.small_button("Executar").clicked() {
                                run_flatpak = Some(fp.app_id.clone());
                            }
                            if ui.small_button("Desinstalar").clicked() {
                                uninstall_flatpak = Some((
                                    fp.app_id.clone(),
                                    fp.name.clone(),
                                    fp.installation.clone(),
                                ));
                            }
                        });
                        row.response().context_menu(|ui| {
                            if ui.button("Executar").clicked() {
                                run_flatpak = Some(fp.app_id.clone());
                                ui.close();
                            }
                            if ui.button("Desinstalar...").clicked() {
                                uninstall_flatpak = Some((
                                    fp.app_id.clone(),
                                    fp.name.clone(),
                                    fp.installation.clone(),
                                ));
                                ui.close();
                            }
                            ui.separator();
                            if ui.button("Copiar Application ID").clicked() {
                                ui.ctx().copy_text(fp.app_id.clone());
                                ui.close();
                            }
                            if ui.button("Copiar nome").clicked() {
                                ui.ctx().copy_text(fp.name.clone());
                                ui.close();
                            }
                        });
                    });
                });
        });

        if let Some(id) = run_flatpak {
            self.run_flatpak_now(&id);
        }
        if let Some((app_id, name, installation)) = uninstall_flatpak {
            self.confirm = Some(Confirm::UninstallFlatpak {
                app_id,
                name,
                installation,
            });
        }
    }

    // ── Diálogo de confirmação ──

    fn render_confirm(&mut self, ctx: &egui::Context) {
        let Some(confirm) = self.confirm.clone() else {
            return;
        };

        let (title, body) = match &confirm {
            Confirm::AppImage(path) => (
                "Instalar AppImage",
                format!(
                    "Copiar o arquivo abaixo para ~/Applications e torná-lo executável (+x)?\n\n{}",
                    path
                ),
            ),
            Confirm::Flatpak {
                app_id,
                remote,
                user_scope,
            } => (
                "Instalar Flatpak",
                format!(
                    "Instalar '{}' a partir de '{}' no escopo {}?{}",
                    app_id,
                    remote,
                    if *user_scope { "usuário" } else { "sistema" },
                    if *user_scope {
                        ""
                    } else {
                        "\n\nO escopo de sistema pode exigir autenticação (polkit)."
                    }
                ),
            ),
            Confirm::DeleteAppImage { path } => (
                "Excluir AppImage",
                format!(
                    "Excluir este arquivo? Ele vai para a lixeira se o 'gio' estiver disponível; caso contrário será apagado de vez.\n\n{}",
                    path
                ),
            ),
            Confirm::UninstallFlatpak {
                app_id,
                name,
                installation,
            } => (
                "Desinstalar Flatpak",
                format!(
                    "Desinstalar '{}' ({}) do escopo '{}'?\n\nOs dados do usuário em ~/.var/app são mantidos.",
                    name, app_id, installation
                ),
            ),
        };

        let mut decision: Option<bool> = None;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.label(body);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Confirmar").clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancelar (Esc)").clicked() {
                        decision = Some(false);
                    }
                });
            });

        match decision {
            Some(true) => {
                self.confirm = None;
                match confirm {
                    Confirm::AppImage(path) => self.start_install_appimage(path),
                    Confirm::Flatpak {
                        app_id,
                        remote,
                        user_scope,
                    } => self.start_install_flatpak(app_id, remote, user_scope),
                    Confirm::DeleteAppImage { path } => self.start_delete_appimage(path),
                    Confirm::UninstallFlatpak {
                        app_id,
                        installation,
                        ..
                    } => self.start_uninstall_flatpak(app_id, installation),
                }
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }
}

impl eframe::App for ArchAuditorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let filter_id = egui::Id::new("search_filter_input");

        self.poll_worker();
        self.handle_dropped_files(&ctx);
        self.handle_shortcuts(&ctx, filter_id);
        self.maybe_auto_refresh_ports(&ctx);
        self.expire_status(&ctx);

        let any_busy = self.any_busy();

        egui::Panel::top("top_panel").show(ui, |ui| {
            ui.add_space(6.0);

            // Linha 1: título + ações
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("ARCH VISUAL AUDITOR")
                        .color(ARCH)
                        .strong()
                        .size(16.0),
                );
                if !self.data.session_summary.is_empty() {
                    ui.label(
                        RichText::new(&self.data.session_summary)
                            .color(MUTED)
                            .small(),
                    );
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!any_busy, egui::Button::new("Exportar (Ctrl+E)"))
                        .on_hover_text("Salva um .md em ~/ e copia para a área de transferência")
                        .clicked()
                    {
                        self.trigger_export(&ctx);
                    }

                    ui.add_enabled_ui(!any_busy, |ui| {
                        ui.menu_button("↻ Atualizar", |ui| {
                            if ui.button("Tudo (F5)").clicked() {
                                self.start_full_refresh(false);
                                ui.close();
                            }
                            ui.separator();
                            if ui.button("Portas").clicked() {
                                self.start_ports_refresh();
                                ui.close();
                            }
                            if ui.button("Pacotes (Ctrl+U)").clicked() {
                                self.start_pkgs_refresh();
                                ui.close();
                            }
                            if ui.button("CVEs (Ctrl+Shift+C)").clicked() {
                                self.start_cve_refresh(true);
                                ui.close();
                            }
                            if ui.button("WMs e ambientes").clicked() {
                                self.start_desktops_refresh();
                                ui.close();
                            }
                            if ui.button("AppImages").clicked() {
                                self.start_appimages_refresh();
                                ui.close();
                            }
                            if ui.button("Flatpaks").clicked() {
                                self.start_flatpaks_refresh();
                                ui.close();
                            }
                        });
                    });

                    if any_busy {
                        ui.spinner();
                    }
                });
            });

            ui.add_space(6.0);

            // Linha 2: cards (que também funcionam como abas) + busca
            ui.horizontal(|ui| {
                for tab in ActiveTab::ALL {
                    self.render_tab_card(ui, tab);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Limpar (Esc)").clicked() {
                        self.filter.clear();
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .id(filter_id)
                            .hint_text("Buscar nesta aba (Ctrl+F)...")
                            .desired_width(240.0),
                    );
                });
            });
            ui.add_space(4.0);
        });

        let updated_txt = if self.data.last_updated_unix == 0 {
            "—".to_string()
        } else {
            format!(
                "Atualizado {}",
                fmt_ago(ArchCollectors::now_unix().saturating_sub(self.data.last_updated_unix))
            )
        };

        egui::Panel::bottom("bottom_status_panel").show(ui, |ui| {
            ui.horizontal(|ui| {
                match &self.status {
                    Some(s) => {
                        let color = if s.is_error { RED } else { MUTED };
                        ui.label(RichText::new(&s.text).color(color));
                    }
                    None => {
                        ui.label(
                            RichText::new(
                                "Ctrl+F buscar · Ctrl+1…6 abas · F5 atualizar tudo · Ctrl+U pacotes · Ctrl+Shift+C CVEs · Ctrl+E exportar",
                            )
                            .color(MUTED),
                        );
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(updated_txt).color(MUTED));
                });
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

        self.render_confirm(&ctx);

        // Mantém o "Atualizado há ..." fresco sem consumir CPU.
        ctx.request_repaint_after(Duration::from_secs(15));
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        let b = |v: bool| if v { "1".to_string() } else { "0".to_string() };
        storage.set_string("tab", self.active_tab.key().to_string());
        storage.set_string("only_external", b(self.only_external_ports));
        storage.set_string("only_high", b(self.only_high_cve));
        storage.set_string("auto_ports", b(self.auto_refresh_ports));
        storage.set_string("flatpak_user", b(self.flatpak_user_scope));
        storage.set_string("flatpak_remote", self.flatpak_remote_input.clone());
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 760.0])
            .with_min_inner_size([980.0, 520.0])
            .with_title("Arch Linux Visual System Auditor"),
        ..Default::default()
    };

    eframe::run_native(
        "Arch Linux Visual System Auditor",
        options,
        Box::new(|cc| Ok(Box::new(ArchAuditorApp::new(cc)))),
    )
}

// ───────────────────────────── Testes ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_addr_port_cases() {
        assert_eq!(
            ArchCollectors::split_addr_port("[::]:22"),
            ("[::]".to_string(), "22".to_string())
        );
        assert_eq!(
            ArchCollectors::split_addr_port("0.0.0.0:80"),
            ("0.0.0.0".to_string(), "80".to_string())
        );
        assert_eq!(
            ArchCollectors::split_addr_port("*:631"),
            ("*".to_string(), "631".to_string())
        );
    }

    #[test]
    fn classify_bind_cases() {
        assert_eq!(ArchCollectors::classify_bind("0.0.0.0"), Exposure::External);
        assert_eq!(ArchCollectors::classify_bind("[::]"), Exposure::External);
        assert_eq!(ArchCollectors::classify_bind("127.0.0.1"), Exposure::Local);
        assert_eq!(ArchCollectors::classify_bind("[::1]"), Exposure::Local);
        assert_eq!(
            ArchCollectors::classify_bind("192.168.0.10"),
            Exposure::Other
        );
    }

    #[test]
    fn parse_arch_audit_with_fix() {
        let e = ArchCollectors::parse_arch_audit_line(
            "Package openssl is affected by CVE-2024-0001, CVE-2024-0002. High risk! Update to 3.0.1-1!",
        )
        .expect("deve parsear");
        assert_eq!(e.package, "openssl");
        assert_eq!(e.severity, "High");
        assert_eq!(e.status, "Correção disponível");
        assert_eq!(e.fixed_ver, "3.0.1-1");
        assert!(e.cves.contains("CVE-2024-0001"));
    }

    #[test]
    fn parse_arch_audit_without_fix() {
        let e = ArchCollectors::parse_arch_audit_line(
            "Package linux is affected by CVE-2024-1111. Medium risk!",
        )
        .expect("deve parsear");
        assert_eq!(e.package, "linux");
        assert_eq!(e.severity, "Medium");
        assert_eq!(e.status, "Vulnerável");
        assert_eq!(e.fixed_ver, "Sem correção");
    }

    #[test]
    fn decode_proc_addresses() {
        // 127.0.0.1 aparece como "0100007F" em /proc/net/tcp (little-endian)
        if cfg!(target_endian = "little") {
            assert_eq!(ArchCollectors::decode_ipv4("0100007F"), "127.0.0.1");
        }
        assert_eq!(
            ArchCollectors::decode_ipv6("00000000000000000000000000000000"),
            "[::]"
        );
    }
}
