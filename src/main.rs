use eframe::egui::{self, Color32, RichText};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

// =====================================================================
// MODELOS DE DADOS
// =====================================================================

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Ports,
    Packages,
    Desktops,
    AppImages,
    Flatpaks,
}

// =====================================================================
// CAMADA DE COLETORES (ARCH LINUX)
// =====================================================================

struct ArchCollectors;

impl ArchCollectors {
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

    fn collect_all() -> AuditSnapshot {
        let (ports, ports_warning) = Self::collect_open_ports();
        let (desktops, session_summary) = Self::collect_wms_and_des();
        let appimages = Self::collect_appimages();
        let (flatpaks, flatpak_note) = Self::collect_flatpaks();
        let (packages, package_notes) = Self::collect_outdated_packages();

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
        }
    }
}

unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

// =====================================================================
// INTERFACE GRÁFICA (EFRAME / EGUI)
// =====================================================================

struct ArchAuditorApp {
    data: AuditSnapshot,
    active_tab: ActiveTab,
    filter: String,
    only_external_ports: bool,
    loading: bool,
    rx: Option<Receiver<AuditSnapshot>>,
}

impl ArchAuditorApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(15, 20, 25);
        visuals.window_fill = Color32::from_rgb(15, 20, 25);
        cc.egui_ctx.set_visuals(visuals);

        let mut app = Self {
            data: AuditSnapshot::default(),
            active_tab: ActiveTab::Ports,
            filter: String::new(),
            only_external_ports: false,
            loading: false,
            rx: None,
        };
        app.start_refresh();
        app
    }

    fn start_refresh(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.loading = true;

        thread::spawn(move || {
            let snap = ArchCollectors::collect_all();
            let _ = tx.send(snap);
        });
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.rx {
            if let Ok(snap) = rx.try_recv() {
                self.data = snap;
                self.loading = false;
                self.rx = None;
            } else if self.loading {
                ctx.request_repaint_after(Duration::from_millis(120));
            }
        }
    }

    fn matches_filter(&self, haystack: &str) -> bool {
        let q = self.filter.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        haystack.to_lowercase().contains(&q)
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

    fn render_packages_tab(&self, ui: &mut egui::Ui) {
        if self.data.packages.is_empty() {
            ui.label(
                RichText::new(
                    "Nenhum pacote desatualizado encontrado ou verificação ainda sem pendências.",
                )
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

    fn render_appimages_tab(&self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("Diretórios verificados: ~/Applications, ~/Downloads, ~/Desktop, ~/.local/bin e /opt")
                .color(Color32::from_rgb(139, 148, 158)),
        );
        ui.add_space(6.0);

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("appimages_grid")
                .striped(true)
                .spacing([14.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Permissão (+x)", "Arquivo", "Tamanho", "Caminho Completo"] {
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
                        ui.end_row();
                    }
                });
        });
    }

    fn render_flatpaks_tab(&self, ui: &mut egui::Ui) {
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

        let external_count = self
            .data
            .ports
            .iter()
            .filter(|p| p.exposure == Exposure::External)
            .count();

        egui::Panel::top("top_panel").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("ARCH VISUAL AUDITOR")
                        .color(Color32::from_rgb(23, 147, 209))
                        .strong()
                        .size(16.0),
                );
                ui.separator();

                let exp_color = if external_count > 0 {
                    Color32::from_rgb(255, 123, 114)
                } else {
                    Color32::from_rgb(63, 185, 80)
                };
                ui.label(
                    RichText::new(format!("Externas (0.0.0.0/[::]): {}", external_count))
                        .color(exp_color)
                        .strong(),
                );
                ui.separator();
                ui.label(format!("Updates: {}", self.data.packages.len()));
                ui.separator();
                ui.label(format!("WMs/DEs: {}", self.data.desktops.len()));
                ui.separator();
                ui.label(format!("AppImages: {}", self.data.appimages.len()));
                ui.separator();
                ui.label(format!("Flatpaks: {}", self.data.flatpaks.len()));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.loading, egui::Button::new("↻ Atualizar"))
                        .clicked()
                    {
                        self.start_refresh();
                    }
                    if self.loading {
                        ui.spinner();
                        ui.label("Coletando...");
                    }
                });
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, ActiveTab::Ports, "Portas Abertas");
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::Packages,
                    "Pacotes Desatualizados",
                );
                ui.selectable_value(&mut self.active_tab, ActiveTab::Desktops, "WMs & Ambientes");
                ui.selectable_value(&mut self.active_tab, ActiveTab::AppImages, "AppImages");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Flatpaks, "Flatpaks");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Limpar").clicked() {
                        self.filter.clear();
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .hint_text("Filtrar na aba atual...")
                            .desired_width(240.0),
                    );
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ui, |ui| match self.active_tab {
            ActiveTab::Ports => self.render_ports_tab(ui),
            ActiveTab::Packages => self.render_packages_tab(ui),
            ActiveTab::Desktops => self.render_desktops_tab(ui),
            ActiveTab::AppImages => self.render_appimages_tab(ui),
            ActiveTab::Flatpaks => self.render_flatpaks_tab(ui),
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1060.0, 680.0])
            .with_min_inner_size([720.0, 440.0])
            .with_title("Arch Linux Visual System Auditor (eframe)"),
        ..Default::default()
    };

    eframe::run_native(
        "Arch Linux Visual System Auditor",
        options,
        Box::new(|cc| Ok(Box::new(ArchAuditorApp::new(cc)))),
    )
}
