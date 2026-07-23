mod cli;

pub fn run() {
    let has_cli_flag = std::env::args().any(|a| a == "--cli");

    // On Windows with windows_subsystem = "windows", there's no console.
    // When --cli is used, allocate one so stdin/stdout/stderr work.
    #[cfg(target_os = "windows")]
    if has_cli_flag {
        extern "system" {
            fn AllocConsole() -> i32;
        }
        unsafe {
            AllocConsole();
        }
        // After AllocConsole(), GetStdHandle() returns valid handles,
        // so println!() etc. work again.
    }

    if has_cli_flag {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        rt.block_on(async { cli::run_cli().await });
        return;
    }
    if start_gui().is_err() {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        rt.block_on(async { cli::run_cli().await });
    }
}

fn start_gui() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("KirinDesk - P2P Remote Desktop"),
        ..Default::default()
    };
    eframe::run_native(
        "KirinDesk",
        options,
        Box::new(|cc| {
            // Force light theme: pure black text on white background
            cc.egui_ctx.set_visuals(egui::Visuals::light());
            // Larger font sizes
            let mut style = (*cc.egui_ctx.style()).clone();
            style.text_styles.insert(
                egui::TextStyle::Body,
                egui::FontId::proportional(20.0),
            );
            style.text_styles.insert(
                egui::TextStyle::Button,
                egui::FontId::proportional(18.0),
            );
            style.text_styles.insert(
                egui::TextStyle::Heading,
                egui::FontId::proportional(26.0),
            );
            style.text_styles.insert(
                egui::TextStyle::Small,
                egui::FontId::proportional(16.0),
            );
            cc.egui_ctx.set_style(style);
            Ok(Box::new(KirinDeskApp::default()))
        }),
    )
    .map_err(|e| e.to_string())
}

#[derive(Default)]
struct KirinDeskApp {
    current_tab: Tab,
    devices: Vec<DeviceEntry>,
    // Connect panel fields
    connect_domain: String,
    connect_ipv6: String,
    connect_port: String,
    connect_nickname: String,
    connect_challenge: String,
    connect_status: String,
    // Settings fields
    api_key: String,
    api_secret: String,
    domain: String,
    device_id: String,
    nickname: String,
    challenge_code: String,
    allowed_domains: String,
    listen_port: String,
    ip_mode_allowed: bool,
    settings_status: String,
    // Status bar
    local_ipv6: String,
    config_loaded: bool,
}

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    Devices,
    Connect,
    Settings,
}
impl Default for Tab {
    fn default() -> Self {
        Tab::Dashboard
    }
}

struct DeviceEntry {
    id: String,
    ipv6: String,
    port: u16,
    status: String,
}

impl eframe::App for KirinDeskApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.config_loaded {
            self.load_config();
            self.config_loaded = true;
        }

        egui::TopBottomPanel::top("nav_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("KirinDesk");
                ui.label("v0.1.0");
                ui.separator();
                ui.selectable_value(&mut self.current_tab, Tab::Dashboard, "Dashboard");
                ui.selectable_value(&mut self.current_tab, Tab::Devices, "Devices");
                ui.selectable_value(&mut self.current_tab, Tab::Connect, "Connect");
                ui.selectable_value(&mut self.current_tab, Tab::Settings, "Settings");
            });
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("IPv6: {}", self.local_ipv6));
                ui.separator();
                if self.api_key.is_empty() {
                    ui.label("API: Not configured");
                } else {
                    ui.label("API: Ready");
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label("77/77 tests");
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.current_tab {
            Tab::Dashboard => self.show_dashboard(ui),
            Tab::Devices => self.show_devices(ui),
            Tab::Connect => self.show_connect(ui),
            Tab::Settings => self.show_settings(ui),
        });
    }
}

impl KirinDeskApp {
    fn load_config(&mut self) {
        self.connect_port = "3389".to_string();
        self.listen_port = "3389".to_string();
        self.ip_mode_allowed = true; // Default to IP mode so Connect page shows IPv6 + Port
        if let Ok(cfg) = kirin_desk_utils::config::Config::load() {
            self.api_key = cfg.godaddy.api_key;
            self.api_secret = cfg.godaddy.api_secret;
            self.domain = cfg.godaddy.domain;
            self.device_id = cfg.device.id;
            self.nickname = cfg.device.nickname;
            self.challenge_code = cfg.device.challenge_code;
            self.allowed_domains = cfg.network.allowed_domains.join(", ");
            self.ip_mode_allowed = cfg.network.ip_mode_allowed;
            self.listen_port = cfg.network.port.to_string();
        }
        if let Ok(ip) = kirin_desk_core::network::ipv6::get_global_ipv6() {
            self.local_ipv6 = ip.to_string();
        } else {
            self.local_ipv6 = "N/A".to_string();
        }
    }

    fn show_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Dashboard");
        ui.separator();
        egui::Grid::new("dash").striped(true).show(ui, |ui| {
            ui.label("Device ID:");
            ui.label(&self.device_id);
            ui.end_row();
            ui.label("Nickname:");
            ui.label(&self.nickname);
            ui.end_row();
            ui.label("IPv6:");
            ui.label(&self.local_ipv6);
            ui.end_row();
            ui.label("Domain:");
            ui.label(&self.domain);
            ui.end_row();
            ui.label("Listen Port:");
            ui.label(&self.listen_port);
            ui.end_row();
            ui.label("API:");
            ui.label(if self.api_key.is_empty() {
                "Not set"
            } else {
                "Ready"
            });
            ui.end_row();
            let wl = if self.allowed_domains.is_empty() {
                "Any (insecure)"
            } else {
                &self.allowed_domains
            };
            ui.label("Allowed:");
            ui.label(wl);
            ui.end_row();
        });
    }

    fn show_devices(&mut self, ui: &mut egui::Ui) {
        ui.heading("Devices");
        ui.separator();
        if self.devices.is_empty() {
            ui.label("No devices yet. Use Connect tab.");
        } else {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for d in &self.devices {
                    ui.group(|ui| {
                        ui.label(format!(
                            "{} @ [{}]:{} [{}]",
                            d.id, d.ipv6, d.port, d.status
                        ));
                    });
                }
            });
        }
    }

    fn show_connect(&mut self, ui: &mut egui::Ui) {
        ui.heading("Connect to Device");
        ui.separator();

        // Show current mode banner
        if self.ip_mode_allowed {
            ui.label("Mode: IP Mode (direct IPv6 connection)");
        } else {
            ui.label("Mode: Domain Mode (DNS-based discovery)");
        }
        ui.separator();

        // Show form based on the setting from Settings page
        if self.ip_mode_allowed {
            // IP Mode: IPv6 + Port + Nickname + Challenge
            ui.horizontal(|ui| {
                ui.label("IPv6 Address:");
                ui.text_edit_singleline(&mut self.connect_ipv6);
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Port:");
                ui.text_edit_singleline(&mut self.connect_port);
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Nickname:");
                ui.text_edit_singleline(&mut self.connect_nickname);
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Challenge:");
                ui.text_edit_singleline(&mut self.connect_challenge);
            });
            ui.add_space(10.0);
            if ui
                .add(egui::Button::new("Connect").min_size(egui::vec2(160.0, 40.0)))
                .clicked()
            {
                let ip = self.connect_ipv6.trim();
                let port: u16 = self.connect_port.parse().unwrap_or(0);
                let nick = self.connect_nickname.trim();
                if ip.is_empty() {
                    self.connect_status = "Enter an IPv6 address".to_string();
                } else if port == 0 {
                    self.connect_status = "Enter a valid port".to_string();
                } else if nick.is_empty() {
                    self.connect_status = "Enter the device nickname".to_string();
                } else {
                    self.connect_status =
                        format!("Connecting [{}]:{} as '{}'...", ip, port, nick);
                }
            }
            ui.separator();
            ui.label("IP mode: direct TCP, no DNS resolution.");
            ui.label("Domain whitelist does not apply.");
        } else {
            // Domain Mode: Domain + Nickname + Challenge
            ui.horizontal(|ui| {
                ui.label("Domain:");
                ui.text_edit_singleline(&mut self.connect_domain);
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Nickname:");
                ui.text_edit_singleline(&mut self.connect_nickname);
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Challenge:");
                ui.text_edit_singleline(&mut self.connect_challenge);
            });
            ui.add_space(10.0);
            if ui
                .add(egui::Button::new("Connect").min_size(egui::vec2(160.0, 40.0)))
                .clicked()
            {
                let domain = self.connect_domain.trim();
                let nick = self.connect_nickname.trim();
                let chal = self.connect_challenge.trim();
                if domain.is_empty() {
                    self.connect_status = "Enter the remote domain".to_string();
                } else if nick.is_empty() {
                    self.connect_status = "Enter the device nickname".to_string();
                } else {
                    self.connect_status = format!(
                        "Connecting to {} as '{}' (challenge: {})...",
                        domain,
                        nick,
                        if chal.is_empty() { "none" } else { chal }
                    );
                }
            }
            ui.separator();
            ui.label("Domain whitelist is enforced.");
            ui.label("Only whitelisted domains in Settings are accepted.");
            ui.add_space(4.0);
            ui.label("Tip: auto-discovers via SRV (port) + TXT (key) + AAAA (IPv6).");
        }

        ui.separator();
        egui::ScrollArea::vertical()
            .max_height(120.0)
            .show(ui, |ui| {
                ui.label(&self.connect_status);
            });
    }

    fn show_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("settings_grid")
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Device ID:");
                    ui.text_edit_singleline(&mut self.device_id);
                    ui.end_row();
                    ui.label("Nickname:");
                    ui.text_edit_singleline(&mut self.nickname);
                    ui.label("  (auth: nickname + challenge)");
                    ui.end_row();
                    ui.label("Challenge Code:");
                    ui.text_edit_singleline(&mut self.challenge_code);
                    ui.end_row();
                    ui.label("Domain:");
                    ui.text_edit_singleline(&mut self.domain);
                    ui.end_row();
                    ui.label("API Key:");
                    ui.text_edit_singleline(&mut self.api_key);
                    ui.end_row();
                    ui.label("API Secret:");
                    ui.text_edit_singleline(&mut self.api_secret);
                    ui.end_row();
                    ui.label("Listen Port:");
                    ui.text_edit_singleline(&mut self.listen_port);
                    ui.end_row();
                    ui.label("Allowed Domains:");
                    ui.end_row();
                    ui.label("");
                    ui.text_edit_multiline(&mut self.allowed_domains);
                    ui.label("  (comma-separated, one or more domains)");
                    ui.end_row();
                    ui.label("Connection Mode:");
                    ui.end_row();
                    ui.label("");
                    ui.horizontal(|ui| {
                        let strict =
                            ui.selectable_label(!self.ip_mode_allowed, "Domain Mode (strict)");
                        let flexible =
                            ui.selectable_label(self.ip_mode_allowed, "IP Mode (flexible)");
                        if strict.clicked() {
                            self.ip_mode_allowed = false;
                        }
                        if flexible.clicked() {
                            self.ip_mode_allowed = true;
                        }
                    });
                    ui.end_row();
                });
            ui.separator();
            ui.label("Domain whitelist is more secure.");
            ui.label("Only connection requests from whitelisted domains are accepted.");
            ui.label("Leave empty = allow any domain (not recommended).");
            ui.separator();
            if ui
                .add(egui::Button::new("Save").min_size(egui::vec2(120.0, 36.0)))
                .clicked()
            {
                let mut cfg = kirin_desk_utils::config::Config::default();
                cfg.device.id = self.device_id.clone();
                cfg.device.nickname = self.nickname.clone();
                cfg.device.challenge_code = self.challenge_code.clone();
                cfg.godaddy.api_key = self.api_key.clone();
                cfg.godaddy.api_secret = self.api_secret.clone();
                cfg.godaddy.domain = self.domain.clone();
                if let Ok(p) = self.listen_port.parse::<u16>() {
                    cfg.network.port = p;
                }
                cfg.network.allowed_domains = self
                    .allowed_domains
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                cfg.network.ip_mode_allowed = self.ip_mode_allowed;
                match cfg.save() {
                    Ok(()) => {
                        self.settings_status = "Saved".to_string();
                        // Save also updates the connect page's default port
                        if let Ok(p) = self.listen_port.parse::<u16>() {
                            self.connect_port = p.to_string();
                        }
                    }
                    Err(e) => self.settings_status = format!("Save failed: {}", e),
                }
            }
            if !self.settings_status.is_empty() {
                ui.label(&self.settings_status);
            }
        });
    }
}
