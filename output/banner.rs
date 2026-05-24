use crate::models::AppConfig;
use colored::*;

pub fn print_banner() {
    println!();
    println!("{}", "  ██████╗  ███████╗ ███████╗ ███████╗ ███████╗  ██████╗ ██╗   ██╗ ██████╗  ██╗ ████████╗ ██╗   ██╗".cyan().bold());
    println!("{}", "  ██╔═══██╗ ██╔════╝ ██╔════╝ ██╔════╝ ██╔════╝ ██╔════╝ ██║   ██║ ██╔══██╗ ██║ ╚══██╔══╝ ╚██╗ ██╔╝".cyan());
    println!("{}", "  ██║   ██║ █████╗   █████╗   ███████╗ █████╗   ██║      ██║   ██║ ██████╔╝ ██║    ██║     ╚████╔╝".cyan());
    println!("{}", "  ██║   ██║ ██╔══╝   ██╔══╝   ╚════██║ ██╔══╝   ██║      ██║   ██║ ██╔══██╗ ██║    ██║      ╚██╔╝".bright_blue());
    println!("{}", "  ╚██████╔╝ ██║      ██║      ███████║ ███████╗ ╚██████╗ ╚██████╔╝ ██║  ██║ ██║    ██║       ██║".bright_blue());
    println!("{}", "   ╚═════╝  ╚═╝      ╚═╝      ╚══════╝ ╚══════╝  ╚═════╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝    ╚═╝       ╚═╝".bright_blue());
    println!();
    println!("{}", format!("  Professional Web Vulnerability Analysis Tool v{}", env!("CARGO_PKG_VERSION")).bright_white().bold());
    println!("{}", "  Authorized use only — Scan your own assets or obtain explicit permission".yellow());
    println!();
    println!("{}", "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬".bright_black());
    println!();
}

pub fn print_scan_start(urls: &[String], config: &AppConfig, aggressive: bool) {
    println!("{}", "╭─ Scan Configuration".cyan());
    if aggressive {
        println!("{}", "│  Mode:          AGGRESSIVE — all checks, no limits, full throttle".red().bold());
    }
    println!("{}", format!("│  Targets:       {}", urls.len()).white());
    if urls.len() <= 5 {
        for url in urls {
            println!("{}", format!("│    • {}", url).white());
        }
    } else {
        for url in urls.iter().take(3) {
            println!("{}", format!("│    • {}", url).white());
        }
        println!("{}", format!("│    • ... and {} more", urls.len() - 3).white());
    }
    println!("{}", format!("│  Threads:       {}", config.scan.max_threads).white());
    println!("{}", format!("│  Timeout:       {}s", config.scan.timeout_secs).white());
    println!("{}", format!("│  Delay:         {}ms", config.scan.delay_between_requests_ms).white());
    println!("{}", format!("│  Max Retries:   {}", config.scan.max_retries).white());
    println!("{}", format!("│  Intensity:     {} ({})", config.scan.intensity_level,
        match config.scan.intensity_level { 1 => "Passive", 2 => "Light Active", _ => "Full Active" }).white());
    if config.http.tor_enabled {
        println!("{}", format!("│  Proxy:         Tor (socks5h://127.0.0.1)").green());
        println!("{}", format!("│  Anonymity:     Enabled — all traffic routed through Tor").green());
        println!("{}", format!("│  TLS Verify:    Disabled (Tor exit nodes)").yellow());
    } else if let Some(ref proxy) = config.http.proxy_url {
        println!("{}", format!("│  Proxy:         {}", proxy).white());
    }
    if config.http.auth_type.is_some() {
        println!("{}", format!("│  Auth:          {}", config.http.auth_type.as_ref().unwrap()).white());
    }
    if !config.http.custom_headers.is_empty() {
        println!("{}", format!("│  Custom Hdrs:   {}", config.http.custom_headers.len()).white());
    }
    println!("{}", format!("│  User-Agent:    {}", config.http.user_agent).white());
    println!("{}", "╰──────────────────────────────────".cyan());
    println!();
    println!("{}", "▸ Starting scan...".green().bold());
    println!();
}

pub fn print_report_saved(format: &str, path: &str) {
    println!(
        "{} {} {}",
        "  ✓".green(),
        format!("{} report saved:", format).white(),
        path.cyan()
    );
}

pub fn print_error(msg: &str) {
    eprintln!("{} {}", "  ✗ ERROR:".red().bold(), msg.red());
}

pub fn print_warning(msg: &str) {
    println!("{} {}", "  ⚠ WARNING:".yellow(), msg.yellow());
}

pub fn print_info(msg: &str) {
    println!("{} {}", "  ℹ".cyan(), msg.white());
}
