mod cli;
mod core;
mod scanner;
mod checks;
mod reporting;
mod models;
mod utils;
mod output;
mod discovery;
mod db;
mod plugins;
mod exploits;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => {
            let config = match models::AppConfig::merge_with_default(args.config.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    output::banner::print_error(&format!("Failed to load config: {}", e));
                    std::process::exit(1);
                }
            };

            let engine = core::ScanEngine::new(config, args);
            if let Err(e) = engine.run().await {
                output::banner::print_error(&format!("Scan failed: {}", e));
                std::process::exit(1);
            }
        }
        Commands::Discover(args) => {
            output::banner::print_banner();
            println!("{}", format!("╭─ Discovery: {}", args.domain).cyan());
            println!();

            let (mut hosts, _duration) = discovery::subdomains::enumerate_with_wordlist(
                &args.domain, 100, args.wordlist.as_deref(),
            ).await;

            if !args.no_ports {
                let profile = args.port_profile.as_deref().unwrap_or("common");
                let scanned = discovery::ports::scan_hosts(&mut hosts, profile, args.port_timeout, 200).await;
                println!("{}", format!("  Found {} open ports", scanned).green());

                for host in &hosts {
                    if !host.open_ports.is_empty() {
                        println!();
                        println!("{}", format!("  {} ({})", host.hostname, host.ip.as_deref().unwrap_or("unknown")).cyan());
                        for (port, service) in &host.services {
                            println!("{}", format!("    :{} — {}", port, service).white());
                        }
                    }
                }
            }

            println!();
            println!("{}", format!("[✓] Discovery completed — {} hosts found", hosts.len()).green().bold());
        }
        Commands::Crawl(args) => {
            output::banner::print_banner();
            println!("{}", format!("╭─ Crawler: {}", args.url).cyan());
            println!();

            let config = models::AppConfig::default();
            let client = std::sync::Arc::new(core::HttpClient::new(config).expect("Failed to create HTTP client"));
            let crawler_config = core::crawler::CrawlerConfig {
                enabled: true,
                max_pages: args.max_pages,
                same_origin_only: !args.all_origins,
            };

            let pages = core::crawler::crawl(&client, &args.url, &crawler_config).await;
            println!("{}", format!("  Discovered {} pages:", pages.len()).green());
            for page in &pages {
                println!("{}", format!("    {}", page).white());
            }
            println!();
            println!("{}", format!("[✓] Crawl completed — {} pages found", pages.len()).green().bold());
        }
        Commands::Diff(args) => {
            let db_path = args.db.as_deref().unwrap_or("offsecurity.db");
            let conn = db::store::init_db(db_path).expect("Failed to open database");

            if let Some(ref target) = args.target {
                db::diff::list_scans(&conn, target).expect("Failed to list scans");
            } else if let (Some(ref a), Some(ref b)) = (&args.scan_a, &args.scan_b) {
                db::diff::compare_scans(&conn, a, b).expect("Failed to compare scans");
            } else {
                println!("Usage: offsecurity diff --target <URL>  OR  offsecurity diff --scan-a <ID> --scan-b <ID>");
            }
        }
        Commands::Version => {
            println!("offsecurity v{}", env!("CARGO_PKG_VERSION"));
            println!("Professional Web Vulnerability Analysis Tool");
            println!("Built with Rust — Async scanning engine");
            println!();
            println!("Authorized use only.");
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("offsecurity=info,warn,error"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_level(false)
        .compact()
        .init();
}
