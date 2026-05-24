pub mod wasm_runtime;

use crate::models::{Finding, HttpData, Severity};
use std::path::Path;
use tracing::{debug, info, warn};

/// Configuration for the plugin system
#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub plugins_dir: Option<String>,
    pub timeout_secs: u64,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            plugins_dir: None,
            timeout_secs: 5,
        }
    }
}

/// Discover and run all WASM plugins against HTTP data
pub async fn run_plugins(
    config: &PluginConfig,
    data: &HttpData,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let plugin_dir = match &config.plugins_dir {
        Some(dir) => dir.clone(),
        None => {
            // Default paths
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_default();

            let paths = [
                format!("{}/.offsecurity/plugins", home),
                "./plugins".to_string(),
            ];

            let existing = paths.iter().find(|p| Path::new(p).exists());
            match existing {
                Some(p) => p.clone(),
                None => return findings, // No plugins found
            }
        }
    };

    debug!("Loading plugins from: {}", plugin_dir);

    let wasm_files = match discover_plugins(&plugin_dir) {
        Ok(files) => files,
        Err(e) => {
            warn!("Failed to scan plugin directory: {}", e);
            return findings;
        }
    };

    if wasm_files.is_empty() {
        return findings;
    }

    info!("Found {} plugin(s) in {}", wasm_files.len(), plugin_dir);

    // Serialize HTTP data to pass to plugins
    let input = serde_json::json!({
        "url": data.final_url,
        "status_code": data.status_code,
        "headers": data.headers,
        "body": data.body.as_deref().unwrap_or(""),
        "is_https": data.is_https,
    })
    .to_string();

    for wasm_path in &wasm_files {
        match wasm_runtime::run_plugin(wasm_path, &input, config.timeout_secs).await {
            Ok(mut plugin_findings) => {
                for f in &mut plugin_findings {
                    f.check_type = format!("plugin-{}", f.check_type);
                }
                findings.extend(plugin_findings);
            }
            Err(e) => {
                warn!("Plugin '{}' failed: {}", wasm_path.display(), e);

                findings.push(Finding::new(
                    "plugins",
                    format!("Plugin '{}' execution failed", wasm_path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()),
                    Severity::Info,
                    format!("The plugin at '{}' failed to execute: {}", wasm_path.display(), e),
                    format!("Error: {}", e),
                    "Check plugin compatibility and ensure it was compiled for wasm32-wasip1.",
                    &data.final_url,
                ));
            }
        }
    }

    findings
}

fn discover_plugins(dir: &str) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut wasm_files = Vec::new();

    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "wasm") {
            wasm_files.push(path);
        }
    }

    Ok(wasm_files)
}
