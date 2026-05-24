use crate::models::{Finding, Severity};
use std::time::Duration;
use tracing::debug;
use wasmtime::{Engine, Instance, Memory, Module, Store};

/// Run a single WASM plugin and return its findings
pub async fn run_plugin(
    wasm_path: &std::path::Path,
    input_json: &str,
    timeout_secs: u64,
) -> Result<Vec<Finding>, String> {
    let wasm_bytes = std::fs::read(wasm_path)
        .map_err(|e| format!("Failed to read plugin '{}': {}", wasm_path.display(), e))?;

    let engine = Engine::default();
    let module = Module::from_binary(&engine, &wasm_bytes)
        .map_err(|e| format!("Invalid WASM module: {}", e))?;

    let mut store = Store::new(&engine, ());
    store.set_fuel(u64::MAX).map_err(|e| format!("Failed to set fuel: {}", e))?;

    // Set up memory for input/output passing
    let instance = match Instance::new(&mut store, &module, &[]) {
        Ok(inst) => inst,
        Err(e) => {
            // Try WASI instantiation
            debug!("Standard instantiation failed, trying with WASI: {}", e);
            return Err(format!("Plugin instantiation failed: {}", e));
        }
    };

    // Check if the plugin exports the required function
    let run_check = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "run_check")
        .map_err(|_| "Plugin must export 'run_check(ptr: i32, len: i32) -> i32'".to_string())?;

    // Check if plugin exports memory
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or("Plugin must export 'memory'")?;

    // Write input JSON into plugin's memory
    let input_bytes = input_json.as_bytes();
    let input_ptr = 8i32; // Start after a small header
    write_memory(&mut store, memory, input_ptr, input_bytes)?;

    // Call the plugin with timeout
    let timeout = Duration::from_secs(timeout_secs);
    let result = tokio::time::timeout(timeout, async {
        run_check.call(&mut store, (input_ptr, input_bytes.len() as i32))
    })
    .await;

    match result {
        Ok(Ok(return_code)) => {
            if return_code < 0 {
                return Err(format!("Plugin returned error code: {}", return_code));
            }

            // Read plugin output from memory
            // Plugin writes findings JSON at a fixed offset after input
            let output_ptr = input_ptr + input_bytes.len() as i32 + 64;
            match read_memory(&mut store, memory, output_ptr, 4096) {
                Ok(output_bytes) => {
                    let output_str = String::from_utf8_lossy(&output_bytes);
                    let trimmed = output_str.trim_end_matches('\0').trim();
                    if trimmed.is_empty() || trimmed == "[]" {
                        return Ok(vec![]);
                    }
                    parse_plugin_findings(trimmed)
                }
                Err(_) => Ok(vec![]),
            }
        }
        Ok(Err(e)) => Err(format!("Plugin function call failed: {}", e)),
        Err(_) => Err("Plugin execution timed out".to_string()),
    }
}

fn write_memory(
    store: &mut Store<()>,
    memory: Memory,
    offset: i32,
    data: &[u8],
) -> Result<(), String> {
    let offset = offset as usize;
    let mem_size = memory.size(&mut *store) * 65536;

    if offset + data.len() > mem_size as usize {
        let needed_pages = ((offset + data.len() - mem_size as usize) / 65536) + 1;
        memory
            .grow(&mut *store, needed_pages as u64)
            .map_err(|e| format!("Failed to grow memory: {}", e))?;
    }

    memory
        .write(&mut *store, offset, data)
        .map_err(|e| format!("Failed to write memory: {}", e))?;

    Ok(())
}

fn read_memory(
    store: &mut Store<()>,
    memory: Memory,
    offset: i32,
    max_len: usize,
) -> Result<Vec<u8>, String> {
    let offset = offset as usize;
    let mem_size = (memory.size(&mut *store) * 65536) as usize;
    let read_len = std::cmp::min(max_len, mem_size.saturating_sub(offset));

    let mut buffer = vec![0u8; read_len];
    memory
        .read(&mut *store, offset, &mut buffer)
        .map_err(|e| format!("Failed to read memory: {}", e))?;

    Ok(buffer)
}

fn parse_plugin_findings(json: &str) -> Result<Vec<Finding>, String> {
    #[derive(serde::Deserialize)]
    struct PluginFinding {
        title: String,
        #[serde(default)]
        severity: String,
        description: String,
        #[serde(default)]
        evidence: String,
        #[serde(default)]
        recommendation: String,
        #[serde(default)]
        url: String,
    }

    let plugin_findings: Vec<PluginFinding> =
        serde_json::from_str(json).map_err(|e| format!("Invalid plugin output: {}", e))?;

    Ok(plugin_findings
        .into_iter()
        .map(|pf| {
            let severity = match pf.severity.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };

            Finding::new(
                "plugin",
                &pf.title,
                severity,
                &pf.description,
                &pf.evidence,
                &pf.recommendation,
                &pf.url,
            )
        })
        .collect())
}
