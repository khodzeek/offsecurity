use crate::db::store;
use colored::*;
use rusqlite::Connection;
use std::collections::HashSet;

/// Compare two scans and print a diff
pub fn compare_scans(conn: &Connection, scan_id_a: &str, scan_id_b: &str) -> Result<(), rusqlite::Error> {
    let findings_a = store::get_findings(conn, scan_id_a)?;
    let findings_b = store::get_findings(conn, scan_id_b)?;

    let titles_a: HashSet<&str> = findings_a.iter().map(|(t, _, _)| t.as_str()).collect();
    let titles_b: HashSet<&str> = findings_b.iter().map(|(t, _, _)| t.as_str()).collect();

    let new_findings: Vec<_> = findings_b.iter().filter(|(t, _, _)| !titles_a.contains(t.as_str())).collect();
    let fixed_findings: Vec<_> = findings_a.iter().filter(|(t, _, _)| !titles_b.contains(t.as_str())).collect();
    let unchanged: Vec<_> = findings_b.iter().filter(|(t, _, _)| titles_a.contains(t.as_str())).collect();

    println!();
    println!("{}", "╭─ Scan Diff".cyan().bold());
    println!("{}", format!("│  {} → {}", scan_id_a, scan_id_b).white());
    println!("{}", "│".cyan());

    println!("{}", format!("│  {} NEW:     {}", "[+]".green(), new_findings.len()).white());
    println!("{}", format!("│  {} FIXED:   {}", "[-]".red(), fixed_findings.len()).white());
    println!("{}", format!("│  {} UNCHANGED: {}", "[=]".bright_black(), unchanged.len()).white());

    // Risk score change
    let score_a = calculate_score(&findings_a);
    let score_b = calculate_score(&findings_b);
    let delta = score_b - score_a;
    let arrow = if delta < 0.0 { "▼".green() } else if delta > 0.0 { "▲".red() } else { "─".yellow() };

    println!("{}", "│".cyan());
    println!("{}", format!("│  Risk Score: {:.1} → {:.1} ({})", score_a, score_b, format!("{} {:.1}", arrow, delta.abs())).white());
    println!("{}", "│".cyan());

    // Show new findings
    if !new_findings.is_empty() {
        println!("{}", "│".cyan());
        println!("{}", "│ [New Findings]".green().bold());
        for (title, severity, _) in &new_findings {
            let icon = severity_icon(severity);
            println!("{}", format!("│   {} {} ({})", icon, title, severity).white());
        }
    }

    // Show fixed findings
    if !fixed_findings.is_empty() {
        println!("{}", "│".cyan());
        println!("{}", "│ [Fixed/Resolved]".red().bold());
        for (title, severity, _) in &fixed_findings {
            println!("{}", format!("│   ✓ {} ({})", title, severity).green());
        }
    }

    println!("{}", "╰──────────────────────────────────────".cyan());
    println!();

    Ok(())
}

/// Print a dashboard of all scans for a target
pub fn list_scans(conn: &Connection, target: &str) -> Result<(), rusqlite::Error> {
    let scans = store::get_scans(conn, target)?;

    println!();
    println!("{}", format!("╭─ Scan History: {}", target).cyan().bold());
    println!("{}", format!("│  {:>10}  {:<22}  {:>8}", "ID", "Date", "Findings").white().bold());
    println!("{}", format!("│  {:-<44}", "").bright_black());

    for (id, date, count) in &scans {
        let short_id = &id[..8.min(id.len())];
        println!("{}", format!("│  {:<10}  {:<22}  {:>8}", short_id, date, count).white());
    }

    println!("{}", "╰──────────────────────────────────────".cyan());
    println!();

    Ok(())
}

fn calculate_score(findings: &[(String, String, String)]) -> f64 {
    findings.iter().map(|(_, severity, _)| {
        match severity.to_lowercase().as_str() {
            "critical" => 10.0,
            "high" => 5.0,
            "medium" => 2.0,
            "low" => 0.5,
            _ => 0.0,
        }
    }).sum()
}

fn severity_icon(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "[CRIT]".red().to_string(),
        "high" => "[HIGH]".bright_red().to_string(),
        "medium" => "[MED ]".yellow().to_string(),
        "low" => "[LOW ]".bright_blue().to_string(),
        _ => "[INFO]".cyan().to_string(),
    }
}
