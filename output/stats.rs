use crate::models::{ScanResult, Severity};
use crate::utils::helpers;
use colored::*;

pub fn print_statistics(results: &[ScanResult], timeout: u64, threads: usize) {
    let all_findings: Vec<&crate::models::Finding> = results
        .iter()
        .flat_map(|r| r.findings.iter())
        .collect();

    let critical = all_findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = all_findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = all_findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = all_findings.iter().filter(|f| f.severity == Severity::Low).count();
    let info = all_findings.iter().filter(|f| f.severity == Severity::Info).count();

    let total_duration: f64 = results.iter().map(|r| r.duration_secs).sum();
    let total_urls = results.len();

    println!();
    println!("{}", "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬".bright_black());
    println!();
    println!("{}", "╭─ Scan Complete — Results".green().bold());
    println!("{}", "│".green());

    // Findings table
    println!("{}", format!("{}  {:<25} {:>8}", "│".green(), "Severity", "Count").white().bold());
    println!("{}", format!("{}  {:-<35}", "│".green(), "").bright_black());

    if critical > 0 {
        println!("{}", format!("{}  {:<25} {:>8}", "│".green(), "  CRITICAL", critical.to_string().red().bold()).white());
    }
    if high > 0 {
        println!("{}", format!("{}  {:<25} {:>8}", "│".green(), "  HIGH", high.to_string().bright_red()).white());
    }
    if medium > 0 {
        println!("{}", format!("{}  {:<25} {:>8}", "│".green(), "  MEDIUM", medium.to_string().yellow()).white());
    }
    if low > 0 {
        println!("{}", format!("{}  {:<25} {:>8}", "│".green(), "  LOW", low.to_string().bright_blue()).white());
    }
    if info > 0 {
        println!("{}", format!("{}  {:<25} {:>8}", "│".green(), "  INFO", info.to_string().cyan()).white());
    }

    println!("{}", format!("{}  {:-<35}", "│".green(), "").bright_black());
    println!("{}", format!("{}  {:<25} {:>8}", "│".green(), "  TOTAL", all_findings.len().to_string().white().bold()).white());

    // Summary
    println!("{}", "│".green());
    println!("{}", format!("│  URLs scanned:     {}", total_urls).white());
    println!("{}", format!("│  Total duration:   {}", helpers::format_duration(total_duration)).white());
    println!("{}", format!("│  Threads used:     {}", threads).white());
    println!("{}", format!("│  Request timeout:  {}s", timeout).white());
    if !all_findings.is_empty() {
        let avg_confidence: f64 = all_findings.iter().map(|f| f.confidence).sum::<f64>() / all_findings.len() as f64;
        let conf_label = if avg_confidence >= 0.8 { "High" } else if avg_confidence >= 0.5 { "Medium" } else { "Low" };
        println!("{}", format!("│  Avg Confidence:  {:.0}% ({})", avg_confidence * 100.0, conf_label).white());
    }
    println!("{}", "│".green());
    println!("{}", "╰──────────────────────────────────────".green());

    // Top findings preview
    if !all_findings.is_empty() {
        println!();
        println!("{}", "╭─ Top Findings".yellow().bold());

        let mut sorted: Vec<&&crate::models::Finding> = all_findings.iter().collect();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.severity.weight()));

        for (i, finding) in sorted.iter().take(10).enumerate() {
            let icon = finding.severity.icon().color(finding.severity.color());
            let conf = format!("{:.0}%", finding.confidence * 100.0);
            let conf_color = if finding.confidence >= 0.8 { conf.green() } else if finding.confidence >= 0.5 { conf.yellow() } else { conf.red() };
            println!(
                "{} {} {} {} {}",
                format!("│ {:>2}.", i + 1).bright_black(),
                icon,
                finding.title.white(),
                conf_color,
                format!("({})", finding.affected_url).bright_black()
            );
        }

        if sorted.len() > 10 {
            println!(
                "{}",
                format!("│ ... and {} more findings", sorted.len() - 10).bright_black()
            );
        }

        println!("{}", "╰──────────────────────────────────────".yellow());
    }

    println!();
    println!("{}", "[✓] Scan finished successfully!".green().bold());
    println!();
    println!("{}", "Disclaimer: Use this tool only on systems you own or have explicit authorization to test.".yellow());
    println!();
}
