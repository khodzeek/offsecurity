use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};
use std::collections::HashMap;

/// Full fingerprint analysis: OS detection, software version extraction, CVE correlation
pub async fn fingerprint(_client: &HttpClient, data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    let fp = extract_fingerprint(data);
    if fp.is_empty() {
        return findings;
    }

    // Report OS detection
    for (source, os) in &fp.operating_systems {
        findings.push(Finding::new(
            "fingerprint-os",
            format!("OS detected: {} (via {})", os, source),
            Severity::Info,
            format!("The server appears to be running {}. This helps narrow down relevant exploits.", os),
            format!("Detected through: {}. Found pattern matching {}.", source, os),
            "Keep the OS updated with the latest security patches. Disable OS fingerprinting where possible.",
            &data.final_url,
        ));
    }

    // Report software versions with live CVE lookup
    for sw in &fp.software {
        let (sev, note) = assess_version_risk(&sw.name, &sw.version);

        // Try live CVE lookup
        let live_cves = lookup_cve_live(&sw.name, &sw.version).await;
        let mut cve_detail = String::new();
        if !live_cves.is_empty() {
            cve_detail.push_str("\n\nLive CVEs from NVD:\n");
            for (cve_id, severity, desc) in &live_cves {
                cve_detail.push_str(&format!("  - {} [{}]: {}\n", cve_id, severity, desc));
            }
        }

        findings.push(Finding::new(
            "fingerprint-version",
            format!("{} version {} detected (via {})", sw.name, sw.version, sw.source),
            sev,
            format!(
                "Detected {} version {}. {}\nCVEs: {}{}",
                sw.name, sw.version, note, sw.known_cves.join(", "), cve_detail
            ),
            format!("Source: {}. Found: {} = {}{}", sw.source, sw.name, sw.version, cve_detail),
            "Check for security updates. Review the listed CVEs and apply patches.",
            &data.final_url,
        ));
    }

    // Report missing/outdated security patterns
    for (_, os) in &fp.operating_systems {
        if let Some(cves) = os_cves(os) {
            for cve in cves {
                findings.push(Finding::new(
                    "fingerprint-cve",
                    format!("Potential OS exploit: {}", cve.id),
                    Severity::High,
                    format!("The detected OS '{}' may be vulnerable to {}: {}", os, cve.id, cve.description),
                    format!("OS: {}. CVE: {} — {}", os, cve.id, cve.description),
                    format!("Check if {} applies. Apply OS security patches.", cve.id),
                    &data.final_url,
                ));
            }
        }
    }

    findings
}

/// Full fingerprint structure
#[allow(dead_code)]
struct Fingerprint {
    operating_systems: Vec<(String, String)>, // (source, os_name)
    software: Vec<SoftwareInfo>,
    extra_info: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct SoftwareInfo {
    name: String,
    version: String,
    source: String,
    known_cves: Vec<String>,
}

impl Fingerprint {
    fn is_empty(&self) -> bool {
        self.operating_systems.is_empty() && self.software.is_empty()
    }
}

fn extract_fingerprint(data: &HttpData) -> Fingerprint {
    let mut os_list = Vec::new();
    let mut software = Vec::new();
    let mut extra = HashMap::new();

    let body = data.body.as_deref().unwrap_or("");
    let headers = &data.headers;

    // ═══ OS Detection ═══

    // TTL-based (from TCP stack — we approximate from Server header patterns)
    if let Some(server) = headers.get("server") {
        let s = server.to_lowercase();

        // Linux-based
        if s.contains("ubuntu") { os_list.push(("Server header".into(), "Ubuntu Linux".into())); }
        else if s.contains("debian") { os_list.push(("Server header".into(), "Debian Linux".into())); }
        else if s.contains("centos") { os_list.push(("Server header".into(), "CentOS Linux".into())); }
        else if s.contains("rhel") || s.contains("red hat") { os_list.push(("Server header".into(), "RHEL Linux".into())); }
        else if s.contains("fedora") { os_list.push(("Server header".into(), "Fedora Linux".into())); }
        else if s.contains("alpine") { os_list.push(("Server header".into(), "Alpine Linux".into())); }

        // Windows-based
        else if s.contains("iis") || s.contains("microsoft") || s.contains("windows") {
            let win_ver = if s.contains("10.0") { "Windows Server 2016/2019/2022" }
                else if s.contains("6.3") { "Windows Server 2012 R2" }
                else if s.contains("6.2") { "Windows Server 2012" }
                else if s.contains("6.1") { "Windows Server 2008 R2" }
                else { "Windows (version unknown)" };
            os_list.push(("Server header".into(), win_ver.to_string()));
        }

        // BSD
        else if s.contains("freebsd") { os_list.push(("Server header".into(), "FreeBSD".into())); }
        else if s.contains("openbsd") { os_list.push(("Server header".into(), "OpenBSD".into())); }
    }

    // Body-based OS detection
    let body_lower = body.to_lowercase();

    // Linux path patterns
    if body_lower.contains("/var/www") || body_lower.contains("/etc/") || body_lower.contains("/usr/share") {
        if os_list.is_empty() {
            os_list.push(("Response body path".into(), "Linux/Unix".into()));
        }
    }

    // Windows path patterns
    if body_lower.contains("c:\\inetpub") || body_lower.contains("c:\\windows") || body_lower.contains("powershell") {
        if !os_list.iter().any(|(_, o)| o.contains("Windows")) {
            os_list.push(("Response body path".into(), "Windows".into()));
        }
    }

    // X-Powered-By
    if let Some(pb) = headers.get("x-powered-by") {
        let pb_lower = pb.to_lowercase();

        // PHP
        if pb_lower.contains("php") {
            let version = extract_version(pb);
            let ver_str = version.unwrap_or_else(|| "unknown".to_string());
            software.push(SoftwareInfo {
                name: "PHP".into(),
                version: ver_str.clone(),
                source: "X-Powered-By header".into(),
                known_cves: cves_for_php(&ver_str),
            });

            // PHP often means Linux, but not always
            if !os_list.iter().any(|(_, o)| o.contains("Linux") || o.contains("Windows")) {
                os_list.push(("PHP detected".into(), "Likely Linux/Unix".into()));
            }
        }

        // ASP.NET
        if pb_lower.contains("asp.net") {
            let version = extract_version(pb);
            software.push(SoftwareInfo {
                name: "ASP.NET".into(),
                version: version.unwrap_or_else(|| "unknown".to_string()),
                source: "X-Powered-By header".into(),
                known_cves: vec![],
            });
            if !os_list.iter().any(|(_, o)| o.contains("Windows")) {
                os_list.push(("ASP.NET detected".into(), "Windows Server".into()));
            }
        }
    }

    // ═══ Server Version Detection ═══

    if let Some(server) = headers.get("server") {
        let s = server.to_lowercase();

        // Apache
        if s.contains("apache") {
            let version = extract_version(server);
            let ver_str = version.clone().unwrap_or_else(|| "unknown".to_string());
            software.push(SoftwareInfo {
                name: "Apache HTTP Server".into(),
                version: ver_str.clone(),
                source: "Server header".into(),
                known_cves: cves_for_apache(&ver_str),
            });

            // Apache version hints at OS
            if s.contains("win32") || s.contains("win64") {
                if !os_list.iter().any(|(_, o)| o.contains("Windows")) {
                    os_list.push(("Apache build target".into(), "Windows".into()));
                }
            } else if s.contains("unix") || s.contains("linux") {
                if !os_list.iter().any(|(_, o)| o.contains("Linux")) {
                    os_list.push(("Apache build target".into(), "Linux/Unix".into()));
                }
            }
        }

        // Nginx
        if s.contains("nginx") {
            let version = extract_version(server);
            let ver_str = version.clone().unwrap_or_else(|| "unknown".to_string());
            software.push(SoftwareInfo {
                name: "Nginx".into(),
                version: ver_str.clone(),
                source: "Server header".into(),
                known_cves: cves_for_nginx(&ver_str),
            });
        }

        // IIS
        if s.contains("iis") || s.contains("microsoft-") {
            let version = extract_version(server);
            let ver_str = version.clone().unwrap_or_else(|| "unknown".to_string());
            software.push(SoftwareInfo {
                name: "Microsoft IIS".into(),
                version: ver_str.clone(),
                source: "Server header".into(),
                known_cves: cves_for_iis(&ver_str),
            });
        }

        // Caddy
        if s.contains("caddy") {
            let version = extract_version(server);
            software.push(SoftwareInfo {
                name: "Caddy".into(),
                version: version.unwrap_or_else(|| "unknown".to_string()),
                source: "Server header".into(),
                known_cves: vec![],
            });
        }

        // Generic version extraction for unknown servers
        if software.is_empty() {
            if let Some(ver) = extract_version(server) {
                software.push(SoftwareInfo {
                    name: "Web Server".into(),
                    version: ver,
                    source: "Server header".into(),
                    known_cves: vec![],
                });
            }
        }
    }

    // ═══ Framework/Language Detection from Body ═══

    // WordPress
    if let Some(ver) = extract_wordpress_version(body) {
        software.push(SoftwareInfo {
            name: "WordPress".into(),
            version: ver.clone(),
            source: "HTML meta generator".into(),
            known_cves: cves_for_wordpress(&ver),
        });
    }

    // jQuery
    if let Some(ver) = extract_jquery_version(body) {
        software.push(SoftwareInfo {
            name: "jQuery".into(),
            version: ver,
            source: "Script tag".into(),
            known_cves: vec![
                "CVE-2020-11023".into(),
                "CVE-2020-11022".into(),
                "CVE-2019-11358".into(),
            ],
        });
    }

    // Bootstrap
    if let Some(ver) = extract_script_version(body, "bootstrap") {
        software.push(SoftwareInfo {
            name: "Bootstrap".into(),
            version: ver.clone(),
            source: "CSS/JS reference".into(),
            known_cves: cves_for_bootstrap(&ver),
        });
    }

    // React (via react-root, __REACT_DEVTOOLS__, etc.)
    if body.contains("react-root") || body.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__") || body.contains("/react-dom") {
        if let Some(ver) = extract_script_version(body, "react") {
            software.push(SoftwareInfo {
                name: "React".into(),
                version: ver,
                source: "JS bundle".into(),
                known_cves: vec![],
            });
        } else {
            software.push(SoftwareInfo {
                name: "React".into(),
                version: "unknown".into(),
                source: "DOM markers".into(),
                known_cves: vec![],
            });
        }
    }

    // Vue.js
    if body.contains("vue") || body.contains("data-v-") {
        if let Some(ver) = extract_script_version(body, "vue") {
            software.push(SoftwareInfo {
                name: "Vue.js".into(),
                version: ver,
                source: "Script reference".into(),
                known_cves: vec![],
            });
        }
    }

    // Angular
    if body.contains("ng-version") || body.contains("angular") {
        let re = regex::Regex::new(r#"ng-version="([^"]+)""#).unwrap();
        if let Some(cap) = re.captures(body) {
            software.push(SoftwareInfo {
                name: "Angular".into(),
                version: cap[1].to_string(),
                source: "ng-version attribute".into(),
                known_cves: vec![],
            });
        }
    }

    // Laravel debug bar or error
    if body_lower.contains("laravel") || body_lower.contains("whoops") {
        let version = extract_version_from_pattern(body, "laravel", r#"Laravel\s+v?([\d.]+)"#);
        software.push(SoftwareInfo {
            name: "Laravel".into(),
            version: version.unwrap_or_else(|| "unknown".to_string()),
            source: "Response body".into(),
            known_cves: vec![
                "CVE-2021-3129".into(),
                "CVE-2024-40075".into(),
            ],
        });
    }

    // Django debug mode
    if body_lower.contains("django") || body_lower.contains("csrfmiddlewaretoken") {
        if body_lower.contains("django settings") || body_lower.contains("debug=True") {
            software.push(SoftwareInfo {
                name: "Django (debug mode enabled!)".into(),
                version: "unknown".into(),
                source: "Response body".into(),
                known_cves: vec![],
            });
        } else {
            software.push(SoftwareInfo {
                name: "Django".into(),
                version: "unknown".into(),
                source: "CSRF token pattern".into(),
                known_cves: vec![],
            });
        }
    }

    // Express.js
    if let Some(etag) = headers.get("etag") {
        if etag.contains("express") {
            software.push(SoftwareInfo {
                name: "Express.js".into(),
                version: "unknown".into(),
                source: "ETag header pattern".into(),
                known_cves: vec![],
            });
        }
    }

    // ═══ Extra info ═══

    // TLS version from headers
    if data.is_https {
        if let Some(tls) = &data.tls_info {
            extra.insert("tls_valid".into(), tls.valid.to_string());
            if let Some(ref issuer) = tls.issuer {
                extra.insert("tls_issuer".into(), issuer.clone());
            }
        }
    }

    // Response technology hints
    if let Some(ct) = headers.get("content-type") {
        if ct.contains("text/html") { extra.insert("content_type".into(), "HTML".into()); }
        if ct.contains("application/json") { extra.insert("content_type".into(), "JSON API".into()); }
        if ct.contains("application/xml") { extra.insert("content_type".into(), "XML".into()); }
    }

    Fingerprint {
        operating_systems: os_list,
        software,
        extra_info: extra,
    }
}

// ═══ Version Extraction ═══

fn extract_version(header: &str) -> Option<String> {
    let re = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?(?:\.[a-zA-Z0-9]+)?)").unwrap();
    re.find(header).map(|m| m.as_str().to_string())
}

fn extract_wordpress_version(body: &str) -> Option<String> {
    let re = regex::Regex::new(r#"<meta\s+name="generator"\s+content="WordPress\s+([^"]+)""#).unwrap();
    re.captures(body).map(|c| c[1].to_string())
}

fn extract_jquery_version(body: &str) -> Option<String> {
    let re = regex::Regex::new(r"jquery[/-]?([\d.]+)(?:\.min)?\.js").unwrap();
    re.captures(&body.to_lowercase()).map(|c| c[1].to_string())
}

fn extract_script_version(body: &str, library: &str) -> Option<String> {
    let pattern = format!(r"{library}[/-]?([\d.]+)(?:\.min)?\.(?:js|css)", library = regex::escape(library));
    let re = regex::Regex::new(&pattern).ok()?;
    re.captures(&body.to_lowercase()).map(|c| c[1].to_string())
}

fn extract_version_from_pattern(body: &str, _context: &str, pattern: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    re.captures(body).map(|c| c[1].to_string())
}

// ═══ Risk Assessment ═══

fn assess_version_risk(name: &str, version: &str) -> (Severity, String) {
    let name_lower = name.to_lowercase();

    // Apache versions
    if name_lower.contains("apache") {
        if version.starts_with("2.2.") {
            return (Severity::Critical, "Apache 2.2.x is end-of-life since 2018. Multiple critical CVEs exist.".into());
        }
        if version.starts_with("2.4.") {
            if let Ok(minor) = version[4..].parse::<u32>() {
                if minor < 57 {
                    return (Severity::High, format!("Apache 2.4.{} has known vulnerabilities. Upgrade to 2.4.62+.", minor));
                }
            }
        }
    }

    // Nginx
    if name_lower.contains("nginx") {
        if version.starts_with("1.0.") || version.starts_with("0.") {
            return (Severity::Critical, "Ancient Nginx version. Multiple critical CVEs.".into());
        }
        if version.starts_with("1.1") || version.starts_with("1.2") || version.starts_with("1.3") {
            return (Severity::High, "Very old Nginx version. Upgrade to latest stable.".into());
        }
    }

    // PHP
    if name_lower.contains("php") {
        let ver = version.replace("php/", "").replace("PHP/", "");
        if ver.starts_with("5.") {
            return (Severity::Critical, "PHP 5.x is end-of-life. No security patches since 2019.".into());
        }
        if ver.starts_with("7.0") || ver.starts_with("7.1") || ver.starts_with("7.2") || ver.starts_with("7.3") {
            return (Severity::High, format!("PHP {} is end-of-life. Upgrade to 8.3+.", ver));
        }
        if ver.starts_with("8.0") || ver.starts_with("8.1") {
            return (Severity::Medium, format!("PHP {} security support ending soon. Upgrade to 8.3+.", ver));
        }
    }

    // WordPress
    if name_lower.contains("wordpress") {
        if let Some(major) = version.split('.').next().and_then(|v| v.parse::<u32>().ok()) {
            if major < 6 {
                return (Severity::High, "WordPress version is significantly outdated. Upgrade to latest.".into());
            }
        }
    }

    // jQuery
    if name_lower.contains("jquery") {
        if version.starts_with("1.") {
            return (Severity::Medium, "jQuery 1.x is very old. Consider upgrading to latest or removing if unused.".into());
        }
        if version.starts_with("2.") {
            return (Severity::Low, "jQuery 2.x is old. Upgrade to 3.x for security fixes.".into());
        }
    }

    // Bootstrap
    if name_lower.contains("bootstrap") {
        if version.starts_with("3.") || version.starts_with("4.0") || version.starts_with("4.1") {
            return (Severity::Low, "Older Bootstrap version with known XSS vulnerabilities.".into());
        }
    }

    (Severity::Info, format!("{} {} — no critical known version issues.", name, version))
}

// ═══ CVE Databases ═══

fn cves_for_apache(version: &str) -> Vec<String> {
    if version.starts_with("2.4.0") || version.starts_with("2.4.1") {
        return vec!["CVE-2024-40898".into(), "CVE-2024-39573".into(), "CVE-2023-45802".into(), "CVE-2023-43622".into()];
    }
    if version.starts_with("2.4.") {
        return vec!["CVE-2024-40898".into(), "CVE-2024-39573".into(), "CVE-2023-45802".into()];
    }
    vec!["CVE-2024-40898".into(), "CVE-2023-45802".into(), "CVE-2023-43622".into(), "CVE-2023-31122".into()]
}

fn cves_for_nginx(version: &str) -> Vec<String> {
    if version.starts_with("1.25") || version.starts_with("1.26") {
        return vec!["CVE-2024-7347".into(), "CVE-2024-24989".into(), "CVE-2024-24990".into()];
    }
    vec!["CVE-2024-7347".into(), "CVE-2024-24989".into(), "CVE-2024-24990".into(), "CVE-2024-21490".into(), "CVE-2023-44487".into()]
}

fn cves_for_iis(version: &str) -> Vec<String> {
    if version.starts_with("10.0") {
        vec!["CVE-2024-21409".into(), "CVE-2024-21319".into(), "CVE-2024-0057".into()]
    } else if version.starts_with("8.") {
        vec!["CVE-2023-36884".into(), "CVE-2023-35356".into(), "CVE-2022-24512".into()]
    } else {
        vec!["CVE-2023-36884".into(), "CVE-2022-24512".into(), "CVE-2022-21907".into()]
    }
}

fn cves_for_php(version: &str) -> Vec<String> {
    if version.starts_with("5.") {
        vec!["CVE-2024-4577".into(), "CVE-2024-2961".into(), "CVE-2023-3824".into(), "CVE-2023-0662".into(), "CVE-2022-31626".into()]
    } else if version.starts_with("7.") {
        vec!["CVE-2024-4577".into(), "CVE-2024-2961".into(), "CVE-2023-3824".into()]
    } else if version.starts_with("8.0") || version.starts_with("8.1") || version.starts_with("8.2") {
        vec!["CVE-2024-4577".into(), "CVE-2024-2961".into()]
    } else {
        vec![]
    }
}

fn cves_for_wordpress(version: &str) -> Vec<String> {
    if version.starts_with("5.") {
        vec!["CVE-2024-43916".into(), "CVE-2024-28000".into(), "CVE-2023-45124".into()]
    } else if version.starts_with("6.0") || version.starts_with("6.1") || version.starts_with("6.2") || version.starts_with("6.3") || version.starts_with("6.4") {
        vec!["CVE-2024-43916".into(), "CVE-2024-28000".into()]
    } else {
        vec![]
    }
}

fn cves_for_bootstrap(_version: &str) -> Vec<String> {
    vec![
        "CVE-2024-6531".into(),
        "CVE-2019-8331".into(),
        "CVE-2018-20676".into(),
        "CVE-2016-10735".into(),
    ]
}

fn os_cves(os: &str) -> Option<Vec<OsCve>> {
    let os_lower = os.to_lowercase();
    if os_lower.contains("windows server 2008") {
        Some(vec![
            OsCve { id: "CVE-2019-0708", description: "BlueKeep RCE — Remote Desktop Protocol vulnerability".into() },
            OsCve { id: "CVE-2020-1472", description: "Zerologon — Netlogon elevation of privilege".into() },
        ])
    } else if os_lower.contains("windows server 2012") {
        Some(vec![
            OsCve { id: "CVE-2020-1472", description: "Zerologon — Netlogon elevation of privilege".into() },
        ])
    } else if os_lower.contains("ubuntu") || os_lower.contains("debian") || os_lower.contains("centos") {
        Some(vec![
            OsCve { id: "CVE-2024-6387", description: "regreSSHion — OpenSSH unauthenticated RCE".into() },
            OsCve { id: "CVE-2024-1086", description: "Linux kernel use-after-free leading to privilege escalation".into() },
        ])
    } else {
        None
    }
}

struct OsCve {
    id: &'static str,
    description: &'static str,
}

// ═══ Live CVE API lookup ═══

/// Query the NVD API for live CVE data for a given software product + version
pub async fn lookup_cve_live(product: &str, version: &str) -> Vec<(String, String, String)> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}%20{}&resultsPerPage=5",
        product, version
    );

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("offsecurity-cve-lookup/1.0")
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    match client.get(&url).send().await {
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(json) => {
                    let mut results = Vec::new();
                    if let Some(vulns) = json["vulnerabilities"].as_array() {
                        for vuln in vulns.iter().take(5) {
                            let cve_id = vuln["cve"]["id"].as_str().unwrap_or("?").to_string();
                            let desc = vuln["cve"]["descriptions"]
                                .as_array()
                                .and_then(|d| d.iter().find(|v| v["lang"].as_str() == Some("en")))
                                .and_then(|d| d["value"].as_str())
                                .unwrap_or("No description")
                                .to_string();

                            let severity = vuln["cve"]["metrics"]["cvssMetricV31"]
                                .as_array()
                                .and_then(|m| m.first())
                                .and_then(|m| m["cvssData"]["baseSeverity"].as_str())
                                .unwrap_or("UNKNOWN")
                                .to_string();

                            results.push((cve_id, severity, desc));
                        }
                    }
                    results
                }
                Err(_) => vec![],
            }
        }
        Err(_) => vec![],
    }
}

// ═══ Generate an exploit report for found versions ═══

pub fn generate_exploit_report(data: &HttpData) -> String {
    let fp = extract_fingerprint(data);
    if fp.is_empty() {
        return String::new();
    }

    let mut report = String::new();
    report.push_str("╔══════════════════════════════════════════════╗\n");
    report.push_str("║     FINGERPRINT + EXPLOIT REPORT              ║\n");
    report.push_str("╠══════════════════════════════════════════════╣\n");

    if !fp.operating_systems.is_empty() {
        report.push_str("║ OS Detected:\n");
        for (source, os) in &fp.operating_systems {
            report.push_str(&format!("║   ● {} (via {})\n", os, source));
        }
        report.push_str("║\n");
    }

    if !fp.software.is_empty() {
        report.push_str("║ Software Versions:\n");
        for sw in &fp.software {
            report.push_str(&format!("║   ● {} v{} (via {})\n", sw.name, sw.version, sw.source));
            if !sw.known_cves.is_empty() {
                report.push_str(&format!("║     ↳ CVEs: {}\n", sw.known_cves.join(", ")));
            }
        }
        report.push_str("║\n");
    }

    report.push_str("║ Search exploits:\n");
    for sw in &fp.software {
        report.push_str(&format!("║   searchsploit {} {}\n", sw.name, sw.version));
        report.push_str(&format!("║   msfconsole -q -x 'search {}'\n", sw.name));
    }
    report.push_str("╚══════════════════════════════════════════════╝\n");

    report
}
