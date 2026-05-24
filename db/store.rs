use crate::models::ScanResult;
use rusqlite::{Connection, params};

/// Initialize the database schema
pub fn init_db(path: &str) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;

    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            version TEXT,
            intensity INTEGER,
            total_findings INTEGER,
            duration_secs REAL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(id),
            target_url TEXT NOT NULL,
            check_type TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            evidence TEXT,
            recommendation TEXT,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'open'
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_title ON findings(title);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
    ")?;

    Ok(conn)
}

/// Save a scan result to the database
pub fn save_scan(conn: &Connection, result: &ScanResult) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT OR REPLACE INTO scans (id, target_url, started_at, completed_at, version, intensity, total_findings, duration_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            result.scan_id,
            result.target_url,
            result.start_time,
            now,
            result.scan_version,
            result.intensity_level,
            result.statistics.total as i64,
            result.duration_secs,
        ],
    )?;

    // Deduplicate: check for existing findings with same check_type + title + target_url
    let mut dedup_stmt = conn.prepare(
        "SELECT id FROM findings WHERE check_type = ?1 AND title = ?2 AND target_url = ?3 LIMIT 1"
    )?;

    for finding in &result.findings {
        // Check for existing duplicate
        let exists: bool = dedup_stmt.exists(
            params![finding.check_type, finding.title, finding.affected_url]
        )?;

        if exists {
            // Update last_seen for deduplicated finding
            conn.execute(
                "UPDATE findings SET last_seen = ?1, status = CASE WHEN status = 'fixed' THEN 'reopened' ELSE status END WHERE check_type = ?2 AND title = ?3 AND target_url = ?4",
                params![now, finding.check_type, finding.title, finding.affected_url],
            )?;
            continue;
        }

        conn.execute(
            "INSERT OR REPLACE INTO findings (id, scan_id, target_url, check_type, title, severity, description, evidence, recommendation, first_seen, last_seen, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'open')",
            params![
                finding.id,
                result.scan_id,
                finding.affected_url,
                finding.check_type,
                finding.title,
                finding.severity.to_string(),
                finding.description,
                finding.evidence,
                finding.recommendation,
                now,
                now,
            ],
        )?;
    }

    Ok(())
}

/// Get all scan IDs for a target
pub fn get_scans(conn: &Connection, target: &str) -> Result<Vec<(String, String, i64)>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, completed_at, total_findings FROM scans WHERE target_url = ?1 ORDER BY completed_at DESC"
    )?;

    let rows = stmt.query_map(params![target], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    let mut scans = Vec::new();
    for row in rows {
        scans.push(row?);
    }
    Ok(scans)
}

/// Get findings for a specific scan
pub fn get_findings(conn: &Connection, scan_id: &str) -> Result<Vec<(String, String, String)>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT title, severity, id FROM findings WHERE scan_id = ?1 ORDER BY severity DESC"
    )?;

    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;

    let mut findings = Vec::new();
    for row in rows {
        findings.push(row?);
    }
    Ok(findings)
}
