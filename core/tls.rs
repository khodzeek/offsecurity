use crate::models::TlsInfo;
use std::sync::Arc;
use x509_parser::prelude::*;

pub async fn fetch_tls_info(host: &str, port: u16) -> TlsInfo {
    let mut errors = Vec::new();

    let addr = match tokio::net::lookup_host((host, port)).await {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                return TlsInfo {
                    valid: false,
                    issuer: None,
                    subject: None,
                    not_before: None,
                    not_after: None,
                    errors: vec!["DNS resolution failed".into()],
                };
            }
        },
        Err(e) => {
            return TlsInfo {
                valid: false,
                issuer: None,
                subject: None,
                not_before: None,
                not_after: None,
                errors: vec![format!("DNS lookup error: {}", e)],
            };
        }
    };

    let tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return TlsInfo {
                valid: false,
                issuer: None,
                subject: None,
                not_before: None,
                not_after: None,
                errors: vec![format!("TCP connection failed: {}", e)],
            };
        }
        Err(_) => {
            return TlsInfo {
                valid: false,
                issuer: None,
                subject: None,
                not_before: None,
                not_after: None,
                errors: vec!["TCP connection timeout".into()],
            };
        }
    };

    let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => return TlsInfo {
            valid: false, issuer: None, subject: None, not_before: None, not_after: None,
            errors: vec!["Invalid server name for TLS".into()],
        },
    };

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    match connector.connect(server_name, tcp).await {
        Ok(tls_stream) => {
            let (_, tls_session) = tls_stream.into_inner();

            match tls_session.peer_certificates() {
                Some(certs) if !certs.is_empty() => {
                    let cert_der = &certs[0];

                    match parse_x509_certificate(cert_der.as_ref()) {
                        Ok((_, cert)) => {
                            let issuer = cert.issuer().to_string();
                            let subject = cert.subject().to_string();
                            let not_before = cert.validity().not_before.to_rfc2822().ok();
                            let not_after = cert.validity().not_after.to_rfc2822().ok();

                            let now = x509_parser::time::ASN1Time::now();
                            let valid = cert.validity().is_valid_at(now);

                            if !valid {
                                errors.push("Certificate is expired or not yet valid".into());
                            }

                            TlsInfo {
                                valid,
                                issuer: Some(clean_dn(&issuer)),
                                subject: Some(clean_dn(&subject)),
                                not_before,
                                not_after,
                                errors,
                            }
                        }
                        Err(e) => TlsInfo {
                            valid: false,
                            issuer: None,
                            subject: None,
                            not_before: None,
                            not_after: None,
                            errors: vec![format!("Certificate parsing error: {}", e)],
                        },
                    }
                }
                _ => TlsInfo {
                    valid: false,
                    issuer: None,
                    subject: None,
                    not_before: None,
                    not_after: None,
                    errors: vec!["No peer certificates presented".into()],
                },
            }
        }
        Err(e) => TlsInfo {
            valid: false,
            issuer: None,
            subject: None,
            not_before: None,
            not_after: None,
            errors: vec![format!("TLS handshake failed: {}", e)],
        },
    }
}

fn clean_dn(dn: &str) -> String {
    dn.split(',')
        .map(|p| p.trim().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
