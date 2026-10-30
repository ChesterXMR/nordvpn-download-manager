//! Chrome-matching HTTP fingerprint.
//!
//! Many file hosts refuse connections whose TLS and HTTP/2 behaviour doesn't look like a real
//! browser (bot checks). The download stack is therefore built on `wreq` with a hand-assembled
//! Chrome 130 emulation profile: the same TLS curves, cipher suites, signature algorithms,
//! extensions, HTTP/2 settings frame and pseudo-header order a Chrome window on Windows sends.
//!
//! The user agent must stay in sync with the profile version, because sites compare the advertised
//! browser version against the TLS fingerprint. Gofile's website token also hashes the user agent.

use wreq::{
    Emulation,
    header::{self, HeaderMap, HeaderValue},
    http2::{Http2Options, PseudoId, PseudoOrder},
    tls::{AlpnProtocol, TlsOptions, TlsVersion},
};

/// Kept in step with the Chrome 130 emulation profile below.
pub const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

/// TLS options as Chrome 130 on Windows sends them (curl-impersonate's `chrome130` profile).
fn chrome_tls() -> TlsOptions {
    TlsOptions::builder()
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .cipher_list(concat!(
            "TLS_AES_128_GCM_SHA256:",
            "TLS_AES_256_GCM_SHA384:",
            "TLS_CHACHA20_POLY1305_SHA256:",
            "ECDHE-ECDSA-AES128-GCM-SHA256:",
            "ECDHE-RSA-AES128-GCM-SHA256:",
            "ECDHE-ECDSA-AES256-GCM-SHA384:",
            "ECDHE-RSA-AES256-GCM-SHA384:",
            "ECDHE-ECDSA-CHACHA20-POLY1305:",
            "ECDHE-RSA-CHACHA20-POLY1305:",
            "ECDHE-RSA-AES256-SHA:",
            "ECDHE-RSA-AES128-SHA"
        ))
        .curves_list("X25519:P-256:P-384")
        .sigalgs_list(concat!(
            "ecdsa_secp256r1_sha256:",
            "rsa_pss_rsae_sha256:",
            "rsa_pkcs1_sha256:",
            "ecdsa_secp384r1_sha384:",
            "rsa_pss_rsae_sha384:",
            "rsa_pkcs1_sha384:",
            "rsa_pss_rsae_sha512:",
            "rsa_pkcs1_sha512"
        ))
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .build()
}

/// HTTP/2 settings frame as Chrome 130 sends it, including pseudo-header order.
fn chrome_http2() -> Http2Options {
    Http2Options::builder()
        .header_table_size(65536)
        .enable_push(false)
        .max_concurrent_streams(1000)
        .initial_window_size(6291456)
        .initial_connection_window_size(15663105)
        .max_header_list_size(262144)
        .enable_connect_protocol(true)
        .headers_pseudo_order(
            PseudoOrder::builder()
                .extend([PseudoId::Method, PseudoId::Authority, PseudoId::Scheme, PseudoId::Path])
                .build(),
        )
        .build()
}

/// Chrome's always-sent headers. Requests add their own on top; anything set per request wins.
fn chrome_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static(CHROME_UA));
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip, deflate, br, zstd"));
    // `http` has no constants for the client-hints headers.
    let sec_ch_ua = header::HeaderName::from_static("sec-ch-ua");
    let sec_ch_ua_mobile = header::HeaderName::from_static("sec-ch-ua-mobile");
    let sec_ch_ua_platform = header::HeaderName::from_static("sec-ch-ua-platform");
    headers.insert(
        sec_ch_ua,
        HeaderValue::from_static(r#""Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99""#),
    );
    headers.insert(sec_ch_ua_mobile, HeaderValue::from_static("?0"));
    headers.insert(sec_ch_ua_platform, HeaderValue::from_static("\"Windows\""));
    headers
}

/// The complete Chrome 130 emulation profile for client builders.
pub fn emulation() -> Emulation {
    Emulation::builder()
        .tls_options(chrome_tls())
        .http2_options(chrome_http2())
        .headers(chrome_headers())
        .build(Default::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emulation_builds() {
        let _ = emulation();
        assert!(CHROME_UA.contains("Chrome/130"));
    }
}
