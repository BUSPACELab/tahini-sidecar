use std::fs::File;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use fizz_rs::{ClientTlsContext, VerificationInfo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Default MAA endpoint for Azure Attestation (East US shared provider).
// Format: https://shared{region}.{region}.attest.azure.net
const DEFAULT_MAA_ENDPOINT: &str = "https://sharedeus.eus.attest.azure.net";

#[derive(Parser)]
#[command(about = "Tahini RPC client — verifies SGX attestation then connects over delegated TLS")]
struct Args {
    /// Path to client verification info JSON
    #[arg(long = "dc-sig")]
    dc_sig: String,

    /// Path to parent TLS certificate
    #[arg(long = "dc-cert")]
    dc_cert: String,

    /// Server address (e.g. server:8443)
    #[arg(long)]
    server: String,

    /// Path to attestation JSON from the sidecar (quote + binary hash + public key)
    #[arg(long)]
    attestation: String,

    /// Azure MAA endpoint for quote verification
    #[arg(long, default_value = DEFAULT_MAA_ENDPOINT)]
    maa_endpoint: String,

    /// Expected binary hash (hex). If provided, verified against report_data.
    #[arg(long)]
    expected_hash: Option<String>,
}

#[derive(Deserialize)]
struct AttestationJson {
    quote: String,
    binary_hash: String,
    public_key: String,
}

#[derive(Serialize)]
struct MaaRequest {
    quote: String,
}

#[derive(Deserialize)]
struct MaaResponse {
    token: String,
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Verify the SGX DCAP quote via Azure Attestation (MAA).
/// Returns the decoded report_data (64 bytes) on success.
async fn verify_quote_via_maa(
    maa_endpoint: &str,
    quote_b64url: &str,
) -> Result<Vec<u8>, String> {
    let url = format!("{}/attest/SgxEnclave?api-version=2022-08-01", maa_endpoint);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&MaaRequest {
            quote: quote_b64url.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("MAA request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("MAA returned {}: {}", status, body));
    }

    let maa_resp: MaaResponse = resp
        .json()
        .await
        .map_err(|e| format!("failed to parse MAA response: {}", e))?;

    // The token is a JWT (header.payload.signature). We decode the payload
    // to extract the report_data claim. In production, verify the JWT signature
    // against MAA's JWKS endpoint.
    let parts: Vec<&str> = maa_resp.token.split('.').collect();
    if parts.len() != 3 {
        return Err("MAA token is not a valid JWT".into());
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("failed to decode JWT payload: {}", e))?;

    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("failed to parse JWT claims: {}", e))?;

    let report_data_raw = claims
        .get("x-ms-sgx-report-data")
        .and_then(|v| v.as_str())
        .ok_or("JWT missing x-ms-sgx-report-data claim")?;

    // MAA returns report_data as a hex string (128 hex chars = 64 bytes).
    // Try hex first, then fall back to base64 for forward-compatibility.
    let report_data = if report_data_raw.len() == 128
        && report_data_raw.chars().all(|c| c.is_ascii_hexdigit())
    {
        decode_hex(report_data_raw)
    } else {
        URL_SAFE_NO_PAD
            .decode(report_data_raw)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(report_data_raw))
            .map_err(|e| format!("failed to decode report_data: {}", e))?
    };

    if report_data.len() != 64 {
        return Err(format!(
            "unexpected report_data length: {} (expected 64)",
            report_data.len()
        ));
    }

    let is_debuggable = claims
        .get("x-ms-sgx-is-debuggable")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if is_debuggable {
        eprintln!("[rpc-client] WARNING: enclave is in debug mode");
    }

    Ok(report_data)
}

/// Check that report_data = binary_hash (32B) || H(public_key) (32B)
fn verify_report_data(
    report_data: &[u8],
    expected_binary_hash: &[u8],
    expected_public_key: &[u8],
) -> Result<(), String> {
    if report_data.len() != 64 {
        return Err(format!("report_data length {} != 64", report_data.len()));
    }

    let rd_hash = &report_data[..32];
    let rd_pubkey_commitment = &report_data[32..64];

    if rd_hash != expected_binary_hash {
        return Err(format!(
            "binary hash mismatch: report_data has {}, expected {}",
            hex::encode(rd_hash),
            hex::encode(expected_binary_hash)
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(expected_public_key);
    let pubkey_hash = hasher.finalize();

    if rd_pubkey_commitment != pubkey_hash.as_slice() {
        return Err(format!(
            "public key commitment mismatch: report_data has {}, expected H(pubkey)={}",
            hex::encode(rd_pubkey_commitment),
            hex::encode(&pubkey_hash)
        ));
    }

    Ok(())
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Step 1: verify SGX attestation quote via Azure MAA
    eprintln!("[rpc-client] loading attestation from {}", args.attestation);
    let attest_file =
        File::open(&args.attestation).expect("failed to open attestation JSON");
    let attest: AttestationJson =
        serde_json::from_reader(attest_file).expect("failed to parse attestation JSON");

    eprintln!(
        "[rpc-client] verifying DCAP quote via {}...",
        args.maa_endpoint
    );
    let report_data = verify_quote_via_maa(&args.maa_endpoint, &attest.quote)
        .await
        .expect("SGX quote verification failed");

    eprintln!("[rpc-client] SGX quote verified by Azure Attestation");

    let binary_hash_bytes = decode_hex(&attest.binary_hash);
    let public_key_bytes = decode_hex(&attest.public_key);

    verify_report_data(&report_data, &binary_hash_bytes, &public_key_bytes)
        .expect("report_data verification failed");

    eprintln!(
        "[rpc-client] report_data verified: binary_hash={}, pubkey_commitment OK",
        attest.binary_hash
    );

    if let Some(ref expected) = args.expected_hash {
        if *expected != attest.binary_hash {
            panic!(
                "binary hash mismatch: server reports {}, expected {}",
                attest.binary_hash, expected
            );
        }
        eprintln!("[rpc-client] binary hash matches expected value");
    }

    // Step 2: establish delegated TLS connection
    eprintln!("[rpc-client] loading verification info from {}", args.dc_sig);
    eprintln!("[rpc-client] loading parent cert from {}", args.dc_cert);
    eprintln!("[rpc-client] connecting to {}", args.server);

    let file = File::open(&args.dc_sig).expect("failed to open verification info JSON");
    let info: VerificationInfo =
        serde_json::from_reader(file).expect("failed to parse verification info JSON");

    let tls = ClientTlsContext::new(info, &args.dc_cert)
        .expect("failed to create client TLS context");

    let host = args.server.split(':').next().unwrap_or("localhost");

    let stream = TcpStream::connect(&args.server)
        .await
        .expect("failed to connect to server");
    eprintln!("[rpc-client] TCP connected to {}", args.server);

    let mut conn = tls
        .connect(stream, host)
        .await
        .expect("TLS handshake failed");
    eprintln!("[rpc-client] TLS handshake succeeded (delegated credential verified)");

    // Step 3: exchange a message over the verified channel
    let message = b"Hello from tahini rpc-client over delegated TLS!";
    conn.write_all(message)
        .await
        .expect("failed to send message");
    conn.flush().await.expect("failed to flush");
    eprintln!(
        "[rpc-client] sent: {}",
        String::from_utf8_lossy(message)
    );

    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await.expect("failed to read response");
    let response = String::from_utf8_lossy(&buf[..n]);
    eprintln!("[rpc-client] received echo: {}", response);

    conn.shutdown()
        .await
        .expect("failed to close connection");
    eprintln!("[rpc-client] connection closed");
}
