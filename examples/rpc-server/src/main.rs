use std::fs::File;

use clap::Parser;
use fizz_rs::{CertificatePublic, DelegatedCredentialData, ServerTlsContext};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ServerCredentialJson {
    signatureScheme: u16,
    credentialPEM: String,
}

#[derive(Parser)]
#[command(about = "Tahini RPC server — listens with delegated TLS credentials")]
struct Args {
    /// Tahini secret key (hex, injected by sidecar)
    #[arg(long = "tahini-secret")]
    secret: String,

    /// Path to server delegated credential JSON
    #[arg(long = "tahini-dc")]
    dc_path: String,

    /// Path to parent TLS certificate
    #[arg(long = "tahini-dc-cert")]
    cert_path: String,

    /// Port to listen on
    #[arg(long, default_value_t = 8443)]
    port: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.secret.len() >= 16 {
        eprintln!("[rpc-server] tahini secret: {}...{}", &args.secret[..8], &args.secret[args.secret.len()-8..]);
    } else {
        eprintln!("[rpc-server] tahini secret: {}", args.secret);
    }
    eprintln!("[rpc-server] loading credential from {}", args.dc_path);
    eprintln!("[rpc-server] loading parent cert from {}", args.cert_path);

    let cert = CertificatePublic::load_from_file(&args.cert_path)
        .expect("failed to load parent certificate");

    let file = File::open(&args.dc_path).expect("failed to open delegated credential server JSON");
    let json: ServerCredentialJson = serde_json::from_reader(file)
        .expect("failed to parse delegated credential server JSON");
    let dc = DelegatedCredentialData::from_pem(&json.credentialPEM)
        .expect("failed to load delegated credential from PEM");

    let tls = ServerTlsContext::new(cert, dc).expect("failed to create server TLS context");

    let bind_addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&bind_addr).await.expect("failed to bind");
    eprintln!("[rpc-server] listening on {}", bind_addr);

    loop {
        let mut conn = match tls.accept(&listener).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[rpc-server] accept error: {}", e);
                continue;
            }
        };
        eprintln!("[rpc-server] client connected");

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("[rpc-server] read error: {}", e);
                        break;
                    }
                };
                let msg = String::from_utf8_lossy(&buf[..n]);
                eprintln!("[rpc-server] received: {}", msg);

                if let Err(e) = conn.write_all(&buf[..n]).await {
                    eprintln!("[rpc-server] write error: {}", e);
                    break;
                }
            }
            eprintln!("[rpc-server] client disconnected");
        });
    }
}
