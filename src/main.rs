use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use log::{error, info, warn, Level, Log, Metadata, Record};
use pgp::{
    crypto::hash::HashAlgorithm,
    types::{KeyTrait, Mpi, PublicKeyTrait, SecretKeyTrait},
    Deserializable, SignedPublicKey,
};
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    error::Error,
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const TIMEOUT: u64 = 5;
const HEARTBEAT_INTERVAL: u64 = 60; // 1 minute
const OFFLINE_TIMEOUT: u64 = 300; // 5 minutes
const ZOMBIE_TIMEOUT: u64 = 3600; // 1 hour

const TEAPOT_BODY: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>418 I'm a teapot</title>
    <style>
        body {
            text-align: center;
            padding: 50px;
            font-family: ""Arial"", sans-serif;
        }

        h1 {
            font-size: 50px;
        }

        body {
            background-color: #f3f3f3;
        }

        .message {
            font-size: 20px;
        }
    </style>
</head>
<body>
    <h1>418</h1>
    <div class=""message"">
        I can't brew coffee, but I can brew tea.
    </div>
</body>
</html>"#;

static LOGGER: Logger = Logger;

pub struct Logger;

#[derive(Parser, Debug)]
struct Args {
    /// Run the program as a server
    #[arg(short = 's', long)]
    server: bool,
    /// Run the program as a client
    #[arg(short = 'c', long)]
    client: Option<String>,
    /// Port number
    #[arg(short = 'p', long)]
    port: Option<u16>,
    /// Whether use HTTPS in client mode
    #[arg(long)]
    https: bool,
    /// Path to public key file (optional for server)
    #[arg(long, value_name = "FILE")]
    pubkey: Option<PathBuf>,
    /// Path to private key file (optional for client)
    #[arg(long, value_name = "FILE")]
    privkey: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct AppState {
    clients: Arc<Mutex<HashMap<IpAddr, u64>>>, // IP address -> timestamp
    public_key: Arc<Option<pgp::SignedPublicKey>>,
}

#[derive(Serialize, Deserialize)]
struct ClientInfo {
    timestamp: u64,
    signature: Option<Vec<String>>,
}

#[tokio::main]
async fn main() {
    init_logging();
    let args = try_parse_args().await.unwrap_or_else(|e| {
        error!("{}", e);
        std::process::exit(1);
    });

    if args.server {
        server_main(args).await.unwrap_or_else(|e| {
            error!("{}", e);
            std::process::exit(1);
        });
    } else {
        client_main(args).await.unwrap_or_else(|e| {
            error!("{}", e);
            std::process::exit(1);
        });
    }
}

async fn server_main(args: Args) -> Result<(), Box<dyn Error>> {
    let public_key = if let Some(path) = args.pubkey {
        let content = std::fs::File::open(path).and_then(|mut f| {
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(s)
        })?;
        let (public_key, _) = SignedPublicKey::from_string(&content)?;
        Some(public_key)
    } else {
        None
    };
    let state = AppState {
        clients: Arc::new(Mutex::new(HashMap::new())),
        public_key: Arc::new(public_key),
    };
    let app = Router::new()
        .route("/", get(teapot))
        .route("/heartbeat", post(heartbeat))
        .route("/status", get(status))
        .with_state(state)
        .fallback(|| async { StatusCode::NOT_FOUND });

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", args.port.unwrap())).await?;
    info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
    Ok(())
}

async fn client_main(args: Args) -> Result<(), Box<dyn Error>> {
    let privkey = if let Some(path) = args.privkey {
        let content = std::fs::File::open(path).and_then(|mut f| {
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(s)
        })?;
        let (privkey, _) = pgp::SignedSecretKey::from_string(&content)?;
        if !privkey.is_signing_key() {
            return Err("Private key is not a signing key".into());
        }
        Some(privkey)
    } else {
        None
    };
    let client: reqwest::Client = reqwest::Client::new();
    loop {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = privkey.as_ref().map(|key| {
            key.create_signature(
                || "".to_string(),
                HashAlgorithm::default(),
                &timestamp.to_string().into_bytes(),
            )
            .unwrap()
        });
        let info = ClientInfo {
            timestamp,
            signature: signature.map(|s| s.into_iter().map(hex::encode).collect()),
        };

        let scheme = if args.https { "https" } else { "http" };
        let res = client
            .post(format!(
                "{}://{}:{}/heartbeat",
                scheme,
                args.client.as_ref().unwrap(),
                args.port.unwrap()
            ))
            .json(&info)
            .send()
            .await;
        match res {
            Ok(res) => {
                if res.status().is_success() {
                    if res.text().await? == "Heartbeat received" {
                        info!("Heartbeat sent");
                    } else {
                        error!("Heartbeat failed: invalid response");
                    }
                } else {
                    error!("Heartbeat failed: {}", res.status());
                }
            }
            Err(e) => {
                error!("Heartbeat failed: {}", e);
            }
        };

        tokio::time::sleep(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL)).await;
    }
}

async fn try_parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = Args::try_parse()?;
    if args.server && args.client.is_some() {
        return Err("Cannot specify both server and client mode".into());
    }
    if args.pubkey.is_some() && !args.pubkey.as_ref().unwrap().exists() {
        return Err("Public key file does not exist".into());
    }
    if args.privkey.is_some() && !args.privkey.as_ref().unwrap().exists() {
        return Err("Private key file does not exist".into());
    }
    if args.port.is_none() {
        args.port = Some(8080);
        info!("Port not specified, using default port 8080");
    }
    if args.client.is_some() {
        let addr_with_port = format!("{}:{}", args.client.as_ref().unwrap(), args.port.unwrap());
        let mut addrs = addr_with_port.to_socket_addrs()?;
        if addrs.next().is_none() {
            return Err("Invalid client address".into());
        }
    }
    if args.server && args.privkey.is_some() {
        warn!("Private key will not be used in server mode");
    }
    if args.client.is_some() && args.pubkey.is_some() {
        warn!("Public key will not be used in client mode");
    }
    Ok(args)
}

async fn teapot() -> impl IntoResponse {
    (
        StatusCode::IM_A_TEAPOT,
        [(header::CONTENT_TYPE, "text/html")],
        TEAPOT_BODY,
    )
}

async fn heartbeat(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(info): Json<ClientInfo>,
) -> Result<&'static str, StatusCode> {
    if let Some(public_key) = &*state.public_key {
        if let Some(signature) = info.signature {
            let signature: Vec<_> = signature
                .into_iter()
                .map(|s| Mpi::from_raw(hex::decode(s).unwrap()))
                .collect();
            public_key
                .verify_signature(
                    HashAlgorithm::default(),
                    &info.timestamp.to_string().into_bytes(),
                    &signature,
                )
                .map_err(|e| match e {
                    pgp::errors::Error::SignatureError(_) => StatusCode::UNAUTHORIZED,
                    _ => StatusCode::BAD_REQUEST,
                })?;
        } else {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now - info.timestamp > TIMEOUT {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut clients = state.clients.lock().unwrap();
    clients.insert(addr.ip(), now);
    Ok("Heartbeat received")
}

async fn status(State(state): State<AppState>) -> &'static str {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut clients = state.clients.lock().unwrap();
    for (_, last_seen) in clients.iter() {
        if last_seen + OFFLINE_TIMEOUT >= now {
            return "ONLINE";
        };
    }
    clients.retain(|_, last_seen| now - *last_seen <= ZOMBIE_TIMEOUT);
    "OFFLINE"
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("[{:5}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init_logging() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(Level::Info.to_level_filter());
}
