use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use pgp::{
    crypto::hash::HashAlgorithm,
    types::{Mpi, PublicKeyTrait},
    Deserializable, SignedPublicKey,
};
use reqwest::header;
use std::{
    collections::HashMap,
    error::Error,
    io::Read,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{config::Args, HeartBeat, OFFLINE_TIMEOUT, TIMEOUT, ZOMBIE_TIMEOUT};

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

#[derive(Debug, Clone)]
struct AppState {
    clients: Arc<Mutex<HashMap<IpAddr, u64>>>, // IP address -> timestamp
    public_key: Arc<Option<pgp::SignedPublicKey>>,
}

pub async fn server_main(args: Args) -> Result<(), Box<dyn Error>> {
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
    println!("info: listening on {}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
    Ok(())
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
    Json(info): Json<HeartBeat>,
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
