use client::client_main;
use config::try_parse_args;
use serde::{Deserialize, Serialize};
use server::server_main;

mod server;
mod client;
mod config;

const TIMEOUT: u64 = 5;
const HEARTBEAT_INTERVAL: u64 = 60; // 1 minute
const OFFLINE_TIMEOUT: u64 = 300; // 5 minutes
const ZOMBIE_TIMEOUT: u64 = 3600; // 1 hour

#[derive(Serialize, Deserialize)]
struct HeartBeat {
    timestamp: u64,
    signature: Option<Vec<String>>,
}

#[tokio::main]
async fn main() {
    let args = try_parse_args().unwrap_or_else(|e| {
        println!("error: {}", e);
        std::process::exit(1);
    });

    if args.server {
        server_main(args).await.unwrap_or_else(|e| {
            println!("error: {}", e);
            std::process::exit(1);
        });
    } else {
        client_main(args).await.unwrap_or_else(|e| {
            println!("error: {}", e);
            std::process::exit(1);
        });
    }
}