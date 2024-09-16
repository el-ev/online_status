use std::{error::Error, net::ToSocketAddrs, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    /// Run the program as a server
    #[arg(short = 's', long)]
    pub server: bool,
    /// Run the program as a client
    #[arg(short = 'c', long)]
    pub client: Option<String>,
    /// Port number
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Whether use HTTPS in client mode
    #[arg(long)]
    pub https: bool,
    /// Path to public key file (optional for server)
    #[arg(long, value_name = "FILE")]
    pub pubkey: Option<PathBuf>,
    /// Path to private key file (optional for client)
    #[arg(long, value_name = "FILE")]
    pub privkey: Option<PathBuf>,
}

pub fn try_parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = Args::try_parse()?;
    if args.server && args.client.is_some() {
        return Err("Cannot specify both server and client mode".into());
    }
    if !args.server && args.client.is_none() {
        return Err("Must specify either server or client mode".into());
    }
    if args.pubkey.is_some() && !args.pubkey.as_ref().unwrap().exists() {
        return Err("Public key file does not exist".into());
    }
    if args.privkey.is_some() && !args.privkey.as_ref().unwrap().exists() {
        return Err("Private key file does not exist".into());
    }
    if args.port.is_none() {
        args.port = Some(8080);
        println!("info: Port not specified, using default port 8080");
    }
    if args.client.is_some() {
        let addr_with_port = format!("{}:{}", args.client.as_ref().unwrap(), args.port.unwrap());
        let mut addrs = addr_with_port.to_socket_addrs()?;
        if addrs.next().is_none() {
            return Err("Invalid client address".into());
        }
    }
    if args.server && args.privkey.is_some() {
        println!("warn: Private key will not be used in server mode");
    }
    if args.client.is_some() && args.pubkey.is_some() {
        println!("warn: Public key will not be used in client mode");
    }
    Ok(args)
}
