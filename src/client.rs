use crate::{config::Args, HeartBeat, HEARTBEAT_INTERVAL, TIMEOUT};
use pgp::{
    crypto::hash::HashAlgorithm,
    types::{KeyTrait, SecretKeyTrait},
    Deserializable, SignedSecretKey,
};
use std::{
    error::Error,
    fs::File,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time;

pub async fn client_main(args: Args) -> Result<(), Box<dyn Error>> {
    let privkey = if let Some(path) = args.privkey {
        let content = File::open(path).and_then(|mut f| {
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(s)
        })?;
        let (privkey, _) = SignedSecretKey::from_string(&content)?;
        if !privkey.is_signing_key() {
            return Err("Private key is not a signing key".into());
        }
        Some(privkey)
    } else {
        None
    };
    let client: reqwest::Client = reqwest::Client::new();
    loop {
        // On windows only send the heartbeat if the screen is not locked
        #[cfg(windows)]
        {
            if sysinfo::System::new_all()
                .processes()
                .iter()
                .any(|(_, p)| p.name().to_ascii_lowercase() == "logonui.exe")
            {
                tokio::time::sleep(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL)).await;
                continue;
            }
        }
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
        let info = HeartBeat {
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
            .timeout(time::Duration::from_secs(TIMEOUT))
            .send()
            .await;
        match res {
            Ok(res) => {
                if res.status().is_success() {
                    if res.text().await? == "Heartbeat received" {
                        println!("info: Heartbeat sent");
                    } else {
                        println!("error: Heartbeat failed: invalid response");
                    }
                } else {
                    println!("error: Heartbeat failed: {}", res.status());
                }
            }
            Err(e) => {
                println!("error: Heartbeat failed: {}", e);
            }
        };

        time::sleep(time::Duration::from_secs(HEARTBEAT_INTERVAL)).await;
    }
}
