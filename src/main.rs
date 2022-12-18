// SPDX-FileCopyrightText: 2022 Moritz Hedtke <Moritz.Hedtke@t-online.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
mod cert_verifier;

use std::{
    error::Error,
    io::ErrorKind,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
};

use quinn::Endpoint;
use rustls::{client::ServerCertVerifier, Certificate, ClientConfig, PrivateKey, RootCertStore};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::cert_verifier::MutableWebPkiVerifier;

pub struct MyIdentity {
    private_key: PrivateKey,
}

impl MyIdentity {
    pub async fn new() -> anyhow::Result<Self> {
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open("private-key.der")
            .await
        {
            Ok(mut file) => {
                // TODO FIXME find out crypto algo
                let cert = rcgen::generate_simple_self_signed(vec![])?;
                file.write_all(&cert.serialize_private_key_der()).await?;
                file.sync_all().await?;
            }
            Err(error) => {
                if error.kind() != ErrorKind::AlreadyExists {
                    Err(error)?;
                }
            }
        }

        let mut file = OpenOptions::new()
            .read(true)
            .open("private-key.der")
            .await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        Ok(MyIdentity {
            private_key: PrivateKey(buffer),
        })
    }
}

pub struct CmRDT {
    file: File,
}

impl CmRDT {
    pub async fn new() -> anyhow::Result<Self> {
        Ok(Self {
            file: File::open("hello.txt").await?,
        })
    }
}

static SERVER_NAME: &str = "localhost";

fn client_addr() -> SocketAddr {
    "127.0.0.1:5000".parse::<SocketAddr>().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:5001".parse::<SocketAddr>().unwrap()
}

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            println!("Hello world");

            let identity = MyIdentity::new().await?;

            let server_verifier: Arc<MutableWebPkiVerifier> = Arc::new(MutableWebPkiVerifier {
                roots: RwLock::new(RootCertStore::empty()),
            });

            server_verifier
                .roots
                .write()
                .unwrap()
                .add_parsable_certificates(&Vec::new());

            let client_config = ClientConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_custom_certificate_verifier(server_verifier)
                .with_single_cert(vec![], identity.private_key)?;

            let mut endpoint = Endpoint::client(client_addr())?;

            let connection = endpoint
                .connect_with(
                    quinn::ClientConfig::new(Arc::new(client_config)),
                    server_addr(),
                    SERVER_NAME,
                )?
                .await?;

            Ok(())
        })
}
