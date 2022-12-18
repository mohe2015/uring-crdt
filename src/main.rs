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

use cert_verifier::MutableClientCertVerifier;
use futures_util::future::try_join;
use quinn::Endpoint;
use rustls::{
    client::ServerCertVerifier, Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig,
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::cert_verifier::MutableWebPkiVerifier;

pub struct MyIdentity {
    certificate: Certificate,
    private_key: PrivateKey,
}

impl MyIdentity {
    pub async fn new(name: &str) -> anyhow::Result<Self> {
        let private_filename = format!("{}-key.der", name);
        let public_filename = format!("{}-cert.der", name);

        let mut private_file = OpenOptions::new()
            .read(true)
            .open(&private_filename)
            .await?;
        let mut private_buffer = Vec::new();
        private_file.read_to_end(&mut private_buffer).await?;

        let mut public_file = OpenOptions::new().read(true).open(&public_filename).await?;
        let mut public_buffer = Vec::new();
        public_file.read_to_end(&mut public_buffer).await?;

        Ok(MyIdentity {
            private_key: PrivateKey(private_buffer),
            certificate: Certificate(public_buffer),
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

async fn client() -> anyhow::Result<()> {
    let identity = MyIdentity::new("client").await?;

    let server_verifier: Arc<MutableWebPkiVerifier> = Arc::new(MutableWebPkiVerifier {
        roots: RwLock::new(RootCertStore::empty()),
    });

    server_verifier
        .roots
        .write()
        .unwrap()
        .add_parsable_certificates(&Vec::new());

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(server_verifier)
        .with_single_cert(vec![identity.certificate], identity.private_key)?;

    let mut endpoint = Endpoint::client(client_addr())?;

    let connection = endpoint
        .connect_with(
            quinn::ClientConfig::new(Arc::new(client_config)),
            server_addr(),
            SERVER_NAME,
        )?
        .await?;

    Ok(())
}

async fn server() -> anyhow::Result<()> {
    let identity = MyIdentity::new("server").await?;

    let client_cert_verifier = Arc::new(MutableClientCertVerifier {
        roots: RwLock::new(RootCertStore::empty()),
    });

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(vec![identity.certificate], identity.private_key)?;

    let endpoint = Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(server_config)),
        server_addr(),
    )?;

    // Start iterating over incoming connections.
    while let Some(conn) = endpoint.accept().await {
        let mut connection = conn.await?;

        println!("connected!");

        // Save connection somewhere, start transferring, receiving data, see DataTransfer tutorial.
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            println!("Hello world");

            let result = try_join(client(), server()).await?;

            Ok(())
        })
}
