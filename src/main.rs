// SPDX-FileCopyrightText: 2022 Moritz Hedtke <Moritz.Hedtke@t-online.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
mod cert_verifier;

use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use cert_verifier::MutableClientCertVerifier;
use futures_util::future::try_join;
use quinn::Endpoint;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
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
        let private_filename = format!("{name}-key.der");
        let public_filename = format!("{name}-cert.der");

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

static SERVER_NAME: &str = "example.org";

fn client_addr() -> SocketAddr {
    "127.0.0.1:5000".parse::<SocketAddr>().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:5001".parse::<SocketAddr>().unwrap()
}

async fn client() -> anyhow::Result<()> {
    let client_identity = MyIdentity::new("client").await?;
    let server_identity = MyIdentity::new("server").await?;

    let server_verifier: Arc<MutableWebPkiVerifier> = Arc::new(MutableWebPkiVerifier {
        roots: RwLock::new(RootCertStore::empty()),
    });

    server_verifier
        .roots
        .write()
        .unwrap()
        .add(&server_identity.certificate)?;

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(server_verifier)
        .with_single_cert(
            vec![client_identity.certificate],
            client_identity.private_key,
        )?;

    let endpoint = Endpoint::client(client_addr())?;

    let connection = endpoint
        .connect_with(
            quinn::ClientConfig::new(Arc::new(client_config)),
            server_addr(),
            SERVER_NAME,
        )?
        .await?;

    let (mut send, mut recv) = connection.open_bi().await?;

    send.write_all(b"this was sent over quic").await?;
    send.finish().await?;

    Ok(())
}

async fn server() -> anyhow::Result<()> {
    let server_identity = MyIdentity::new("server").await?;
    let client_identity = MyIdentity::new("client").await?;

    let client_cert_verifier = Arc::new(MutableClientCertVerifier {
        roots: RwLock::new(RootCertStore::empty()),
    });

    client_cert_verifier
        .roots
        .write()
        .unwrap()
        .add(&client_identity.certificate)?;

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(
            vec![server_identity.certificate],
            server_identity.private_key,
        )?;

    let endpoint = Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(server_config)),
        server_addr(),
    )?;

    // Start iterating over incoming connections.
    while let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;

        println!("connected!");

        let (mut send, mut recv) = connection.accept_bi().await?;

        let mut string = String::new();
        recv.read_to_string(&mut string).await?;

        println!("server gotr \"{}\" in {:?}", string, recv.id())

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

            //server().await?;

            let _result = try_join(client(), server()).await?;

            Ok(())
        })
}
