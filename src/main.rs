// SPDX-FileCopyrightText: 2022 Moritz Hedtke <Moritz.Hedtke@t-online.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
mod async_serde;
mod cert_verifier;

use std::{
    io::SeekFrom,
    marker::PhantomData,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use async_serde::Codec;
use bytes::Bytes;
use cert_verifier::MutableClientCertVerifier;
use futures::{future::try_join, SinkExt};
use quinn::Endpoint;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::StreamDeserializer;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use tokio_util::codec::{Decoder, Framed, FramedRead, FramedWrite};

use crate::cert_verifier::MutableWebPkiVerifier;

// https://briansmith.org/rustdoc/ring/digest/index.html
// https://briansmith.org/rustdoc/ring/signature/index.html
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

// our operation needs to be commutative
// if we want to store the entries in a non-deterministic order but still ordered by causality
// this needs to merge correctly

#[derive(Serialize, Deserialize)]
pub struct CmRDTEntry<T> {
    value: T,
    predecessors: Vec<String>,
    author: String,
    nonce: String,
    signature: String,
}

impl<T> CmRDTEntry<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            predecessors: Vec::new(),
            author: "".to_string(),
            nonce: "".to_string(),
            signature: "".to_string(),
        }
    }
}

trait Commutative {
    type Entry;
}

#[derive(Serialize)]
pub struct PositiveNegativeCounterEntry(i64);

pub struct PositiveNegativeCounter;

impl PositiveNegativeCounter {
    pub fn new() -> Self {
        Self {}
    }

    pub fn change_by(diff: i64) -> PositiveNegativeCounterEntry {
        PositiveNegativeCounterEntry(diff)
    }
}

// hash index
// https://en.wikipedia.org/wiki/Extendible_hashing

// https://docs.rs/tokio-util/latest/tokio_util/codec/index.html
// https://github.com/bincode-org/bincode
// https://docs.rs/serde_json/latest/serde_json/struct.StreamDeserializer.html

// https://github.com/serde-rs/json/issues/575

pub struct CmRDT<T> {
    framed: Framed<File, Codec<CmRDTEntry<T>>>,
}

impl<T: Serialize> CmRDT<T> {
    pub async fn new() -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .open("hello.txt")
            .await?;
        let framed = Framed::new(file, Codec::new());
        Ok(Self { framed })
    }

    pub async fn write_entry(&mut self, entry: CmRDTEntry<T>) -> anyhow::Result<()> {
        let file = self.framed.get_mut();
        file.seek(SeekFrom::End(0)).await?;
        self.framed.send(entry).await?;
        Ok(())
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

    connection.send_datagram(Bytes::from("this is a datagram"))?;

    let (mut send, mut recv) = connection.open_bi().await?;

    send.write_all(b"this was sent over quic").await?;
    send.finish().await?;

    let mut string = String::new();
    recv.read_to_string(&mut string).await?;

    println!("client got \"{}\" in {:?}", string, recv.id());

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

        let datagram = connection.read_datagram().await?;

        println!("datagram {}", std::str::from_utf8(&datagram).unwrap());

        let (mut send, mut recv) = connection.accept_bi().await?;

        let mut string = String::new();
        recv.read_to_string(&mut string).await?;

        println!("server got \"{}\" in {:?}", string, recv.id());

        send.write_all(b"server responded").await?;

        send.finish().await?;

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

            let mut crdt = CmRDT::<PositiveNegativeCounterEntry>::new().await?;

            crdt.write_entry(CmRDTEntry::<PositiveNegativeCounterEntry> {
                value: PositiveNegativeCounterEntry(1),
                predecessors: Vec::new(),
                author: String::new(),
                nonce: String::new(),
                signature: String::new(),
            })
            .await?;

            //let _result = try_join(client(), server()).await?;

            Ok(())
        })
}
