// SPDX-FileCopyrightText: 2022 Moritz Hedtke <Moritz.Hedtke@t-online.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::error::Error;

use rustls::Certificate;
use tokio::{fs::{OpenOptions, File}, io::{AsyncWriteExt, AsyncReadExt}};

pub struct MyIdentity {
    // public and private key
    certificate: Certificate
}

impl MyIdentity {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        let cert = rcgen::generate_simple_self_signed(vec![])?;
        // don't accidentially overwrite the file
        let mut file = OpenOptions::new().create_new(true).open("private-key.pem").await?;
        file.write_all(&cert.serialize_private_key_der()).await?;
        file.sync_all().await?; 

        let mut file = OpenOptions::new().read(true).open("private-key.pem").await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        Ok(MyIdentity { 
            certificate: Certificate(buffer)
         })
    }
}

pub struct CmRDT {
    file: File,
}

impl CmRDT {

    pub async fn new() -> Result<Self, Box<dyn Error>> {

        Ok(Self {
            file: File::open("hello.txt").await?
        })
    }
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            println!("Hello world");
        })
}