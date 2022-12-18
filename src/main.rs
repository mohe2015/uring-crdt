// SPDX-FileCopyrightText: 2022 Moritz Hedtke <Moritz.Hedtke@t-online.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_uring::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio_uring::start(async {
        // Open a file
        let file = File::open("hello.txt").await?;

        let buf = vec![0; 4096];
        // Read some data, the buffer is passed by ownership and
        // submitted to the kernel. When the operation completes,
        // we get the buffer back.
        let (res, buf) = file.read_at(buf, 0).await;
        let n = res?;

        // Display the contents
        println!("{:?}", &buf[..n]);

        Ok(())
    })
}