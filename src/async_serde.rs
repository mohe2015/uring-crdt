// https://github.com/serde-rs/json/issues/575#issuecomment-918346326
use bytes::{Buf, BufMut};
use serde::{de::DeserializeOwned, Serialize};
use std::io::Write;
use std::marker::PhantomData;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read/write data: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("failed to decode/encode json: {source}")]
    Json { source: serde_json::Error },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Codec<T> {
    _type: PhantomData<T>,
}

impl<T> Codec<T> {
    pub fn new() -> Self {
        Self { _type: PhantomData }
    }
}

impl<T: DeserializeOwned> Decoder for Codec<T> {
    type Item = T;
    type Error = Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (v, consumed) = {
            let mut i = serde_json::Deserializer::from_slice(src).into_iter();
            let v = match i.next().unwrap_or(Ok(None)) {
                Ok(v) => Ok(v),
                Err(e) => {
                    if e.classify() == serde_json::error::Category::Eof {
                        Ok(None)
                    } else {
                        Err(Error::Json { source: e })
                    }
                }
            };
            (v, i.byte_offset())
        };
        src.advance(consumed);
        v
    }
}

impl<T, S: Serialize> Encoder<S> for Codec<T> {
    type Error = Error;

    fn encode(&mut self, item: S, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let mut w = dst.writer();
        serde_json::to_writer(&mut w, &item).map_err(|source| Error::Json { source })?;
        // NOTE: you may or may not need/want this
        w.write_all(b"\n")?;
        Ok(())
    }
}