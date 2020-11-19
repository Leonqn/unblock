use anyhow::{anyhow, Result};
use bytes::Bytes;

use async_trait::async_trait;

use crate::dns::message::{Header, MessageType};

#[async_trait]
pub trait DnsClient: Send + Sync {
    async fn send(&self, request: &DnsRequest) -> Result<DnsResponse>;
}

#[derive(Debug, Clone)]
pub struct DnsRequest {
    request: Bytes,
    header: Header,
}

impl DnsRequest {
    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        let header = Header::from_packet(&bytes)?;
        if matches!(header.flags.message_type, MessageType::Query) {
            Ok(Self {
                request: bytes,
                header,
            })
        } else {
            Err(anyhow!("Got dns response"))
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn bytes(&self) -> &Bytes {
        &self.request
    }
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    response: Bytes,
    header: Header,
}

impl DnsResponse {
    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        let header = Header::from_packet(&bytes)?;
        if matches!(header.flags.message_type, MessageType::Response) {
            Ok(Self {
                response: bytes,
                header,
            })
        } else {
            Err(anyhow!("Got dns response"))
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn bytes(&self) -> &Bytes {
        &self.response
    }
}
