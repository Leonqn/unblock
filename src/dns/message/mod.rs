use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

mod parsers;

#[derive(Debug, Clone)]
pub struct Query {
    request: Bytes,
    sender: Option<IpAddr>,
}

impl Query {
    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        let header = Header::from_packet(&bytes)?;
        if matches!(header.flags.message_type, MessageType::Query) {
            Ok(Self {
                request: bytes,
                sender: None,
            })
        } else {
            Err(anyhow!("Got dns response"))
        }
    }

    /// Build a minimal DNS A-record query for the given domain.
    pub fn for_domain(domain: &str) -> Self {
        let mut buf = Vec::with_capacity(32 + domain.len());
        // Header: ID=0x0001, flags=0x0100 (standard query, recursion desired), QDCOUNT=1
        buf.extend_from_slice(&[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: encode domain labels
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        Self {
            request: Bytes::from(buf),
            sender: None,
        }
    }

    pub fn set_sender(&mut self, sender: IpAddr) {
        self.sender = Some(sender);
    }

    pub fn sender(&self) -> Option<IpAddr> {
        self.sender
    }

    pub fn parse(&self) -> Result<Message<'_>> {
        Message::from_packet(self.bytes())
    }

    pub fn bytes(&self) -> &Bytes {
        &self.request
    }

    /// Returns a copy of the query with an EDNS Client Subnet opt-out (0.0.0.0/0).
    /// This tells recursive resolvers not to forward client subnet information.
    /// Only adds the OPT record if the query doesn't already have additional records.
    pub fn with_ecs_optout(&self) -> Query {
        let bytes = &self.request;
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);
        if arcount > 0 {
            return self.clone();
        }
        let mut buf = BytesMut::from(bytes.as_ref());
        buf[10..12].copy_from_slice(&1u16.to_be_bytes());
        // OPT record with ECS 0.0.0.0/0
        buf.extend_from_slice(&[
            0x00, // Name: root
            0x00, 0x29, // Type: OPT (41)
            0x10, 0x00, // UDP payload size: 4096
            0x00, 0x00, 0x00, 0x00, // Extended RCODE + flags
            0x00, 0x08, // RDLENGTH: 8
            0x00, 0x08, // Option code: EDNS Client Subnet (8)
            0x00, 0x04, // Option length: 4
            0x00, 0x01, // Family: IPv4
            0x00, // Source prefix-length: 0
            0x00, // Scope prefix-length: 0
        ]);
        Query {
            request: buf.freeze(),
            sender: self.sender,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    response: Bytes,
    trace: String,
}

impl Response {
    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        let header = Header::from_packet(&bytes)?;
        if matches!(header.flags.message_type, MessageType::Response) {
            Ok(Self {
                response: bytes,
                trace: String::new(),
            })
        } else {
            Err(anyhow!("Got dns query"))
        }
    }

    pub fn parse(&self) -> Result<Message<'_>> {
        Message::from_packet(self.bytes())
    }

    pub fn bytes(&self) -> &Bytes {
        &self.response
    }

    pub fn trace(&self) -> &str {
        &self.trace
    }

    pub fn append_trace(&mut self, s: &str) {
        if !self.trace.is_empty() {
            self.trace.push_str("; ");
        }
        self.trace.push_str(s);
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Message<'a> {
    pub header: Header,
    pub questions: Option<Vec<Question<'a>>>,
    pub answer: Option<Vec<ResourceRecord<'a>>>,
    pub authority: Option<Vec<ResourceRecord<'a>>>,
    pub additional: Option<Vec<ResourceRecord<'a>>>,
}

impl<'m> Message<'m> {
    fn from_packet(packet: &[u8]) -> Result<Message<'_>> {
        match parsers::parse_message(packet) {
            Ok((_, msg)) => Ok(msg),
            Err(err) => Err(anyhow!(
                "got error while parsing dns message. Err: {:?}, raw_packet: {:02X?}",
                err,
                packet
            )),
        }
    }

    pub fn ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.answer
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
            .flatten()
            .filter_map(|r| match &r.data {
                ResourceData::Ipv4(ip) => Some(IpAddr::V4(*ip)),
                ResourceData::Ipv6(ip) => Some(IpAddr::V6(*ip)),
                ResourceData::Other(_) => None,
            })
    }

    pub fn domains(&self) -> impl Iterator<Item = String> + '_ {
        self.questions
            .iter()
            .flatten()
            .map(|q| q.name.as_slice())
            .map(|d| d.join("."))
    }

    pub fn min_ttl(&self) -> Option<Duration> {
        self.answer
            .iter()
            .chain(&self.authority)
            .flatten()
            .map(|r| r.ttl)
            .min()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum MessageType {
    Query,
    Response,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Flags {
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Header {
    pub id: u16,
    pub flags: Flags,
    pub questions: u16,
    pub answer_resource_records: u16,
    pub authority_resource_records: u16,
    pub additional_resource_records: u16,
}

impl Header {
    fn from_packet(packet: &[u8]) -> Result<Header> {
        match parsers::parse_header(packet) {
            Ok((_, header)) => Ok(header),
            Err(err) => Err(anyhow!(
                "got error while parsing dns header. Err: {:?}, raw_packet: {:02X?}",
                err,
                packet
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Question<'a> {
    pub name: Vec<&'a str>,
    pub type_: u16,
    pub class: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ResourceRecord<'a> {
    pub name: Vec<&'a str>,
    pub type_: u16,
    pub class: u16,
    pub ttl: Duration,
    pub data: ResourceData<'a>,
}

impl ResourceRecord<'_> {
    fn from_raw<'a>(
        name: Vec<&'a str>,
        type_: u16,
        class: u16,
        ttl: Duration,
        data: &'a [u8],
    ) -> Option<ResourceRecord<'a>> {
        let data = if class == 1 && type_ == 1 {
            ResourceData::Ipv4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?))
        } else if class == 1 && type_ == 28 {
            ResourceData::Ipv6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))
        } else {
            ResourceData::Other(data)
        };
        Some(ResourceRecord {
            name,
            type_,
            class,
            ttl,
            data,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ResourceData<'a> {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Other(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use super::{Flags, Header, Message, MessageType, Question, ResourceData, ResourceRecord};
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use std::{collections::HashMap, time::Duration};

    #[test]
    fn should_parse_pessages() -> Result<()> {
        for (packet, message) in prepare_messages() {
            let parsed = Message::from_packet(packet)?;
            assert_eq!(parsed, message);
        }
        Ok(())
    }

    fn prepare_messages() -> HashMap<&'static [u8], Message<'static>> {
        let mut hashmap = HashMap::new();

        hashmap.insert(
            &include_bytes!("../../../test/dns_packets/q_api.browser.yandex.com.bin")[..],
            Message {
                header: Header {
                    id: 0x6d5c,
                    flags: Flags {
                        message_type: MessageType::Query,
                    },
                    questions: 1,
                    answer_resource_records: 0,
                    authority_resource_records: 0,
                    additional_resource_records: 0,
                },
                questions: Some(vec![Question {
                    name: vec!["api", "browser", "yandex", "com"],
                    class: 1,
                    type_: 1,
                }]),
                answer: None,
                authority: None,
                additional: None,
            },
        );

        hashmap.insert(
            &include_bytes!("../../../test/dns_packets/a_api.browser.yandex.com.bin")[..],
            Message {
                header: Header {
                    id: 0x6d5c,
                    flags: Flags {
                        message_type: MessageType::Response,
                    },
                    questions: 1,
                    answer_resource_records: 1,
                    authority_resource_records: 0,
                    additional_resource_records: 0,
                },
                questions: Some(vec![Question {
                    name: vec!["api", "browser", "yandex", "com"],
                    class: 1,
                    type_: 1,
                }]),
                answer: Some(vec![ResourceRecord {
                    name: vec!["api", "browser", "yandex", "com"],
                    class: 1,
                    type_: 1,
                    data: ResourceData::Ipv4("213.180.193.234".parse().unwrap()),
                    ttl: Duration::from_secs(201),
                }]),
                authority: None,
                additional: None,
            },
        );

        hashmap.insert(
            include_bytes!("../../../test/dns_packets/q_www.google.com.bin"),
            Message {
                header: Header {
                    id: 0xa542,
                    flags: Flags {
                        message_type: MessageType::Query,
                    },
                    questions: 1,
                    answer_resource_records: 0,
                    authority_resource_records: 0,
                    additional_resource_records: 0,
                },
                questions: Some(vec![Question {
                    name: vec!["www", "google", "com"],
                    class: 1,
                    type_: 1,
                }]),
                answer: None,
                authority: None,
                additional: None,
            },
        );

        hashmap.insert(
            include_bytes!("../../../test/dns_packets/a_www.google.com.bin"),
            Message {
                header: Header {
                    id: 0xa542,
                    flags: Flags {
                        message_type: MessageType::Response,
                    },
                    questions: 1,
                    answer_resource_records: 6,
                    authority_resource_records: 0,
                    additional_resource_records: 0,
                },
                questions: Some(vec![Question {
                    name: vec!["www", "google", "com"],
                    class: 1,
                    type_: 1,
                }]),
                answer: Some(vec![
                    ResourceRecord {
                        name: vec!["www", "google", "com"],
                        class: 1,
                        type_: 1,
                        ttl: Duration::from_secs(126),
                        data: ResourceData::Ipv4("64.233.162.103".parse().unwrap()),
                    },
                    ResourceRecord {
                        name: vec!["www", "google", "com"],
                        class: 1,
                        type_: 1,
                        ttl: Duration::from_secs(126),
                        data: ResourceData::Ipv4("64.233.162.106".parse().unwrap()),
                    },
                    ResourceRecord {
                        name: vec!["www", "google", "com"],
                        class: 1,
                        type_: 1,
                        ttl: Duration::from_secs(126),
                        data: ResourceData::Ipv4("64.233.162.104".parse().unwrap()),
                    },
                    ResourceRecord {
                        name: vec!["www", "google", "com"],
                        class: 1,
                        type_: 1,
                        ttl: Duration::from_secs(126),
                        data: ResourceData::Ipv4("64.233.162.99".parse().unwrap()),
                    },
                    ResourceRecord {
                        name: vec!["www", "google", "com"],
                        class: 1,
                        type_: 1,
                        ttl: Duration::from_secs(126),
                        data: ResourceData::Ipv4("64.233.162.105".parse().unwrap()),
                    },
                    ResourceRecord {
                        name: vec!["www", "google", "com"],
                        class: 1,
                        type_: 1,
                        ttl: Duration::from_secs(126),
                        data: ResourceData::Ipv4("64.233.162.147".parse().unwrap()),
                    },
                ]),
                authority: None,
                additional: None,
            },
        );

        hashmap.insert(
            include_bytes!("../../../test/dns_packets/a_dmg.digitaltarget.ru.bin"),
            Message {
                header: Header {
                    id: 0xdc06,
                    flags: Flags {
                        message_type: MessageType::Response,
                    },
                    questions: 1,
                    answer_resource_records: 0,
                    authority_resource_records: 1,
                    additional_resource_records: 0,
                },
                questions: Some(vec![Question {
                    name: vec!["dmg", "digitaltarget", "ru"],
                    class: 1,
                    type_: 1,
                }]),
                answer: None,
                authority: Some(vec![ResourceRecord {
                    name: vec!["dmg", "digitaltarget", "ru"],
                    class: 1,
                    type_: 6,
                    ttl: Duration::from_secs(10),
                    data: ResourceData::Other(b"\x19\x66\x61\x6b\x65\x2d\x66\x6f\x72\x2d\x6e\x65\x67\x61\x74\x69\x76\x65\x2d\x63\x61\x63\x68\x69\x6e\x67\x07\x61\x64\x67\x75\x61\x72\x64\x03\x63\x6f\x6d\x00\x0a\x68\x6f\x73\x74\x6d\x61\x73\x74\x65\x72\xc0\x0c\x00\x01\x88\x94\x00\x00\x07\x08\x00\x00\x03\x84\x00\x09\x3a\x80\x00\x01\x51\x80")
                }]),
                additional: None,
            },
        );

        hashmap.insert(
            include_bytes!("../../../test/dns_packets/a_cname_www.youtube.com.bin"),
            Message {
                header: Header {
                    id: 0xb45e,
                    flags: Flags {
                        message_type: MessageType::Response,
                    },
                    questions: 1,
                    answer_resource_records: 3,
                    authority_resource_records: 0,
                    additional_resource_records: 0,
                },
                questions: Some(vec![Question {
                    name: vec!["www", "youtube", "com"],
                    class: 1,
                    type_: 1,
                }]),
                answer: Some(vec![ResourceRecord {
                    name: vec!["www", "youtube", "com"],
                    class: 1,
                    type_: 5,
                    ttl: Duration::from_secs(222),
                    data: ResourceData::Other(b"\x0a\x79\x6f\x75\x74\x75\x62\x65\x2d\x75\x69\x01\x6c\x06\x67\x6f\x6f\x67\x6c\x65\xc0\x18")
                },
                ResourceRecord {
                    name: vec!["youtube-ui", "l", "google", "com"],
                    class: 1,
                    type_: 5,
                    ttl: Duration::from_secs(222),
                    data: ResourceData::Other(b"\x0c\x77\x69\x64\x65\x2d\x79\x6f\x75\x74\x75\x62\x65\xc0\x38"),
                },ResourceRecord {
                    name: vec!["wide-youtube", "l", "google", "com"],
                    class: 1,
                    type_: 1,
                    ttl: Duration::from_secs(222),
                    data: ResourceData::Ipv4("64.233.161.198".parse().unwrap()),
                },
                ]),
                authority: None,
                additional: None,
            },
        );

        hashmap
    }
}
