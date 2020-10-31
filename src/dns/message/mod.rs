use anyhow::{anyhow, Result};
use std::{convert::TryFrom, net::Ipv4Addr, time::Duration};

mod parsers;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Message<'a> {
    pub header: Header,
    pub questions: Option<Vec<Question<'a>>>,
    pub answer: Option<Vec<ResourceRecord<'a>>>,
    pub authority: Option<Vec<ResourceRecord<'a>>>,
    pub additional: Option<Vec<ResourceRecord<'a>>>,
}

impl Message<'_> {
    pub fn from_packet<'a>(packet: &'a [u8]) -> Result<Message<'a>> {
        match parsers::parse_message(packet) {
            Ok((_, msg)) => Ok(msg),
            Err(err) => Err(anyhow!(
                "got error while parsing packet. Err: {:#}, raw_packet: {:04X?}",
                err,
                packet
            )),
        }
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
    Other(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use super::{Flags, Header, Message, MessageType, Question, ResourceData, ResourceRecord};
    use anyhow::Result;
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

        hashmap
    }
}
