use anyhow::{anyhow, Result};
use std::{convert::TryInto, net::Ipv4Addr};

#[derive(Debug)]
pub struct DnsPacket {
    buf: [u8; 512],
    size: usize,
}

impl DnsPacket {
    pub fn new(buf: [u8; 512], size: usize) -> Self {
        Self { buf, size }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[0..self.size]
    }

    pub fn is_response(&self) -> Result<bool> {
        is_response(self.as_slice())
    }

    pub fn id(&self) -> Result<u16> {
        get_id(self.as_slice())
    }
    pub fn extract_domains(&self, domains: &mut Vec<String>) -> Result<()> {
        extract_domains(self.as_slice(), domains)
    }
    pub fn extract_ips(&self, ips: &mut Vec<Ipv4Addr>) -> Result<()> {
        extract_ips(self.as_slice(), ips)
    }
}

fn is_response(dns_packet: &[u8]) -> Result<bool> {
    let flags = dns_packet.get(2).ok_or_else(|| anyhow!("Flags missing"))?;

    Ok(flags >> 7 == 1)
}

fn get_id(dns_packet: &[u8]) -> Result<u16> {
    dns_packet
        .get_u16_be(0)
        .ok_or_else(|| anyhow!("Dns packet less than 2 bytes"))
}

fn extract_domains(dns_request: &[u8], domains: &mut Vec<String>) -> Result<()> {
    let questions_count = dns_request
        .get_u16_be(4)
        .ok_or_else(|| anyhow!("can't find questions count"))?;
    let mut questions_start = 12;
    for _ in 0..questions_count {
        let domain_stop = dns_request
            .get(questions_start..)
            .ok_or_else(|| anyhow!("can't find question"))?
            .iter()
            .take_while(|x| **x != 0)
            .count()
            + questions_start;
        let domain = dns_request
            .get(questions_start..domain_stop)
            .and_then(parse_qname)
            .ok_or_else(|| anyhow!("can't find qname"))?
            .collect();
        domains.push(domain);
        questions_start += domain_stop + 5;
    }
    Ok(())
}

fn extract_ips(dns_response: &[u8], ips: &mut Vec<Ipv4Addr>) -> Result<()> {
    let answers = dns_response
        .get_u16_be(6)
        .ok_or_else(|| anyhow!("can't find answers count"))?;
    if answers == 0 {
        return Ok(());
    }

    let questions = dns_response
        .get_u16_be(4)
        .ok_or_else(|| anyhow!("can't find questions count"))?;
    let answers_start = find_answers_start_idx(dns_response, questions)?;
    find_ips(dns_response, answers, answers_start, ips)
}

fn parse_qname<'a>(qname: &'a [u8]) -> Option<impl Iterator<Item = char> + 'a> {
    let mut qname_iter = qname.iter();
    let label_len = u8::from_be(*qname_iter.next()?);

    Some(qname_iter.scan(label_len, |label_len, label_part| {
        if *label_len == 0 {
            *label_len = u8::from_be(*label_part);
            Some('.')
        } else {
            *label_len -= 1;
            Some(char::from(*label_part))
        }
    }))
}

fn find_ips(
    dns_packet: &[u8],
    answers: u16,
    mut answers_start: usize,
    ips: &mut Vec<Ipv4Addr>,
) -> Result<()> {
    let a_in_record = [0, 1, 0, 1];
    for _ in 0..answers {
        let record_type = &dns_packet
            .get(answers_start + 2..answers_start + 6)
            .ok_or_else(|| anyhow!("can't get record type"))?;

        if record_type == &a_in_record {
            let ip: [u8; 4] = dns_packet
                .get(answers_start + 12..answers_start + 16)
                .and_then(|i| i.try_into().ok())
                .ok_or_else(|| anyhow!("can't get ip"))?;
            ips.push(Ipv4Addr::from(ip));
        }
        let data_size = dns_packet
            .get_u16_be(answers_start + 10)
            .ok_or_else(|| anyhow!("can't get data size"))?;
        answers_start += 12 + data_size as usize;
    }
    Ok(())
}

fn find_answers_start_idx(dns_packet: &[u8], questions: u16) -> Result<usize> {
    let header_size = 12;

    (0..questions).try_fold(header_size, |size, _| {
        Ok(dns_packet
            .get(size..)
            .ok_or_else(|| anyhow!("can't find answers"))?
            .iter()
            .take_while(|b| **b != 0)
            .count()
            + 5
            + size)
    })
}

trait GetU16 {
    fn get_u16_be(&self, start_idx: usize) -> Option<u16>;
}

impl GetU16 for [u8] {
    fn get_u16_be(&self, start_idx: usize) -> Option<u16> {
        self.get(start_idx..start_idx + 2)
            .and_then(|q| q.try_into().ok())
            .map(u16::from_be_bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{extract_domains, extract_ips, is_response};

    #[test]
    fn test_is_request() {
        let dns_query = "ec1401000001000000000000067335357361730773746f726167650679616e646578036e65740000010001";
        let request = hex::decode(dns_query).unwrap();
        let dns_query = "3c1e818000010004000000000e643237787865376a7568317573360a636c6f756466726f6e74036e65740000010001c00c000100010000001b000436c0622bc00c000100010000001b000436c06211c00c000100010000001b000436c062a2c00c000100010000001b000436c0629d";
        let response = hex::decode(dns_query).unwrap();

        assert!(!is_response(&request).unwrap());
        assert!(is_response(&response).unwrap());
    }

    #[test]
    fn test_extract_domains() {
        let dns_query = "b97801000001000000000000067265706f72740a6170706d6574726963610679616e646578036e65740000010001";
        let dns_query = hex::decode(dns_query).unwrap();

        let mut questions = Vec::new();
        extract_domains(&dns_query, &mut questions).unwrap();
        assert!(questions.len() == 1);
        assert!(questions[0] == "report.appmetrica.yandex.net");
    }

    #[test]
    fn test_extract_domains_from_response() {
        let dns_query = "3c1e818000010004000000000e643237787865376a7568317573360a636c6f756466726f6e74036e65740000010001c00c000100010000001b000436c0622bc00c000100010000001b000436c06211c00c000100010000001b000436c062a2c00c000100010000001b000436c0629d";
        let dns_query = hex::decode(dns_query).unwrap();

        let mut questions = Vec::new();
        extract_domains(&dns_query, &mut questions).unwrap();
        assert!(questions.len() == 1);
        assert!(questions[0] == "d27xxe7juh1us6.cloudfront.net");
    }

    #[test]
    fn test_extract_ips_from_a_in() {
        let dns_response = "3c1e818000010004000000000e643237787865376a7568317573360a636c6f756466726f6e74036e65740000010001c00c000100010000001b000436c0622bc00c000100010000001b000436c06211c00c000100010000001b000436c062a2c00c000100010000001b000436c0629d";
        let dns_response = hex::decode(dns_response).unwrap();

        let mut ips = Vec::new();
        extract_ips(&dns_response, &mut ips).unwrap();

        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(54, 192, 98, 43),
                Ipv4Addr::new(54, 192, 98, 17),
                Ipv4Addr::new(54, 192, 98, 162),
                Ipv4Addr::new(54, 192, 98, 157),
            ]
        )
    }

    #[test]
    fn test_extract_ips_from_query() {
        let dns_response =
            "969a01000001000000000000087370636c69656e740277670773706f7469667903636f6d0000010001";
        let dns_response = hex::decode(dns_response).unwrap();

        let mut ips = Vec::new();
        extract_ips(&dns_response, &mut ips).unwrap();

        assert!(ips.is_empty())
    }

    #[test]
    fn test_extract_ips_from_resp_without_answer_rrs() {
        let dns_response =
            "148a8183000100000001000006766f727465780464617461096d6963726f736f667403636f6d0000010001c00c000600010000000a00451966616b652d666f722d6e656761746976652d63616368696e670761646775617264c0220a686f73746d6173746572c00c00018894000007080000038400093a8000015180";
        let dns_response = hex::decode(dns_response).unwrap();

        let mut ips = Vec::new();
        extract_ips(&dns_response, &mut ips).unwrap();

        assert!(ips.is_empty())
    }

    #[test]
    fn test_extract_ips_from_resp_with_different_answers() {
        let dns_response =
            "3db7818000010002000000000169047363646e02636f0000010001c00c000500010000011b001f067363646e636f0773706f74696679036d617006666173746c79036e657400c027000100010000000d0004976556f8";
        let dns_response = hex::decode(dns_response).unwrap();

        let mut ips = Vec::new();
        extract_ips(&dns_response, &mut ips).unwrap();

        assert_eq!(ips, vec![Ipv4Addr::new(151, 101, 86, 248)])
    }

    #[test]
    #[should_panic]
    fn test_extract_ips_from_bad_packet() {
        let dns_response =
            "3db78180010002000000000169047363646e02636f0000010001c00c000500010000011b001f067363646e636f0773706f74696679036d617006666173746c79036e657400c027000100010000000d0004976556f8";
        let dns_response = hex::decode(dns_response).unwrap();

        let mut ips = Vec::new();
        extract_ips(&dns_response, &mut ips).unwrap();
    }
}
