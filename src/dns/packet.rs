use anyhow::{anyhow, Result};
use std::{convert::TryInto, net::Ipv4Addr};

pub fn extract_ips(dns_response: &[u8], ips: &mut Vec<Ipv4Addr>) -> Result<()> {
    let answers = dns_response
        .get(6..8)
        .and_then(|a| a.try_into().ok())
        .ok_or_else(|| anyhow!("can't find answers count"))?;
    let answers = u16::from_be_bytes(answers);
    if answers == 0 {
        return Ok(());
    }

    let questions = dns_response
        .get(4..6)
        .and_then(|q| q.try_into().ok())
        .ok_or_else(|| anyhow!("can't find questions count"))?;
    let questions = u16::from_be_bytes(questions);
    let answers_start = find_answers_start_idx(dns_response, questions)?;
    find_ips(dns_response, answers, answers_start, ips)
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
            .get(answers_start + 10..answers_start + 12)
            .and_then(|d| d.try_into().ok())
            .ok_or_else(|| anyhow!("can't get data size"))?;
        answers_start += 12 + u16::from_be_bytes(data_size) as usize;
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
            .enumerate()
            .find(|(_, b)| **b == 0)
            .ok_or_else(|| anyhow!("can't find label stop"))?
            .0
            + 5
            + size)
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::extract_ips;

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
