use std::time::Duration;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{cond, flat_map, map, map_opt, map_res},
    error::{make_error, ErrorKind},
    multi::{count, many_till},
    number::complete::{be_u16, be_u32, be_u8},
    IResult, Parser,
};

use super::{Flags, Header, Message, MessageType, Question, ResourceRecord};

pub fn parse_message(packet: &[u8]) -> IResult<&[u8], Message<'_>> {
    let parse_resource_records = |count| move |i| parse_resource_records(count, packet, i);

    let parse_body = |header: Header| {
        let parse_body = (
            move |i| parse_questions(header.questions, i),
            parse_resource_records(header.answer_resource_records),
            parse_resource_records(header.authority_resource_records),
            parse_resource_records(header.additional_resource_records),
        );
        map(
            parse_body,
            move |(questions, answer, authority, additional)| Message {
                header,
                questions,
                answer,
                authority,
                additional,
            },
        )
    };
    let (rest, parsed) = flat_map(parse_header, parse_body).parse(packet)?;
    Ok((rest, parsed))
}

pub fn parse_header(packet: &[u8]) -> IResult<&[u8], Header> {
    let parse_header = (be_u16, parse_flags, be_u16, be_u16, be_u16, be_u16);
    map(
        parse_header,
        |(
            id,
            flags,
            questions,
            answer_resource_records,
            authority_resource_records,
            additional_resource_records,
        )| Header {
            id,
            flags,
            questions,
            answer_resource_records,
            authority_resource_records,
            additional_resource_records,
        },
    )
    .parse(packet)
}

fn parse_questions(
    questions_count: u16,
    questions: &[u8],
) -> IResult<&[u8], Option<Vec<Question<'_>>>> {
    cond(
        questions_count != 0,
        count(parse_question, questions_count as usize),
    )
    .parse(questions)
}

fn parse_resource_records<'a>(
    records_count: u16,
    packet: &'a [u8],
    records: &'a [u8],
) -> IResult<&'a [u8], Option<Vec<ResourceRecord<'a>>>> {
    cond(
        records_count != 0,
        count(|i| parse_resource_record(i, packet), records_count as usize),
    )
    .parse(records)
}

fn parse_resource_record<'a>(
    records: &'a [u8],
    packet: &'a [u8],
) -> IResult<&'a [u8], ResourceRecord<'a>> {
    let parse_name_and_pointer = |i| parse_name_and_pointer(i, packet);
    let parse_ttl = map(be_u32, |ttl| Duration::from_secs(ttl as u64));
    let parse_r_data = flat_map(be_u16, take);
    let resource_record = (
        parse_name_and_pointer,
        be_u16,
        be_u16,
        parse_ttl,
        parse_r_data,
    );
    map_opt(resource_record, |(name, type_, class, ttl, r_data)| {
        ResourceRecord::from_raw(name, type_, class, ttl, r_data)
    })
    .parse(records)
}

fn parse_name_and_pointer<'a>(
    records: &'a [u8],
    packet: &'a [u8],
) -> IResult<&'a [u8], Vec<&'a str>> {
    let parse_pointer_or_zero = alt((parse_pointer, map(tag("\0"), |_| 0)));
    let mut parse_name = many_till(parse_label, parse_pointer_or_zero);
    let (rest, (mut name, pointer)) = parse_name.parse(records)?;
    if pointer != 0 {
        if let Some(pointed) = packet.get(pointer as usize..) {
            let (_, pointed_names) = parse_name_and_pointer(pointed, packet)?;
            name.extend_from_slice(&pointed_names);
        } else {
            return Err(nom::Err::Failure(make_error(rest, ErrorKind::MapOpt)));
        }
    }
    Ok((rest, name))
}

fn parse_question(questions: &[u8]) -> IResult<&[u8], Question<'_>> {
    let parse_question = (parse_name, be_u16, be_u16);
    map(parse_question, |(name, type_, class)| Question {
        name,
        type_,
        class,
    })
    .parse(questions)
}

fn parse_name(label_part: &[u8]) -> IResult<&[u8], Vec<&str>> {
    map(many_till(parse_label, tag("\0")), |(name, _)| name).parse(label_part)
}

fn parse_pointer(label_part: &[u8]) -> IResult<&[u8], u16> {
    let parser = (
        nom::bits::complete::tag(3u8, 2u8),
        nom::bits::complete::take::<_, u16, _, nom::error::Error<_>>(14u8),
    );
    map(nom::bits::bits(parser), |(_, pointer)| pointer).parse(label_part)
}

fn parse_label(label_part: &[u8]) -> IResult<&[u8], &str> {
    map_res(flat_map(be_u8, take), std::str::from_utf8).parse(label_part)
}

fn parse_flags(flags: &[u8]) -> IResult<&[u8], Flags> {
    let qr_flag = nom::bits::bits(nom::bits::complete::take::<_, u8, _, nom::error::Error<_>>(
        1usize,
    ));
    map((qr_flag, be_u8), |(qr_flag, _)| {
        if qr_flag == 0 {
            Flags {
                message_type: MessageType::Query,
            }
        } else {
            Flags {
                message_type: MessageType::Response,
            }
        }
    })
    .parse(flags)
}
