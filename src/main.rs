#![allow(dead_code, unused_assignments, unused_variables)]
pub(crate) mod dns;
use crate::dns::message::MessageBuilder;
use crate::dns::{Answer, Header, Label, MessageType, Question};
use std::net::UdpSocket;
use std::usize;

use dns::message::Message;
use nom::bits::complete::take;
use nom::IResult;
fn two_bytes_parser(
    input: (/*buf*/ &[u8], /*offset*/ usize),
    bit_count: usize,
) -> IResult<(&[u8], usize), u16> {
    take(bit_count)(input)
}
fn parser(input: (&[u8], usize), bit_count: usize) -> IResult<(&[u8], usize), u8> {
    take(bit_count)(input)
}

fn generic_parser<
    T: std::ops::Shr<usize, Output = T>
        + std::ops::Shl<usize, Output = T>
        + std::ops::AddAssign
        + std::convert::From<u8>,
>(
    input: (&[u8], usize),
    bit_count: usize,
) -> IResult<(&[u8], usize), T> {
    take(bit_count)(input)
}

fn parse_labels(
    buf: &[u8],
    full_req_buf: &[u8],
) -> anyhow::Result<(Option<Vec<Label>>, /*bytes_read*/ usize)> {
    let mut buf_offset: usize = 0;
    let mut bytes_read: usize = 0;
    let value: u8 = 0;
    let mut labels: Option<Vec<Label>> = None;

    loop {
        let value = buf[buf_offset];
        if value == 0 {
            // found the null byte
            return Ok((labels, bytes_read + 1)); // 1 for the null byte
        }
        let compression_bytes_mask = 0b11000000; // Read here https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
        let val = value & compression_bytes_mask;
        if val == 192 {
            let offset_octet = &buf[buf_offset..(buf_offset + 2)];
            let (_, uncompressed_offset) = two_bytes_parser((offset_octet, 2), 14).unwrap();
            let (uncompressed_labels, _) =
                parse_labels(&full_req_buf[uncompressed_offset as usize..], full_req_buf).unwrap();
            let mut uncompressed_labels = uncompressed_labels.unwrap(); // must contain labels.
            match labels.as_mut() {
                Some(labels) => labels.append(&mut uncompressed_labels),
                None => {
                    labels = Some(uncompressed_labels);
                }
            };
            return Ok((labels, bytes_read + 1));
        }

        bytes_read += 1;
        buf_offset += 1;
        let label: Vec<u8> = buf[buf_offset..(buf_offset + value as usize)].into();
        let label = Label::Uncompressed(label);
        match labels.as_mut() {
            Some(labels) => labels.push(label),
            None => {
                labels = Some(vec![label]);
            }
        };
        bytes_read += value as usize;
        buf_offset += value as usize;
    }
}

fn parse_question_section(
    question_count: u16,
    mut buf: &[u8],
    full_req_buf: &[u8],
) -> anyhow::Result<(Vec<Question>, /*bytes read*/ usize)> {
    let mut questions = vec![];
    let mut total_bytes_read = 0;
    for _ in 0..question_count {
        let (labels, mut bytes_read) = parse_labels(buf, full_req_buf).unwrap();

        let labels = labels.unwrap(); // there must be labels.
                                      // TODO: remove optional labels

        buf = &buf[bytes_read..];
        let (_, record_type) = two_bytes_parser((&buf[0..2], 0), 16).unwrap();
        let (_, class) = two_bytes_parser((&buf[2..], 0), 16).unwrap();
        let question = Question {
            labels,
            record_type,
            class,
        };
        bytes_read += 4;
        buf = &buf[4..];
        total_bytes_read += bytes_read;
        questions.push(question);
    }
    Ok((questions, total_bytes_read))
}

fn parse_header(msg_buf: &[u8]) -> anyhow::Result<Header> {
    let offset = 0;
    let ((rest, offset), _id) = two_bytes_parser((msg_buf, offset), 16).unwrap();

    let ((rest, offset), qr) = parser((rest, offset), 1).unwrap();
    let ((rest, offset), _opcode) = parser((rest, offset), 4).unwrap();
    let ((rest, offset), aa) = parser((rest, offset), 1).unwrap();
    let ((rest, offset), tc) = parser((rest, offset), 1).unwrap();
    let ((rest, offset), rd) = parser((rest, offset), 1).unwrap();
    let ((rest, offset), ra) = parser((rest, offset), 1).unwrap();
    let ((rest, offset), z) = parser((rest, offset), 3).unwrap();
    let ((rest, offset), rcode) = parser((rest, offset), 4).unwrap();
    let ((rest, offset), qdcount) = two_bytes_parser((rest, offset), 16).unwrap();
    let ((rest, offset), ancount) = two_bytes_parser((rest, offset), 16).unwrap();
    let ((rest, offset), nscount) = two_bytes_parser((rest, offset), 16).unwrap();
    let ((_rest, _offset), arcount) = two_bytes_parser((rest, offset), 16).unwrap();

    let aa = aa == 1;
    let tc = tc == 1;
    let rd = rd == 1;
    let ra = ra == 1;
    Ok(Header {
        id: _id,
        qr: MessageType::from(qr),
        opcode: _opcode,
        aa,
        tc,
        rd,
        ra,
        z,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    })
}

fn get_non_forwarded_dns_response_message(
    req_header: &Header,
    rcode: u8,
    req_questions: Vec<Question>,
) -> Message {
    let response = [0; 512];
    let res_header = Header {
        id: req_header.id,
        qr: MessageType::Response,
        opcode: req_header.opcode,
        aa: false,
        tc: false,
        rd: req_header.rd,
        ra: false,
        z: 0,
        rcode: rcode,
        qdcount: req_header.qdcount,
        ancount: req_header.qdcount,
        nscount: 0,
        arcount: 0,
    };

    let res_questions: Vec<_> = req_questions
        .iter()
        .map(|q| {
            // TODO: remove clone if possible.
            return Question {
                record_type: 1,
                labels: q.labels.iter().map(|l| l.clone()).collect(),
                class: 1,
            };
        })
        .collect();

    let res_answers = res_questions
        .iter()
        .map(|q| Answer {
            class: 1,
            labels: q.labels.iter().map(|l| l.clone()).collect(), //TODO: remove this
            record_type: q.record_type,
            ttl: 60,
            rdlength: 4,
            data: vec![8, 8, 8, 8],
        })
        .collect::<Vec<_>>();

    let builder = MessageBuilder::new();
    let message = builder
        .buf(response)
        .header(res_header)
        .questions(res_questions)
        .answers(res_answers)
        .build()
        .unwrap();
    message
}

fn get_answer_from_forward_dns(
    req_header: &Header,
    req_questions: &Vec<Question>,
    forward_dns_addr: &str,
) -> Message {
    let udp_socket = UdpSocket::bind("127.0.0.1:2054").expect("could not bind to 127.0.0.1:2054");
    udp_socket
        .connect(forward_dns_addr)
        .expect("could not connect to forward_dns_addr");
    let mut all_answers: Vec<Answer> = vec![];

    for ques in req_questions.iter() {
        let mut header = req_header.clone();
        header.qdcount = 1;
        header.opcode = 0;

        let mut ques = ques.clone();
        ques.class = 1;
        ques.record_type = 1;
        let questions = vec![ques];
        let forward_dns_req: [u8; 512] = [0; 512];
        let mut forward_dns_res: [u8; 512] = [0; 512];

        let message = MessageBuilder::new()
            .buf(forward_dns_req)
            .header(header)
            .questions(questions)
            .build()
            .expect("could not build message");

        let message_bytes = message.get_bytes_for_wire_transfer().unwrap();

        let _ = udp_socket
            .send(&message_bytes)
            .expect("could not send message to forward_dns_addr");

        let bytes = udp_socket
            .recv(&mut forward_dns_res)
            .expect("could not receive message from forward_dns_addr");

        let (header, questions, answers) = parse_message(&mut forward_dns_res).unwrap();
        let mut answers = answers.unwrap(); // forward_dns server will always give reply.
        all_answers.append(&mut answers);
    }
    let mut res_header = req_header.clone();
    res_header.qr = MessageType::Response;
    res_header.ancount = all_answers.len() as u16;
    res_header.rcode = match res_header.opcode {
        0 => 0,
        _ => 4,
    };

    MessageBuilder::new()
        .buf([0; 512])
        .header(res_header) // TODO: remove clone
        .questions(req_questions.clone())
        .answers(all_answers)
        .build()
        .unwrap()
}

fn parse_answer_section(
    answer_count: u16,
    mut buf: &[u8],
    full_req_buf: &[u8],
) -> anyhow::Result<(Vec<Answer>, usize)> {
    let mut ansers: Vec<Answer> = vec![];
    let mut total_bytes_read = 0;
    for _ in 0..answer_count {
        let (labels, mut bytes_read) =
            parse_labels(buf, full_req_buf).expect("could not parse labels in answer section");

        let labels = labels.expect("No labels found");
        buf = &buf[bytes_read..];
        let (_, record_type) = two_bytes_parser((&buf[0..2], 0), 16).unwrap();
        let (_, class) = two_bytes_parser((&buf[2..], 0), 16).unwrap();
        bytes_read += 4;
        buf = &buf[4..];

        let (_, ttl) = generic_parser::<u32>((&buf[0..4], 0), 32).unwrap();
        buf = &buf[4..];
        bytes_read += 4;
        let (_, rdlength) = generic_parser::<usize>((&buf[0..2], 0), 16).unwrap();
        buf = &buf[2..];
        bytes_read += 2;
        let data = buf[0..rdlength].iter().map(|x| *x).collect::<Vec<u8>>();
        buf = &buf[rdlength..];
        bytes_read += rdlength;
        let answer = Answer {
            labels,
            rdlength: rdlength as u16,
            data,
            ttl,
            class,
            record_type,
        };
        total_bytes_read += bytes_read;
        ansers.push(answer);
    }
    Ok((ansers, total_bytes_read))
}

fn parse_message(
    orig_buf: &mut [u8; 512],
) -> anyhow::Result<(Header, Vec<Question>, Option<Vec<Answer>>)> {
    let header = parse_header(&mut orig_buf[0..12]).unwrap(); // total bytes read will
                                                              // always be 12 for header.
    let mut buf = &orig_buf[12..];
    let (questions, _bytes_read) = parse_question_section(header.qdcount, buf, orig_buf).unwrap();
    if header.ancount == 0 {
        return Ok((header, questions, None));
    }
    buf = &buf[_bytes_read..];
    let (answers, _bytes_read) = parse_answer_section(header.ancount, buf, orig_buf).unwrap();
    Ok((header, questions, Some(answers)))
}

fn main() {
    let args = std::env::args();
    let n = args.len();
    let mut forward_dns_addr: Option<String> = None;
    if n == 3 {
        let lastarg = args.collect::<Vec<String>>()[2].clone(); // TODO: Remove clone.
        forward_dns_addr = Some(lastarg);
    }

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut orig_buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut orig_buf) {
            Ok((_size, source)) => {
                let (req_header, req_questions, _) = parse_message(&mut orig_buf).unwrap();
                let rcode = match req_header.opcode {
                    0 => 0,
                    _ => 4,
                };

                let message = match forward_dns_addr.as_ref() {
                    None => {
                        get_non_forwarded_dns_response_message(&req_header, rcode, req_questions)
                    }
                    Some(addr) => {
                        get_answer_from_forward_dns(&req_header, &req_questions, addr.as_str())
                    }
                };

                let response = message.get_bytes_for_wire_transfer().unwrap();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
