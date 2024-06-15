use std::io;

pub(crate) mod message {
    use anyhow::anyhow;

    use crate::dns::Header;

    use super::{Answer, Question};

    pub(crate) struct Message {
        buf: [u8; 512],
        pub(crate) header: Header,
        pub(crate) questions: Option<Vec<Question>>,
        pub(crate) answers: Option<Vec<Answer>>,
    }

    pub(crate) struct NoBuf;
    pub(crate) struct Buf([u8; 512]);

    pub(crate) struct MessageBuilder<B> {
        buf: B,
        header: Option<Header>,
        questions: Option<Vec<Question>>,
        answers: Option<Vec<Answer>>,
    }

    impl Default for MessageBuilder<NoBuf> {
        fn default() -> Self {
            Self {
                buf: NoBuf,
                header: None,
                questions: None,
                answers: None,
            }
        }
    }

    impl MessageBuilder<NoBuf> {
        pub(crate) fn new() -> Self {
            MessageBuilder::default()
        }
        pub(crate) fn buf(self, buf: [u8; 512]) -> MessageBuilder<Buf> {
            MessageBuilder {
                buf: Buf(buf),
                header: self.header,
                questions: self.questions,
                answers: self.answers,
            }
        }
    }

    impl MessageBuilder<Buf> {
        pub(crate) fn header(mut self, header: Header) -> Self {
            self.header = Some(header);
            self
        }
        pub(crate) fn questions(mut self, questions: Vec<Question>) -> Self {
            self.questions = Some(questions);
            self
        }

        pub(crate) fn answers(mut self, ansers: Vec<Answer>) -> Self {
            self.answers = Some(ansers);
            self
        }

        pub(crate) fn build(self) -> anyhow::Result<Message> {
            if self.header.is_none() {
                return Err(anyhow!("Header not found"));
            }
            let header = self.header.unwrap();
            let buf = self.buf.0;

            Ok(Message {
                header,
                buf,
                questions: self.questions,
                answers: self.answers,
            })
        }
    }

    impl Message {
        pub(crate) fn get_bytes_for_wire_transfer(mut self) -> anyhow::Result<[u8; 512]> {
            let mut offset = self.header.write(&mut self.buf)?;

            if let Some(questions) = self.questions {
                for question in questions.iter() {
                    let bytes = question.write(&mut self.buf[offset..])?;
                    offset += bytes;
                }
            }

            if let Some(answers) = self.answers {
                for answer in answers.iter() {
                    let bytes = answer.write(&mut self.buf[offset..])?;
                    offset += bytes;
                }
            }

            Ok(self.buf)
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum MessageType {
    Query,
    Response,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0 => MessageType::Query,
            1 => MessageType::Response,
            val => unreachable!("Invalid message type: {}", val),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Header {
    pub(crate) id: u16,         // 16 bits, id
    pub(crate) qr: MessageType, // 1 bit
    pub(crate) opcode: u8,      // 4 bits, Typically always 0, see RFC1035 for details.
    pub(crate) aa: bool,        // authorative_answer, 1 bit
    pub(crate) tc: bool,        // truncation 1 bit
    pub(crate) rd: bool,        // recursion_desired, 1 bit
    pub(crate) ra: bool,        // recursion_available, 1 bit
    pub(crate) z: u8,           // Reserved, 3 bits
    pub(crate) rcode: u8,       // response_code, 4 bits
    pub(crate) qdcount: u16,    // question_count, 16 bits
    pub(crate) ancount: u16,    // answer_count, 16 bits
    pub(crate) nscount: u16,    // authority_record_count, 16 bits
    pub(crate) arcount: u16,    // additional_record_count, 16 bits
}

impl Header {
    // returns number of bytes written successfully.
    pub(crate) fn write(&self, response_buf: &mut [u8]) -> io::Result<usize> {
        let id = self.id.to_be_bytes();
        response_buf[0..2].copy_from_slice(&id);

        let mut byte_buf: u8 = 0_u8.to_be();
        if self.qr == MessageType::Response {
            let msb_mask: u8 = 0b1000_0000; // 0b00001111 0b01111000
            byte_buf |= msb_mask;
        }
        {
            // writing opcode's 4 bit
            //let mask: u8 = 0b00001111;
            //byte_buf |= (self.opcode & mask) << 3;
            byte_buf |= self.opcode << 3;
        }

        if self.aa {
            let msb_mask: u8 = 0b0000_0100;
            byte_buf |= msb_mask;
        }
        if self.tc {
            let msb_mask: u8 = 0b0000_0010;
            byte_buf |= msb_mask;
        }
        if self.rd {
            let msb_mask: u8 = 0b0000_0001;
            byte_buf |= msb_mask;
        }

        response_buf[2] = byte_buf;
        byte_buf = 0;

        if self.ra {
            let msb_mask: u8 = 0b1000_0000;
            byte_buf |= msb_mask;
        }
        // NOTE: for now, the `z(response_code)` is always 0, that is why keeping next 3 bits untouched
        {
            byte_buf |= self.rcode
        }

        response_buf[3] = byte_buf;

        response_buf[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        response_buf[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        response_buf[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        response_buf[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        Ok(12) // it wrote 12 bytes.
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Label {
    Uncompressed(Vec<u8>),
    Compressed(u16 /*offset*/),
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        match self {
            Label::Uncompressed(buf) => buf.as_ref(),
            Label::Compressed(offset) => {
                unimplemented!()
            }
        }
    }
}

impl Label {
    fn write(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let mut curr_offset = 0;
        let len = match self {
            Label::Uncompressed(label) => label.len(),
            Label::Compressed(_) => {
                unimplemented!()
            }
        };
        buf[curr_offset] = len as u8;
        curr_offset += 1;
        buf[curr_offset..(curr_offset + len)].copy_from_slice(self.as_ref());
        curr_offset += len;
        Ok(curr_offset)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Question {
    pub(crate) labels: Vec<Label>,
    pub(crate) record_type: u16,
    pub(crate) class: u16,
}

#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) labels: Vec<Label>,
    pub(crate) record_type: u16, // TODO: convert the record_type to an Enum.
    pub(crate) class: u16,
    pub(crate) ttl: u32,
    pub(crate) rdlength: u16,
    pub(crate) data: Vec<u8>,
}

impl Answer {
    fn write(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let mut curr_offset: usize = 0;
        for label in self.labels.iter() {
            let bytes_written = label.write(&mut buf[curr_offset..])?;
            curr_offset += bytes_written;
        }
        buf[curr_offset] = 0; // null byte after the labels.
        curr_offset += 1;
        buf[curr_offset..(curr_offset + 2)].copy_from_slice(&self.record_type.to_be_bytes());
        curr_offset += 2;
        buf[curr_offset..(curr_offset + 2)].copy_from_slice(&self.class.to_be_bytes());
        curr_offset += 2;
        buf[curr_offset..(curr_offset + 4)].copy_from_slice(&self.ttl.to_be_bytes());
        curr_offset += 4;
        buf[curr_offset..(curr_offset + 2)].copy_from_slice(&self.rdlength.to_be_bytes());
        curr_offset += 2;
        buf[curr_offset..(curr_offset + 4)].copy_from_slice(self.data.as_ref());
        curr_offset += 4;
        Ok(curr_offset)
    }
}

impl Question {
    fn write(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let mut curr_offset: usize = 0;
        for label in self.labels.iter() {
            let bytes_written = label.write(&mut buf[curr_offset..])?;
            curr_offset += bytes_written;
        }
        buf[curr_offset] = 0; // null byte after the labels.
        curr_offset += 1;
        buf[curr_offset..(curr_offset + 2)].copy_from_slice(&self.record_type.to_be_bytes());
        curr_offset += 2;
        buf[curr_offset..(curr_offset + 2)].copy_from_slice(&self.class.to_be_bytes());
        Ok(curr_offset + 2)
    }
}
