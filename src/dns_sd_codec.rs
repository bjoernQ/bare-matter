use core::str::{FromStr, Utf8Error};

#[derive(Debug, Clone, PartialEq)]
pub enum DnsCodecErr {
    BufferOverflow,
    Unparseable,
}

impl From<()> for DnsCodecErr {
    fn from(_: ()) -> Self {
        DnsCodecErr::BufferOverflow
    }
}

impl From<u8> for DnsCodecErr {
    fn from(_: u8) -> Self {
        DnsCodecErr::BufferOverflow
    }
}

impl From<Utf8Error> for DnsCodecErr {
    fn from(_: Utf8Error) -> Self {
        DnsCodecErr::BufferOverflow
    }
}

impl<const N: usize> From<heapless::String<N>> for DnsCodecErr {
    fn from(_: heapless::String<N>) -> Self {
        DnsCodecErr::BufferOverflow
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    Query = 0x0000,
    Response = 0x8400,
}

impl From<u16> for MessageType {
    fn from(val: u16) -> Self {
        match val {
            0x0000 => MessageType::Query,
            0x8400 => MessageType::Response,
            _ => panic!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub name: heapless::String<255>,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecordClass {
    IN,
    Other(u16),
}

impl From<u16> for RecordClass {
    fn from(val: u16) -> Self {
        match val {
            0x01 => RecordClass::IN,
            _ => RecordClass::Other(val),
        }
    }
}

impl Into<u16> for RecordClass {
    fn into(self) -> u16 {
        match self {
            RecordClass::IN => 0x01,
            RecordClass::Other(val) => val,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecordType {
    A = 0x01,
    PTR = 0x0C,
    TXT = 0x10,
    AAAA = 0x1C,
    SRV = 0x21,
    ANY = 0xFF,
}

impl From<u16> for RecordType {
    fn from(val: u16) -> Self {
        match val {
            0x01 => RecordType::A,
            0x0c => RecordType::PTR,
            0x10 => RecordType::TXT,
            0x1c => RecordType::SRV,
            _ => RecordType::ANY,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub name: heapless::String<255>,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32,
    pub value: DnsValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub message_type: MessageType,
    pub queries: heapless::Vec<Query, 8>,
    pub answers: heapless::Vec<Record, 16>,
    pub authorities: heapless::Vec<Record, 2>,
    pub additional_records: heapless::Vec<Record, 8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsValue {
    Ptr(heapless::String<255>),
    Srv(SrvRecordValue),
    Txt(heapless::Vec<heapless::String<55>, 10>),
    Aaaa(u8, u8, u8, u8, u8, u8),
    A(u8, u8, u8, u8),
    Any(heapless::Vec<u8, 255>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SrvRecordValue {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: heapless::String<255>,
}

pub fn decode(data: &[u8]) -> Result<DnsMessage, DnsCodecErr> {
    let transaction_id = u16::from_be_bytes(data[0..][..2].try_into().unwrap());
    let message_type = u16::from_be_bytes(data[2..][..2].try_into().unwrap());
    let queries_count = u16::from_be_bytes(data[4..][..2].try_into().unwrap());
    let answers_count = u16::from_be_bytes(data[6..][..2].try_into().unwrap());
    let authorities_count = u16::from_be_bytes(data[8..][..2].try_into().unwrap());
    let additional_records_count = u16::from_be_bytes(data[10..][..2].try_into().unwrap());

    let mut queries: heapless::Vec<Query, 8> = heapless::Vec::new();
    let mut idx = 12;
    for _ in 0..queries_count {
        let (len, query) = decode_query(&data[idx..], data)?;
        idx += len;
        if let Err(_) = queries.push(query) {
            log::warn!("Too many queries");
        }
    }

    let mut answers = heapless::Vec::new();
    for _ in 0..answers_count {
        let (len, query) = decode_record(&data[idx..], data)?;
        idx += len;
        if let Err(_) = answers.push(query) {
            log::warn!("Too many answers");
        }
    }

    let mut authorities = heapless::Vec::new();
    for _ in 0..authorities_count {
        let (len, query) = decode_record(&data[idx..], data)?;
        idx += len;
        if let Err(_) = authorities.push(query) {
            log::warn!("Too many authorities");
        }
    }

    let mut additional_records = heapless::Vec::new();
    for _ in 0..additional_records_count {
        let (len, query) = decode_record(&data[idx..], data)?;
        idx += len;
        if let Err(_) = additional_records.push(query) {
            log::warn!("Too many additional record");
        }
    }

    Ok(DnsMessage {
        transaction_id,
        message_type: message_type.into(),
        queries,
        answers,
        authorities,
        additional_records,
    })
}

fn decode_record(data: &[u8], all: &[u8]) -> Result<(usize, Record), DnsCodecErr> {
    let (len, name) = decode_qname(data, all)?;
    let record_type = u16::from_be_bytes(data[len..][..2].try_into().unwrap());
    let record_class = u16::from_be_bytes(data[len + 2..][..2].try_into().unwrap());
    let ttl = u32::from_be_bytes(data[len + 4..][..4].try_into().unwrap());
    let value_len = u16::from_be_bytes(data[len + 8..][..2].try_into().unwrap()) as usize;
    if data.len() < len + 10 + value_len {
        // shouldn't happen ... but does
        return Err(DnsCodecErr::BufferOverflow);
    }
    let bytes = &data[len + 10..][..value_len];
    let value = decode_value(bytes, record_type.into(), all)?;

    Ok((
        len + value_len + 10,
        Record {
            name,
            record_type: record_type.into(),
            record_class: record_class.into(),
            ttl,
            value,
        },
    ))
}

fn decode_value(data: &[u8], record_type: RecordType, all: &[u8]) -> Result<DnsValue, DnsCodecErr> {
    match record_type {
        RecordType::A => Ok(DnsValue::A(data[0], data[1], data[2], data[3])),
        RecordType::PTR => {
            let (_, name) = decode_qname(data, all)?;
            Ok(DnsValue::Ptr(name))
        }
        RecordType::TXT => {
            let mut res = heapless::Vec::new();
            let mut idx = 0;
            while idx < data.len() {
                let len = data[idx] as usize;
                let s = core::str::from_utf8(&data[idx + 1..][..len])?;
                res.push(heapless::String::from_str(s)?)?;
                idx += 1 + len;
            }
            Ok(DnsValue::Txt(res))
        }
        RecordType::AAAA => Ok(DnsValue::Aaaa(
            data[0], data[1], data[2], data[3], data[4], data[5],
        )),
        RecordType::SRV => Ok(DnsValue::Srv(decode_srv(data, all)?)),
        RecordType::ANY => Ok(DnsValue::Any(heapless::Vec::from_slice(data)?)),
    }
}

fn decode_srv(data: &[u8], all: &[u8]) -> Result<SrvRecordValue, DnsCodecErr> {
    let priority = u16::from_be_bytes(data[0..][..2].try_into().unwrap());
    let weight = u16::from_be_bytes(data[2..][..2].try_into().unwrap());
    let port = u16::from_be_bytes(data[4..][..2].try_into().unwrap());
    let (_, target) = decode_qname(&data[6..], all)?;

    Ok(SrvRecordValue {
        priority,
        weight,
        port,
        target,
    })
}

fn decode_query(data: &[u8], all: &[u8]) -> Result<(usize, Query), DnsCodecErr> {
    let (len, name) = decode_qname(data, all)?;
    let record_type = u16::from_be_bytes(data[len..][..2].try_into().unwrap());
    let record_class = u16::from_be_bytes(data[len + 2..][..2].try_into().unwrap());

    Ok((
        len + 4,
        Query {
            name,
            record_type: record_type.into(),
            record_class: record_class.into(),
        },
    ))
}

fn decode_qname(data: &[u8], all: &[u8]) -> Result<(usize, heapless::String<255>), DnsCodecErr> {
    let mut res = heapless::String::new();
    let mut idx = 0;

    loop {
        let len = data[idx] as usize;

        if len == 0 {
            idx += 1;
            break;
        }

        if len & 0xc0 != 0 {
            // compressed qname
            let in_message_idx = (data[idx + 1] as usize | (len as usize & 0x3f) << 8) as usize;

            if in_message_idx >= all.len() {
                return Err(DnsCodecErr::Unparseable);
            }

            let (_len, name) = decode_qname(&all[in_message_idx..], all)?;
            if res.len() > 0 {
                res.push('.')?;
            }
            res.push_str(&name)?;
            idx += 2;
            break;
        }

        if res.len() > 0 {
            res.push('.')?;
        }
        res.push_str(core::str::from_utf8(&data[idx + 1..][..len])?)?;
        idx += 1 + len;
    }

    Ok((idx, res))
}

pub fn encode(msg: DnsMessage) -> Result<heapless::Vec<u8, 2048>, DnsCodecErr> {
    let mut buffer = heapless::Vec::new();

    buffer.extend_from_slice(&u16::to_be_bytes(msg.transaction_id))?;
    buffer.extend_from_slice(&u16::to_be_bytes(msg.message_type as u16))?;
    buffer.extend_from_slice(&u16::to_be_bytes(msg.queries.len() as u16))?;
    buffer.extend_from_slice(&u16::to_be_bytes(msg.answers.len() as u16))?;
    buffer.extend_from_slice(&u16::to_be_bytes(0))?;
    buffer.extend_from_slice(&u16::to_be_bytes(msg.additional_records.len() as u16))?;

    for query in &msg.queries {
        encode_qname(&query.name, &mut buffer)?;
        buffer.extend_from_slice(&u16::to_be_bytes(query.record_type.clone() as u16))?;
        buffer.extend_from_slice(&u16::to_be_bytes(query.record_class.clone().into()))?;
    }

    for record in &msg.answers {
        encode_qname(&record.name, &mut buffer)?;
        buffer.extend_from_slice(&u16::to_be_bytes(record.record_type.clone() as u16))?;
        buffer.extend_from_slice(&u16::to_be_bytes(record.record_class.clone().into()))?;
        buffer.extend_from_slice(&u32::to_be_bytes(record.ttl.clone().into()))?;
        let encoded_value = encode_value(&record.value)?;
        buffer.extend_from_slice(&u16::to_be_bytes(encoded_value.len() as u16))?;
        buffer.extend_from_slice(&encoded_value)?;
    }

    for record in &msg.additional_records {
        encode_qname(&record.name, &mut buffer)?;
        buffer.extend_from_slice(&u16::to_be_bytes(record.record_type.clone() as u16))?;
        buffer.extend_from_slice(&u16::to_be_bytes(record.record_class.clone().into()))?;
        buffer.extend_from_slice(&u32::to_be_bytes(record.ttl.clone().into()))?;
        let encoded_value = encode_value(&record.value)?;
        buffer.extend_from_slice(&u16::to_be_bytes(encoded_value.len() as u16))?;
        buffer.extend_from_slice(&encoded_value)?;
    }

    Ok(buffer)
}

fn encode_value(value: &DnsValue) -> Result<heapless::Vec<u8, 2048>, DnsCodecErr> {
    let mut buffer = heapless::Vec::new();

    match value {
        DnsValue::Ptr(ptr) => {
            encode_qname(ptr, &mut buffer)?;
        }
        DnsValue::Srv(srv) => {
            buffer.extend_from_slice(&u16::to_be_bytes(srv.priority))?;
            buffer.extend_from_slice(&u16::to_be_bytes(srv.weight))?;
            buffer.extend_from_slice(&u16::to_be_bytes(srv.port))?;
            encode_qname(&srv.target, &mut buffer)?;
        }
        DnsValue::Txt(txt) => {
            for entry in txt {
                buffer.push(entry.len() as u8)?;
                buffer.extend_from_slice(entry.as_bytes())?;
            }
        }
        DnsValue::Aaaa(a, b, c, d, e, f) => {
            buffer.push(*a)?;
            buffer.push(*b)?;
            buffer.push(*c)?;
            buffer.push(*d)?;
            buffer.push(*e)?;
            buffer.push(*f)?;
        }
        DnsValue::A(a, b, c, d) => {
            buffer.push(*a)?;
            buffer.push(*b)?;
            buffer.push(*c)?;
            buffer.push(*d)?;
        }
        DnsValue::Any(data) => {
            buffer.extend_from_slice(&data)?;
        }
    }

    Ok(buffer)
}

fn encode_qname(
    name: &heapless::String<255>,
    buffer: &mut heapless::Vec<u8, 2048>,
) -> Result<(), DnsCodecErr> {
    for part in name.split(".") {
        buffer.push(part.len() as u8)?;
        buffer.extend_from_slice(part.as_bytes())?
    }
    buffer.push(0)?;

    Ok(())
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::println;

    use crate::message_codec::{MessageHeader, PayloadHeader};

    extern crate std;
    use super::*;

    #[test]
    fn test_decode() {
        let _res = super::decode(&hex_literal::hex!("000000000003000200000001026c62075f646e732d7364045f756470056c6f63616c00000c00010f5f636f6d70616e696f6e2d6c696e6b045f746370c01c000c0001085f686f6d656b6974c037000c0001c027000c000100001194000a074b69746368656ec027c042000c00010000119400272441423645433741312d333837422d353235332d413835342d394441353236333535363746c04200002905a00000119400120004000e0099929387b033db4275a6a31b2d"));
        // todo check res
    }

    #[test]
    fn test_decode2() {
        let res = super::decode(&[
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x09, 0x5f,
            0x43, 0x43, 0x31, 0x41, 0x44, 0x38, 0x34, 0x35, 0x04, 0x5f, 0x73, 0x75, 0x62, 0x0b,
            0x5f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x63, 0x61, 0x73, 0x74, 0x04, 0x5f, 0x74,
            0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x78, 0x00, 0x2f, 0x2c, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2d, 0x48,
            0x6f, 0x6d, 0x65, 0x2d, 0x32, 0x39, 0x37, 0x34, 0x62, 0x35, 0x39, 0x39, 0x61, 0x66,
            0x33, 0x65, 0x32, 0x33, 0x32, 0x66, 0x62, 0x33, 0x30, 0x65, 0x37, 0x34, 0x61, 0x64,
            0x39, 0x34, 0x64, 0x33, 0x32, 0x34, 0x38, 0x62, 0xc0, 0x1b, 0xc0, 0x3d, 0x00, 0x10,
            0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0xba, 0x23, 0x69, 0x64, 0x3d, 0x32, 0x39,
            0x37, 0x34, 0x62, 0x35, 0x39, 0x39, 0x61, 0x66, 0x33, 0x65, 0x32, 0x33, 0x32, 0x66,
            0x62, 0x33, 0x30, 0x65, 0x37, 0x34, 0x61, 0x64, 0x39, 0x34, 0x64, 0x33, 0x32, 0x34,
            0x38, 0x62, 0x23, 0x63, 0x64, 0x3d, 0x30, 0x44, 0x41, 0x42, 0x41, 0x42, 0x34, 0x32,
            0x42, 0x42, 0x43, 0x41, 0x31, 0x31, 0x32, 0x42, 0x36, 0x42, 0x41, 0x42, 0x33, 0x32,
            0x46, 0x38, 0x37, 0x32, 0x42, 0x43, 0x44, 0x34, 0x36, 0x44, 0x13, 0x72, 0x6d, 0x3d,
            0x44, 0x45, 0x36, 0x32, 0x44, 0x34, 0x39, 0x44, 0x34, 0x42, 0x46, 0x36, 0x31, 0x41,
            0x35, 0x44, 0x05, 0x76, 0x65, 0x3d, 0x30, 0x35, 0x0e, 0x6d, 0x64, 0x3d, 0x47, 0x6f,
            0x6f, 0x67, 0x6c, 0x65, 0x20, 0x48, 0x6f, 0x6d, 0x65, 0x12, 0x69, 0x63, 0x3d, 0x2f,
            0x73, 0x65, 0x74, 0x75, 0x70, 0x2f, 0x69, 0x63, 0x6f, 0x6e, 0x2e, 0x70, 0x6e, 0x67,
            0x0d, 0x66, 0x6e, 0x3d, 0x57, 0x6f, 0x68, 0x6e, 0x7a, 0x69, 0x6d, 0x6d, 0x65, 0x72,
            0x09, 0x63, 0x61, 0x3d, 0x31, 0x39, 0x39, 0x31, 0x37, 0x32, 0x04, 0x73, 0x74, 0x3d,
            0x30, 0x0f, 0x62, 0x73, 0x3d, 0x46, 0x41, 0x38, 0x46, 0x43, 0x41, 0x37, 0x42, 0x32,
            0x31, 0x46, 0x32, 0x04, 0x6e, 0x66, 0x3d, 0x31, 0x03, 0x72, 0x73, 0x3d, 0xc0, 0x3d,
            0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00,
            0x1f, 0x49, 0x24, 0x32, 0x39, 0x37, 0x34, 0x62, 0x35, 0x39, 0x39, 0x2d, 0x61, 0x66,
            0x33, 0x65, 0x2d, 0x32, 0x33, 0x32, 0x66, 0x2d, 0x62, 0x33, 0x30, 0x65, 0x2d, 0x37,
            0x34, 0x61, 0x64, 0x39, 0x34, 0x64, 0x33, 0x32, 0x34, 0x38, 0x62, 0xc0, 0x2c, 0xc1,
            0x44, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x02,
            0x6e,
        ]);

        println!("{:?}", res);
    }

    #[test]
    fn test_decode3() {
        let _res = super::decode(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x5f,
            0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d,
            0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
            0x00, 0x0c, 0x00, 0x01, 0x04, 0x5f, 0x68, 0x75, 0x65, 0x04, 0x5f, 0x74, 0x63, 0x70,
            0xc0, 0x23, 0x00, 0x0c, 0x00, 0x01, 0x0b, 0x5f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
            0x63, 0x61, 0x73, 0x74, 0xc0, 0x33, 0x00, 0x0c, 0x00, 0x01, 0x0b, 0x5f, 0x67, 0x6f,
            0x6f, 0x67, 0x6c, 0x65, 0x7a, 0x6f, 0x6e, 0x65, 0xc0, 0x33, 0x00, 0x0c, 0x00, 0x01,
            0x08, 0x5f, 0x61, 0x72, 0x64, 0x75, 0x69, 0x6e, 0x6f, 0xc0, 0x33, 0x00, 0x0c, 0x00,
            0x01, 0x0d, 0x5f, 0x6e, 0x76, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x64, 0x62,
            0x64, 0xc0, 0x33, 0x00, 0x0c, 0x00, 0x01, 0x0b, 0x5f, 0x61, 0x6d, 0x7a, 0x6e, 0x2d,
            0x77, 0x70, 0x6c, 0x61, 0x79, 0xc0, 0x33, 0x00, 0x0c, 0x00, 0x01,
        ]);
    }

    #[test]
    fn test_encode() {
        let msg = DnsMessage {
            transaction_id: 1234,
            message_type: MessageType::Response,
            queries: heapless::Vec::new(),
            answers: heapless::Vec::from_slice(&[Record {
                name: heapless::String::from_str("_services._dns-sd._udp.local").unwrap(),
                record_type: RecordType::PTR,
                record_class: RecordClass::IN,
                ttl: 4500,
                value: super::DnsValue::Ptr(heapless::String::from_str("test").unwrap()),
            }])
            .unwrap(),
            authorities: heapless::Vec::new(),
            additional_records: heapless::Vec::from_slice(&[Record {
                name: heapless::String::from_str("_services._dns-sd._udp.local").unwrap(),
                record_type: RecordType::PTR,
                record_class: RecordClass::IN,
                ttl: 4500,
                value: super::DnsValue::Ptr(heapless::String::from_str("test").unwrap()),
            }])
            .unwrap(),
        };

        let res = super::encode(msg).unwrap();
        assert_eq!(&res, &super::encode(super::decode(&res).unwrap()).unwrap());
    }
}
