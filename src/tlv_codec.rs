use crate::TlvAnyData;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),

    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),

    Boolean(bool),

    Float(f32),

    Double(f64),

    String(heapless::Vec<u8, 256>),

    ByteString(heapless::Vec<u8, 1024>),

    Null,

    Container,
    EndOfContainer,
}

impl Value {
    pub fn to_simple_tlv(&self) -> TlvAnyData {
        let mut encoder = Encoder::new();
        encoder.write(self.infert_tlv_type(), TagControl::Anonymous, self.clone());
        TlvAnyData::from_slice(encoder.to_slice()).unwrap()
    }

    pub fn to_bytes<const N: usize>(&self) -> heapless::Vec<u8, N> {
        let mut res: heapless::Vec<u8, N> = heapless::Vec::new();

        match self {
            Value::Signed8(v) => res.push(*v as u8).unwrap(),
            Value::Signed16(v) => res.extend_from_slice(&(v.to_le_bytes())).unwrap(),
            Value::Signed32(v) => res.extend_from_slice(&(v.to_le_bytes())).unwrap(),
            Value::Signed64(v) => res.extend_from_slice(&(v.to_le_bytes())).unwrap(),
            Value::Unsigned8(v) => res.extend_from_slice(&(v.to_le_bytes())).unwrap(),
            Value::Unsigned16(v) => res.extend_from_slice(&(v.to_le_bytes())).unwrap(),
            Value::Unsigned32(v) => res.extend_from_slice(&(v.to_le_bytes())).unwrap(),
            Value::Unsigned64(v) => res.extend_from_slice(&(v.to_le_bytes())).unwrap(),
            Value::Boolean(_v) => (),
            Value::Float(_v) => panic!("unsupported"),
            Value::Double(_v) => panic!("unsupported"),
            Value::String(v) => res.extend_from_slice(&v).unwrap(),
            Value::ByteString(v) => res.extend_from_slice(&v).unwrap(),
            Value::Null => (),
            Value::Container => (),
            Value::EndOfContainer => (),
        }

        res
    }

    pub fn unsigned_value(&self) -> u64 {
        match self {
            Value::Unsigned8(v) => *v as u64,
            Value::Unsigned16(v) => *v as u64,
            Value::Unsigned32(v) => *v as u64,
            Value::Unsigned64(v) => *v as u64,
            _ => 0xffffffff_ffffffff,
        }
    }

    pub fn vec<const N: usize>(&self) -> heapless::Vec<u8, N> {
        match self {
            Value::ByteString(v) => heapless::Vec::from_slice(&v).unwrap(),
            _ => heapless::Vec::new(),
        }
    }

    pub(crate) fn infert_tlv_type(&self) -> TlvType {
        match self {
            Value::Signed8(_) => TlvType::SignedInt(ElementSize::Byte1),
            Value::Signed16(_) => TlvType::SignedInt(ElementSize::Byte2),
            Value::Signed32(_) => TlvType::SignedInt(ElementSize::Byte4),
            Value::Signed64(_) => TlvType::SignedInt(ElementSize::Byte8),
            Value::Unsigned8(_) => TlvType::UnsignedInt(ElementSize::Byte1),
            Value::Unsigned16(_) => TlvType::UnsignedInt(ElementSize::Byte2),
            Value::Unsigned32(_) => TlvType::UnsignedInt(ElementSize::Byte4),
            Value::Unsigned64(_) => TlvType::UnsignedInt(ElementSize::Byte8),
            Value::Boolean(v) => TlvType::Boolean(*v),
            Value::Float(_) => TlvType::Float,
            Value::Double(_) => TlvType::Double,
            Value::String(c) => TlvType::String(ElementSize::Byte1, c.len()),
            Value::ByteString(c) => TlvType::String(ElementSize::Byte1, c.len()),
            Value::Null => TlvType::Null,
            Value::Container => panic!("Can't infer type of Value::Container"),
            Value::EndOfContainer => TlvType::EndOfContainer,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ElementSize {
    Byte1 = 0x00,
    Byte2 = 0x01,
    Byte4 = 0x02,
    Byte8 = 0x03,
}

impl ElementSize {
    fn to_byte(&self) -> u8 {
        match self {
            ElementSize::Byte1 => 0,
            ElementSize::Byte2 => 1,
            ElementSize::Byte4 => 2,
            ElementSize::Byte8 => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlvType {
    SignedInt(ElementSize),
    UnsignedInt(ElementSize),
    Boolean(bool),
    Float,
    Double,
    String(ElementSize, usize),
    ByteString(ElementSize, usize),
    Null,
    Structure,
    Array,
    List,
    EndOfContainer,
}

impl TlvType {
    fn from(data: &[u8], control: TagControl) -> Self {
        let skip = control.skip();
        let value = data[0] & 0x1f;
        match value {
            0x00 => TlvType::SignedInt(ElementSize::Byte1),
            0x01 => TlvType::SignedInt(ElementSize::Byte2),
            0x02 => TlvType::SignedInt(ElementSize::Byte4),
            0x03 => TlvType::SignedInt(ElementSize::Byte8),
            0x04 => TlvType::UnsignedInt(ElementSize::Byte1),
            0x05 => TlvType::UnsignedInt(ElementSize::Byte2),
            0x06 => TlvType::UnsignedInt(ElementSize::Byte4),
            0x07 => TlvType::UnsignedInt(ElementSize::Byte8),
            0x08 => TlvType::Boolean(false),
            0x09 => TlvType::Boolean(true),
            0x0a => TlvType::Float,
            0x0b => TlvType::Double,
            0x0c => TlvType::String(ElementSize::Byte1, data[1 + skip] as usize),
            0x0d => TlvType::String(
                ElementSize::Byte2,
                u16::from_le_bytes(data[1 + skip..][..2].try_into().unwrap()) as usize,
            ),
            0x0e => TlvType::String(
                ElementSize::Byte4,
                u32::from_le_bytes(data[1 + skip..][..4].try_into().unwrap()) as usize,
            ),
            0x0f => panic!("64bit string unsupported"),
            0x10 => TlvType::ByteString(ElementSize::Byte1, data[1 + skip] as usize),
            0x11 => TlvType::ByteString(
                ElementSize::Byte2,
                u16::from_le_bytes(data[1 + skip..][..2].try_into().unwrap()) as usize,
            ),
            0x12 => TlvType::ByteString(
                ElementSize::Byte4,
                u32::from_le_bytes(data[1 + skip..][..4].try_into().unwrap()) as usize,
            ),
            0x13 => panic!("64bit byte-string unsupported"),
            0x14 => TlvType::Null,
            0x15 => TlvType::Structure,
            0x16 => TlvType::Array,
            0x17 => TlvType::List,
            0x18 => TlvType::EndOfContainer,
            _ => panic!("Unknown TlvType {:02x}", value),
        }
    }

    fn to_bytes(&self) -> heapless::Vec<u8, 5> {
        let mut res = heapless::Vec::new();
        match self {
            TlvType::SignedInt(s) => res.push(0x00 + s.to_byte()).unwrap(),
            TlvType::UnsignedInt(s) => res.push(0x04 + s.to_byte()).unwrap(),
            TlvType::Boolean(value) => res.push(0x08 + if *value { 1 } else { 0 }).unwrap(),
            TlvType::Float => todo!(),
            TlvType::Double => todo!(),
            TlvType::String(s, len) => {
                res.push(0x0c + s.to_byte()).unwrap();
                match s {
                    ElementSize::Byte1 => res.push(*len as u8).unwrap(),
                    ElementSize::Byte2 => {
                        res.extend_from_slice(&(*len as u16).to_le_bytes()).unwrap()
                    }
                    ElementSize::Byte4 => {
                        res.extend_from_slice(&(*len as u32).to_le_bytes()).unwrap()
                    }
                    ElementSize::Byte8 => panic!(),
                };
            }
            TlvType::ByteString(s, len) => {
                res.push(0x10 + s.to_byte()).unwrap();
                match s {
                    ElementSize::Byte1 => res.push(*len as u8).unwrap(),
                    ElementSize::Byte2 => {
                        res.extend_from_slice(&(*len as u16).to_le_bytes()).unwrap()
                    }
                    ElementSize::Byte4 => {
                        res.extend_from_slice(&(*len as u32).to_le_bytes()).unwrap()
                    }
                    ElementSize::Byte8 => panic!(),
                };
            }
            TlvType::Null => res.push(0x14).unwrap(),
            TlvType::Structure => res.push(0x15).unwrap(),
            TlvType::Array => res.push(0x16).unwrap(),
            TlvType::List => res.push(0x17).unwrap(),
            TlvType::EndOfContainer => res.push(0x18).unwrap(),
        };

        res
    }

    fn content_len(&mut self) -> usize {
        match self {
            TlvType::SignedInt(ElementSize::Byte1) => 1,
            TlvType::SignedInt(ElementSize::Byte2) => 2,
            TlvType::SignedInt(ElementSize::Byte4) => 4,
            TlvType::SignedInt(ElementSize::Byte8) => 8,
            TlvType::UnsignedInt(ElementSize::Byte1) => 1,
            TlvType::UnsignedInt(ElementSize::Byte2) => 2,
            TlvType::UnsignedInt(ElementSize::Byte4) => 4,
            TlvType::UnsignedInt(ElementSize::Byte8) => 8,
            TlvType::Boolean(_) => 0,
            TlvType::Float => 4,
            TlvType::Double => 8,
            TlvType::String(ElementSize::Byte1, len) => *len,
            TlvType::String(ElementSize::Byte2, len) => *len,
            TlvType::String(ElementSize::Byte4, len) => *len,
            TlvType::String(ElementSize::Byte8, len) => *len,
            TlvType::ByteString(ElementSize::Byte1, len) => *len,
            TlvType::ByteString(ElementSize::Byte2, len) => *len,
            TlvType::ByteString(ElementSize::Byte4, len) => *len,
            TlvType::ByteString(ElementSize::Byte8, len) => *len,
            TlvType::Null => 0,
            TlvType::Structure => 0,
            TlvType::Array => 0,
            TlvType::List => 0,
            TlvType::EndOfContainer => 0,
        }
    }

    fn skip(&mut self) -> usize {
        match self {
            TlvType::SignedInt(ElementSize::Byte1) => 0,
            TlvType::SignedInt(ElementSize::Byte2) => 0,
            TlvType::SignedInt(ElementSize::Byte4) => 0,
            TlvType::SignedInt(ElementSize::Byte8) => 0,
            TlvType::UnsignedInt(ElementSize::Byte1) => 0,
            TlvType::UnsignedInt(ElementSize::Byte2) => 0,
            TlvType::UnsignedInt(ElementSize::Byte4) => 0,
            TlvType::UnsignedInt(ElementSize::Byte8) => 0,
            TlvType::Boolean(_) => 0,
            TlvType::Float => 0,
            TlvType::Double => 0,
            TlvType::String(ElementSize::Byte1, _len) => 1,
            TlvType::String(ElementSize::Byte2, _len) => 2,
            TlvType::String(ElementSize::Byte4, _len) => 4,
            TlvType::String(ElementSize::Byte8, _len) => 8,
            TlvType::ByteString(ElementSize::Byte1, _len) => 1,
            TlvType::ByteString(ElementSize::Byte2, _len) => 2,
            TlvType::ByteString(ElementSize::Byte4, _len) => 4,
            TlvType::ByteString(ElementSize::Byte8, _len) => 8,
            TlvType::Null => 0,
            TlvType::Structure => 0,
            TlvType::Array => 0,
            TlvType::List => 0,
            TlvType::EndOfContainer => 0,
        }
    }

    fn is_container(&self) -> bool {
        match self {
            TlvType::Structure => true,
            TlvType::Array => true,
            TlvType::List => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TagControl {
    Anonymous,
    ContextSpecific(u8),
    CommonProfile2Bytes([u8; 2]),
    CommonProfile4Bytes([u8; 4]),
    ImplicitProfile2Bytes([u8; 2]),
    ImplicitProfile4Bytes([u8; 4]),
    FullyQualified6Bytes([u8; 6]),
    FullyQualified8Bytes([u8; 8]),
}

impl TagControl {
    fn skip(&self) -> usize {
        match self {
            TagControl::Anonymous => 0,
            TagControl::ContextSpecific(_) => 1,
            TagControl::CommonProfile2Bytes(_) => 2,
            TagControl::CommonProfile4Bytes(_) => 4,
            TagControl::ImplicitProfile2Bytes(_) => 2,
            TagControl::ImplicitProfile4Bytes(_) => 4,
            TagControl::FullyQualified6Bytes(_) => 6,
            TagControl::FullyQualified8Bytes(_) => 8,
        }
    }

    fn to_bytes(&self) -> heapless::Vec<u8, 9> {
        let mut res = heapless::Vec::new();

        let control = match self {
            TagControl::Anonymous => 0x00,
            TagControl::ContextSpecific(byte) => {
                res.push(*byte).unwrap();
                0x20
            }
            TagControl::CommonProfile2Bytes(bytes) => {
                res.extend_from_slice(bytes).unwrap();
                0x40
            }
            TagControl::CommonProfile4Bytes(bytes) => {
                res.extend_from_slice(bytes).unwrap();
                0x60
            }
            TagControl::ImplicitProfile2Bytes(bytes) => {
                res.extend_from_slice(bytes).unwrap();
                0x80
            }
            TagControl::ImplicitProfile4Bytes(bytes) => {
                res.extend_from_slice(bytes).unwrap();
                0xa0
            }
            TagControl::FullyQualified6Bytes(bytes) => {
                res.extend_from_slice(bytes).unwrap();
                0xc0
            }
            TagControl::FullyQualified8Bytes(bytes) => {
                res.extend_from_slice(bytes).unwrap();
                0xd0
            }
        };

        res.insert(0, control).unwrap();

        res
    }
}

pub trait Tlv<'a> {
    fn get_type(&self) -> TlvType;

    fn get_control(&self) -> TagControl;

    fn next(&self) -> TlvData<'a>;

    fn read_to_bytes(&self) -> (TlvData<'a>, TlvAnyData);

    fn is_container(&self) -> bool;

    fn next_in_container(&self) -> TlvData<'a>;

    fn get_value(&self) -> Value;

    fn is_last(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq)]
pub struct TlvData<'a> {
    data: &'a [u8],
    index: usize,
    in_container: bool,
}

impl<'a> Tlv<'a> for TlvData<'a> {
    fn get_type(&self) -> TlvType {
        TlvType::from(&self.data[self.index..], self.get_control())
    }

    fn get_control(&self) -> TagControl {
        match self.data[self.index] & 0xe0 {
            0x00 => TagControl::Anonymous,
            0x20 => TagControl::ContextSpecific(self.data[self.index + 1]),
            0x40 => TagControl::CommonProfile2Bytes(
                self.data[self.index + 1..][..2].try_into().unwrap(),
            ),
            0x60 => TagControl::CommonProfile4Bytes(
                self.data[self.index + 1..][..4].try_into().unwrap(),
            ),
            0x80 => TagControl::ImplicitProfile2Bytes(
                self.data[self.index + 1..][..2].try_into().unwrap(),
            ),
            0xa0 => TagControl::ImplicitProfile4Bytes(
                self.data[self.index + 1..][..4].try_into().unwrap(),
            ),
            0xc0 => TagControl::FullyQualified6Bytes(
                self.data[self.index + 1..][..6].try_into().unwrap(),
            ),
            0xe0 => TagControl::FullyQualified8Bytes(
                self.data[self.index + 1..][..8].try_into().unwrap(),
            ),
            _ => panic!("Unknown control {:02x}", self.data[self.index]),
        }
    }

    fn is_container(&self) -> bool {
        self.get_type().is_container()
    }

    fn next(&self) -> TlvData<'a> {
        if !self.in_container {
            return self.next_in_container();
        }

        loop {
            let next = self.next_in_container();
            if next.get_type() == TlvType::EndOfContainer {
                break self.next_in_container();
            }
        }
    }

    /// Read the type (maybe container) into bytes and return the next element.
    fn read_to_bytes(&self) -> (TlvData<'a>, TlvAnyData) {
        if !self.is_container() {
            let mut encoder = Encoder::new();
            encoder.write(self.get_type(), self.get_control(), self.get_value());
            return (
                self.next_in_container(),
                TlvAnyData::from_slice(encoder.to_slice()).unwrap(),
            );
        }

        let mut outer_written = false;
        let mut depth = 1;
        let mut encoder = Encoder::new();
        let mut next = self.clone();
        loop {
            encoder.write(next.get_type(), next.get_control(), next.get_value());
            if outer_written && next.is_container() {
                depth += 1;
            }

            if next.get_type() == TlvType::EndOfContainer {
                depth -= 1;

                if depth == 0 {
                    return (
                        next.next_in_container(),
                        TlvAnyData::from_slice(encoder.to_slice()).unwrap(),
                    );
                }
            }

            outer_written = true;
            next = next.next_in_container();
        }
    }

    fn next_in_container(&self) -> TlvData<'a> {
        let skip =
            1 + self.get_type().skip() + self.get_control().skip() + self.get_type().content_len();
        let mut res = TlvData {
            data: self.data,
            index: self.index + skip,
            in_container: self.in_container,
        };

        if res.is_container() {
            res.in_container = true;
        }

        if res.get_type() == TlvType::EndOfContainer {
            res.in_container = false;
        }

        res
    }

    fn is_last(&self) -> bool {
        let skip =
            1 + self.get_type().skip() + self.get_control().skip() + self.get_type().content_len();

        self.index + skip >= self.data.len()
    }

    fn get_value(&self) -> Value {
        let skip = 1 + self.get_type().skip() + self.get_control().skip();
        match self.get_type() {
            TlvType::SignedInt(s) => match s {
                ElementSize::Byte1 => Value::Signed8(self.data[self.index + skip] as i8),
                ElementSize::Byte2 => Value::Signed16(i16::from_le_bytes(
                    self.data[self.index + skip..][..2].try_into().unwrap(),
                )),
                ElementSize::Byte4 => Value::Signed32(i32::from_le_bytes(
                    self.data[self.index + skip..][..4].try_into().unwrap(),
                )),
                ElementSize::Byte8 => Value::Signed64(i64::from_le_bytes(
                    self.data[self.index + skip..][..8].try_into().unwrap(),
                )),
            },
            TlvType::UnsignedInt(s) => match s {
                ElementSize::Byte1 => Value::Unsigned8(self.data[self.index + skip]),
                ElementSize::Byte2 => Value::Unsigned16(u16::from_le_bytes(
                    self.data[self.index + skip..][..2].try_into().unwrap(),
                )),
                ElementSize::Byte4 => Value::Unsigned32(u32::from_le_bytes(
                    self.data[self.index + skip..][..4].try_into().unwrap(),
                )),
                ElementSize::Byte8 => Value::Unsigned64(u64::from_le_bytes(
                    self.data[self.index + skip..][..8].try_into().unwrap(),
                )),
            },
            TlvType::Boolean(b) => Value::Boolean(b),
            TlvType::Float => todo!(),
            TlvType::Double => todo!(),
            TlvType::String(_s, len) => {
                let mut vec = heapless::Vec::new();
                vec.extend_from_slice(&self.data[self.index + skip..][..len])
                    .unwrap();
                Value::String(vec)
            }
            TlvType::ByteString(_s, len) => {
                let mut vec = heapless::Vec::new();
                vec.extend_from_slice(&self.data[self.index + skip..][..len])
                    .unwrap();
                Value::ByteString(vec)
            }
            TlvType::Null => Value::Null,
            TlvType::Structure => Value::Container,
            TlvType::Array => Value::Container,
            TlvType::List => Value::Container,
            TlvType::EndOfContainer => Value::EndOfContainer,
        }
    }
}

pub fn decode(data: &[u8]) -> TlvData {
    TlvData {
        data: data,
        index: 0,
        in_container: false,
    }
}

pub struct Encoder {
    data: heapless::Vec<u8, 1024>,
}

impl Encoder {
    pub fn new() -> Encoder {
        Encoder {
            data: heapless::Vec::new(),
        }
    }

    pub fn write(&mut self, tlv_type: TlvType, control: TagControl, value: Value) {
        let tlv_type_bytes = tlv_type.to_bytes();
        let control_bytes = control.to_bytes();
        self.data
            .push(tlv_type_bytes[0] | control_bytes[0])
            .unwrap();
        self.data.extend_from_slice(&control_bytes[1..]).unwrap();
        self.data.extend_from_slice(&tlv_type_bytes[1..]).unwrap();
        self.data
            .extend_from_slice(&value.to_bytes::<1024>())
            .unwrap();
    }

    pub fn write_raw(&mut self, control: TagControl, data: &[u8]) {
        let mut tlv = decode(data);
        self.write(tlv.get_type(), control, tlv.get_value());

        if tlv.is_last() {
            return;
        }

        tlv = tlv.next_in_container();
        loop {
            self.write(tlv.get_type(), tlv.get_control(), tlv.get_value());
            if tlv.is_last() {
                break;
            }
            tlv = tlv.next_in_container();
        }
    }

    pub fn to_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn to_vec<const N: usize>(&self) -> heapless::Vec<u8, N> {
        heapless::Vec::from_slice(self.to_slice()).unwrap()
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::{format, println};

    extern crate std;

    use crate::tlv_codec::TlvType;

    use super::{ElementSize, TagControl, Tlv, Value};

    #[test]
    fn test_decode1() {
        let encoded = hex_literal::hex!("153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca250233dc240300280435052501881325022c011818");

        let decoded = super::decode(&encoded);
        let mut indent = 0;

        let mut next = decoded;
        loop {
            let ind = format!("{:indent$}", "", indent = indent * 4);
            println!("{}{:?}", ind, next.get_type());
            println!("{}{:?}", ind, next.get_control());
            println!("{}{:?}", ind, next.get_value());
            println!("{}{:?}", ind, next.is_container());
            println!("{}{:?}", ind, next.is_last());
            println!();

            if next.is_container() {
                indent += 1;
            }

            next = next.next_in_container();

            if next.get_type() == TlvType::EndOfContainer {
                if indent > 0 {
                    indent -= 1;
                } else {
                    break;
                }
            }

            if next.is_last() {
                break;
            }
        }

        // TODO actually test something here!

        //assert!(false);
        //assert_eq!(wanted, decoded);
    }

    #[test]
    fn test_encode() {
        let wanted = hex_literal::hex!("153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca250233dc240300280435052501881325022c011818");
        let mut encoder = super::Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, 32),
            TagControl::ContextSpecific(1),
            Value::ByteString(
                heapless::Vec::from_slice(&[
                    71, 21, 164, 6, 198, 176, 73, 106, 213, 32, 57, 227, 71, 219, 133, 40, 203,
                    105, 161, 203, 47, 206, 111, 35, 24, 85, 42, 230, 94, 16, 58, 202,
                ])
                .unwrap(),
            ),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(2),
            Value::Unsigned16(56371),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(3),
            Value::Unsigned8(0),
        );
        encoder.write(
            TlvType::Boolean(false),
            TagControl::ContextSpecific(4),
            Value::Boolean(false),
        );
        encoder.write(
            TlvType::Structure,
            TagControl::ContextSpecific(5),
            Value::Container,
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(1),
            Value::Unsigned16(5000),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(2),
            Value::Unsigned16(300),
        );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            Value::Container,
        );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            Value::Container,
        );

        println!("{:02x?}", encoder.to_slice());
        assert_eq!(&wanted, encoder.to_slice());
    }
}
