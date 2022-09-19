use crate::tlv_codec::{decode, ElementSize, Encoder, TagControl, Tlv, TlvType, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct ArmFailSafeRequest {
    pub expiry_length_seconds: u16,
    pub bread_crumb: u16,
}

impl ArmFailSafeRequest {
    pub fn from_tlv(data: &[u8]) -> ArmFailSafeRequest {
        let mut expiry_length_seconds: Option<u16> = None;
        let mut bread_crumb: Option<u16> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }

            match tlv.get_control() {
                TagControl::ContextSpecific(0) => {
                    expiry_length_seconds = Some(tlv.get_value().unsigned_value() as u16);
                }
                TagControl::ContextSpecific(1) => {
                    bread_crumb = Some(tlv.get_value().unsigned_value() as u16);
                }
                _ => (),
            }

            tlv = tlv.next_in_container();
        }

        ArmFailSafeRequest {
            expiry_length_seconds: expiry_length_seconds.unwrap(),
            bread_crumb: bread_crumb.unwrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SuccessFailureReponse<'a> {
    pub error_code: u8,
    pub debug_text: &'a str,
}

impl<'a> SuccessFailureReponse<'a> {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(0),
            Value::Unsigned8(self.error_code),
        );
        encoder.write(
            TlvType::String(ElementSize::Byte1, self.debug_text.len()),
            TagControl::ContextSpecific(1),
            Value::String(heapless::Vec::from_slice(self.debug_text.as_bytes()).unwrap()),
        );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            Value::Container,
        );

        encoder
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetRegulatoryConfigRequest {
    pub config: u16,
    pub country_code: heapless::String<3>,
    pub bread_crumb: u16,
}

impl SetRegulatoryConfigRequest {
    pub fn from_tlv(data: &[u8]) -> SetRegulatoryConfigRequest {
        let mut config: Option<u16> = None;
        let mut country_code: Option<heapless::String<3>> = None;
        let mut bread_crumb: Option<u16> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }

            match tlv.get_control() {
                TagControl::ContextSpecific(0) => {
                    config = Some(tlv.get_value().unsigned_value() as u16);
                }
                TagControl::ContextSpecific(1) => {
                    if let Value::String(s) = tlv.get_value() {
                        let mut cc = heapless::String::new();
                        cc.push_str(core::str::from_utf8(&s).unwrap()).unwrap();
                        country_code = Some(cc);
                    }
                }
                TagControl::ContextSpecific(2) => {
                    bread_crumb = Some(tlv.get_value().unsigned_value() as u16);
                }
                _ => (),
            }

            tlv = tlv.next_in_container();
        }

        SetRegulatoryConfigRequest {
            config: config.unwrap(),
            country_code: country_code.unwrap(),
            bread_crumb: bread_crumb.unwrap(),
        }
    }
}
