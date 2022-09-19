use crate::tlv_codec::*;

#[derive(Debug, Clone, PartialEq)]
pub struct CaseSigma1 {
    pub random: heapless::Vec<u8, 32>,
    pub session_id: u16,
    pub destination_id: heapless::Vec<u8, 32>,
    pub ecdh_public_key: heapless::Vec<u8, 67>,
    pub mrp_parameters_idle_retrans_timeout_ms: Option<u16>,
    pub mrp_parameters_active_retrans_timeout_ms: Option<u16>,

    pub resumption_id: Option<heapless::Vec<u8, 16>>,
    pub resume_mic: Option<heapless::Vec<u8, 16>>,
}

impl CaseSigma1 {
    pub fn from_tlv(data: &[u8]) -> CaseSigma1 {
        let mut random: Option<heapless::Vec<u8, 32>> = None;
        let mut session_id: Option<u16> = None;
        let mut destination_id: Option<heapless::Vec<u8, 32>> = None;
        let mut ecdh_public_key: Option<heapless::Vec<u8, 67>> = None;
        let mut mrp_parameters_idle_retrans_timeout_ms: Option<u16> = None;
        let mut mrp_parameters_active_retrans_timeout_ms: Option<u16> = None;
        let mut resumption_id: Option<heapless::Vec<u8, 16>> = None;
        let mut resume_mic: Option<heapless::Vec<u8, 16>> = None;

        let tlv = decode(data);

        let mut element = tlv;

        loop {
            if element.is_last() {
                break;
            }

            match element.get_control() {
                TagControl::ContextSpecific(1) => {
                    random = Some(element.get_value().vec());
                }
                TagControl::ContextSpecific(2) => {
                    session_id = Some(element.get_value().unsigned_value() as u16);
                }
                TagControl::ContextSpecific(3) => {
                    destination_id = Some(element.get_value().vec());
                }
                TagControl::ContextSpecific(4) => {
                    ecdh_public_key = Some(element.get_value().vec());
                }
                TagControl::ContextSpecific(5) => loop {
                    if element.is_last() {
                        break;
                    }

                    match element.get_control() {
                        TagControl::ContextSpecific(1) => {
                            mrp_parameters_idle_retrans_timeout_ms =
                                Some(element.get_value().unsigned_value() as u16);
                        }
                        TagControl::ContextSpecific(2) => {
                            mrp_parameters_active_retrans_timeout_ms =
                                Some(element.get_value().unsigned_value() as u16);
                        }
                        _ => (),
                    }

                    element = element.next_in_container();

                    if element.get_type() == TlvType::EndOfContainer {
                        break;
                    }
                },
                TagControl::ContextSpecific(6) => {
                    resumption_id = Some(element.get_value().vec());
                }
                TagControl::ContextSpecific(7) => {
                    resume_mic = Some(element.get_value().vec());
                }

                _ => (),
            }

            element = element.next_in_container();
        }

        CaseSigma1 {
            random: random.unwrap(),
            session_id: session_id.unwrap(),
            destination_id: destination_id.unwrap(),
            ecdh_public_key: ecdh_public_key.unwrap(),
            mrp_parameters_idle_retrans_timeout_ms: mrp_parameters_idle_retrans_timeout_ms,
            mrp_parameters_active_retrans_timeout_ms: mrp_parameters_active_retrans_timeout_ms,
            resumption_id: resumption_id,
            resume_mic: resume_mic,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaseSigma2 {
    pub random: heapless::Vec<u8, 32>,
    pub session_id: u16,
    pub ecdh_public_key: heapless::Vec<u8, 67>,
    pub encrypted: heapless::Vec<u8, 1024>,
    pub mrp_parameters_idle_retrans_timeout_ms: Option<u16>,
    pub mrp_parameters_active_retrans_timeout_ms: Option<u16>,
}

impl CaseSigma2 {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.random.len()),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.random).unwrap()),
        );

        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(2),
            Value::Unsigned16(self.session_id),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.ecdh_public_key.len()),
            TagControl::ContextSpecific(3),
            Value::ByteString(heapless::Vec::from_slice(&self.ecdh_public_key).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.encrypted.len()),
            TagControl::ContextSpecific(4),
            Value::ByteString(heapless::Vec::from_slice(&self.encrypted).unwrap()),
        );

        if self.mrp_parameters_active_retrans_timeout_ms.is_some()
            || self.mrp_parameters_idle_retrans_timeout_ms.is_some()
        {
            encoder.write(
                TlvType::Structure,
                TagControl::ContextSpecific(5),
                Value::Container,
            );

            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte2),
                TagControl::ContextSpecific(1),
                Value::Unsigned16(self.mrp_parameters_idle_retrans_timeout_ms.unwrap()),
            );

            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte2),
                TagControl::ContextSpecific(2),
                Value::Unsigned16(self.mrp_parameters_active_retrans_timeout_ms.unwrap()),
            );

            encoder.write(
                TlvType::EndOfContainer,
                TagControl::Anonymous,
                Value::Container,
            );
        }

        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            Value::Container,
        );

        encoder
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TagBasedSignatureData {
    pub new_op_cert: heapless::Vec<u8, 1024>,
    pub intermediate_ca_cert: Option<heapless::Vec<u8, 1024>>,
    pub ecdh_public_key: heapless::Vec<u8, 67>,
    pub peer_ecdh_public_key: heapless::Vec<u8, 67>,
}

impl TagBasedSignatureData {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.new_op_cert.len()),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.new_op_cert).unwrap()),
        );

        if self.intermediate_ca_cert.is_some() {
            encoder.write(
                TlvType::ByteString(
                    ElementSize::Byte1,
                    self.intermediate_ca_cert.as_ref().unwrap().len(),
                ),
                TagControl::ContextSpecific(2),
                Value::ByteString(
                    heapless::Vec::from_slice(&self.intermediate_ca_cert.as_ref().unwrap())
                        .unwrap(),
                ),
            );
        }

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.ecdh_public_key.len()),
            TagControl::ContextSpecific(3),
            Value::ByteString(heapless::Vec::from_slice(&self.ecdh_public_key).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.peer_ecdh_public_key.len()),
            TagControl::ContextSpecific(4),
            Value::ByteString(heapless::Vec::from_slice(&self.peer_ecdh_public_key).unwrap()),
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
pub struct TagBasedEcryptionData {
    pub new_op_cert: heapless::Vec<u8, 1024>,
    pub intermediate_ca_cert: Option<heapless::Vec<u8, 1024>>,
    pub signature: heapless::Vec<u8, 67>,
    pub resumption_id: Option<heapless::Vec<u8, 16>>,
}

impl TagBasedEcryptionData {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.new_op_cert.len()),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.new_op_cert).unwrap()),
        );

        if self.intermediate_ca_cert.is_some() {
            encoder.write(
                TlvType::ByteString(
                    ElementSize::Byte1,
                    self.intermediate_ca_cert.as_ref().unwrap().len(),
                ),
                TagControl::ContextSpecific(2),
                Value::ByteString(
                    heapless::Vec::from_slice(&self.intermediate_ca_cert.as_ref().unwrap())
                        .unwrap(),
                ),
            );
        }

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.signature.len()),
            TagControl::ContextSpecific(3),
            Value::ByteString(heapless::Vec::from_slice(&self.signature).unwrap()),
        );

        if self.resumption_id.is_some() {
            encoder.write(
                TlvType::ByteString(
                    ElementSize::Byte1,
                    self.resumption_id.as_ref().unwrap().len(),
                ),
                TagControl::ContextSpecific(4),
                Value::ByteString(
                    heapless::Vec::from_slice(&self.resumption_id.as_ref().unwrap()).unwrap(),
                ),
            );
        };

        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            Value::Container,
        );

        encoder
    }

    pub fn from_tlv(data: &[u8]) -> TagBasedEcryptionData {
        let mut new_op_cert: Option<heapless::Vec<u8, 1024>> = None;
        let mut intermediate_ca_cert: Option<heapless::Vec<u8, 1024>> = None;
        let mut signature: Option<heapless::Vec<u8, 67>> = None;
        let mut resumption_id: Option<heapless::Vec<u8, 16>> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }
            match tlv.get_control() {
                TagControl::ContextSpecific(1) => {
                    new_op_cert = Some(tlv.get_value().to_bytes());
                }
                TagControl::ContextSpecific(2) => {
                    intermediate_ca_cert = Some(tlv.get_value().to_bytes());
                }
                TagControl::ContextSpecific(3) => {
                    signature = Some(tlv.get_value().to_bytes());
                }
                TagControl::ContextSpecific(4) => {
                    resumption_id = Some(tlv.get_value().to_bytes());
                }
                _ => {}
            }

            tlv = tlv.next_in_container();
        }

        TagBasedEcryptionData {
            new_op_cert: new_op_cert.unwrap(),
            intermediate_ca_cert: intermediate_ca_cert,
            signature: signature.unwrap(),
            resumption_id: resumption_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaseSigma3 {
    pub encrypted: heapless::Vec<u8, 1024>,
}

impl CaseSigma3 {
    pub fn from_tlv(data: &[u8]) -> CaseSigma3 {
        let mut encrypted: Option<heapless::Vec<u8, 1024>> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }
            match tlv.get_control() {
                TagControl::ContextSpecific(1) => {
                    encrypted = Some(tlv.get_value().to_bytes());
                }
                _ => {}
            }

            tlv = tlv.next_in_container();
        }

        CaseSigma3 {
            encrypted: encrypted.unwrap(),
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::{format, println};

    extern crate std;

    #[test]
    fn test_decode_sigma1() {
        let encoded = [
            21, 48, 1, 32, 107, 65, 91, 35, 137, 236, 57, 15, 37, 157, 71, 6, 12, 100, 62, 249,
            234, 55, 16, 161, 241, 94, 148, 84, 22, 238, 206, 143, 17, 128, 146, 41, 37, 2, 164,
            82, 48, 3, 32, 21, 245, 100, 166, 138, 8, 10, 47, 213, 234, 149, 161, 231, 138, 104,
            42, 127, 179, 179, 188, 88, 108, 68, 25, 210, 228, 74, 253, 61, 247, 47, 199, 48, 4,
            65, 4, 58, 127, 245, 162, 251, 35, 249, 90, 104, 229, 18, 211, 216, 224, 122, 229, 56,
            114, 241, 252, 179, 39, 58, 117, 218, 58, 117, 251, 4, 107, 3, 140, 134, 47, 79, 59,
            117, 3, 182, 245, 239, 166, 124, 58, 61, 107, 249, 76, 39, 173, 124, 226, 15, 241, 232,
            9, 11, 81, 75, 228, 192, 220, 35, 86, 53, 5, 37, 1, 136, 19, 37, 2, 44, 1, 24, 24,
        ];

        let _decoded = super::CaseSigma1::from_tlv(&encoded);

        // panic!("{:?}", _decoded);
    }
}
