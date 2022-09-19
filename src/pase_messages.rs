use crate::tlv_codec::*;

#[derive(Debug, Clone, PartialEq)]
pub struct PbkdfParamRequest {
    pub random: [u8; 32],
    pub session_id: u16,
    pub passcode_id: u8,
    pub has_pbkdf_parameters: bool,
    pub mrp_parameters_idle_retrans_timeout_ms: Option<u16>,
    pub mrp_parameters_active_retrans_timeout_ms: Option<u16>,
}

impl PbkdfParamRequest {
    pub fn from_tlv(data: &[u8]) -> PbkdfParamRequest {
        let tlv = decode(data);

        let mut random: Option<[u8; 32]> = None;
        let mut session_id: Option<u16> = None;
        let mut passcode_id: Option<u8> = None;
        let mut has_pbkdf_parameters: Option<bool> = None;
        let mut mrp_parameters_idle_retrans_timeout_ms: Option<u16> = None;
        let mut mrp_parameters_active_retrans_timeout_ms: Option<u16> = None;

        let mut element = tlv;
        let mut in_mrp_parameters = false;
        loop {
            match element.get_control() {
                TagControl::ContextSpecific(1) if !in_mrp_parameters => {
                    if let Value::ByteString(bytes) = element.get_value() {
                        random = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                TagControl::ContextSpecific(2) if !in_mrp_parameters => {
                    if let Value::Unsigned16(value) = element.get_value() {
                        session_id = Some(value);
                    }
                }
                TagControl::ContextSpecific(3) => {
                    if let Value::Unsigned8(value) = element.get_value() {
                        passcode_id = Some(value);
                    }
                }
                TagControl::ContextSpecific(4) => {
                    if let Value::Boolean(value) = element.get_value() {
                        has_pbkdf_parameters = Some(value);
                    }
                }
                TagControl::ContextSpecific(5) => {
                    in_mrp_parameters = true;
                }
                TagControl::ContextSpecific(1) if in_mrp_parameters => {
                    if let Value::Unsigned16(value) = element.get_value() {
                        mrp_parameters_idle_retrans_timeout_ms = Some(value);
                    }
                }
                TagControl::ContextSpecific(2) if in_mrp_parameters => {
                    if let Value::Unsigned16(value) = element.get_value() {
                        mrp_parameters_active_retrans_timeout_ms = Some(value);
                    }
                }
                _ => (),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        PbkdfParamRequest {
            random: random.unwrap(),
            session_id: session_id.unwrap(),
            passcode_id: passcode_id.unwrap(),
            has_pbkdf_parameters: has_pbkdf_parameters.unwrap(),
            mrp_parameters_idle_retrans_timeout_ms,
            mrp_parameters_active_retrans_timeout_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PbkdfParamResponse {
    pub peer_random: [u8; 32],
    pub random: [u8; 32],
    pub session_id: u16,
    pub pbkdf_parameters: Option<PbkdfParameters>,
    pub mrp_parameters_idle_retrans_timeout_ms: Option<u16>,
    pub mrp_parameters_active_retrans_timeout_ms: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PbkdfParameters {
    pub iteration: u16,
    pub salt: [u8; 32],
}

impl PbkdfParamResponse {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, 32),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.peer_random).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, 32),
            TagControl::ContextSpecific(2),
            Value::ByteString(heapless::Vec::from_slice(&self.random).unwrap()),
        );

        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(3),
            Value::Unsigned16(self.session_id),
        );

        if self.pbkdf_parameters.is_some() {
            encoder.write(
                TlvType::Structure,
                TagControl::ContextSpecific(4),
                Value::Container,
            );

            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte2),
                TagControl::ContextSpecific(1),
                Value::Unsigned16(self.pbkdf_parameters.as_ref().unwrap().iteration),
            );

            encoder.write(
                TlvType::ByteString(ElementSize::Byte1, 32),
                TagControl::ContextSpecific(2),
                Value::ByteString(
                    heapless::Vec::from_slice(&self.pbkdf_parameters.as_ref().unwrap().salt)
                        .unwrap(),
                ),
            );

            encoder.write(
                TlvType::EndOfContainer,
                TagControl::Anonymous,
                Value::Container,
            );
        }

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
pub struct PasePake1 {
    pub x: [u8; 65],
}

impl PasePake1 {
    pub fn from_tlv(data: &[u8]) -> PasePake1 {
        let tlv = decode(data);

        let mut x: Option<[u8; 65]> = None;

        let mut element = tlv;
        loop {
            match element.get_control() {
                TagControl::ContextSpecific(1) => {
                    if let Value::ByteString(bytes) = element.get_value() {
                        x = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                _ => (),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        PasePake1 { x: x.unwrap() }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PasePake2 {
    pub y: [u8; 65],
    pub verifier: [u8; 32],
}

impl PasePake2 {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, 65),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.y).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, 32),
            TagControl::ContextSpecific(2),
            Value::ByteString(heapless::Vec::from_slice(&self.verifier).unwrap()),
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
pub struct PasePake3 {
    pub verifier: [u8; 32],
}

impl PasePake3 {
    pub fn from_tlv(data: &[u8]) -> PasePake3 {
        let tlv = decode(data);

        let mut verifier: Option<[u8; 32]> = None;

        let mut element = tlv;
        loop {
            match element.get_control() {
                TagControl::ContextSpecific(1) => {
                    if let Value::ByteString(bytes) = element.get_value() {
                        verifier = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                _ => (),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        PasePake3 {
            verifier: verifier.unwrap(),
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::{format, println};

    extern crate std;

    #[test]
    fn test_decode_pbkdf_param_request() {
        let encoded = hex_literal::hex!("153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca250233dc240300280435052501881325022c011818");
        let msg = super::PbkdfParamRequest::from_tlv(&encoded);
        let wanted = super::PbkdfParamRequest {
            random: [
                71, 21, 164, 6, 198, 176, 73, 106, 213, 32, 57, 227, 71, 219, 133, 40, 203, 105,
                161, 203, 47, 206, 111, 35, 24, 85, 42, 230, 94, 16, 58, 202,
            ],
            session_id: 56371,
            passcode_id: 0,
            has_pbkdf_parameters: false,
            mrp_parameters_idle_retrans_timeout_ms: Some(5000),
            mrp_parameters_active_retrans_timeout_ms: Some(300),
        };
        println!("{:?}", msg);

        assert_eq!(wanted, msg);
    }

    #[test]
    fn test_encode_pbkdf_param_response() {
        let pbkdf_parameters = super::PbkdfParameters {
            iteration: 12322,
            salt: [
                71, 21, 164, 6, 198, 176, 73, 106, 213, 32, 57, 227, 71, 219, 133, 40, 203, 105,
                161, 203, 47, 206, 111, 35, 24, 85, 42, 230, 94, 16, 58, 202,
            ],
        };

        let msg = super::PbkdfParamResponse {
            peer_random: [
                71, 21, 164, 6, 198, 176, 73, 106, 213, 32, 57, 227, 71, 219, 133, 40, 203, 105,
                161, 203, 47, 206, 111, 35, 24, 85, 42, 230, 94, 16, 58, 202,
            ],
            random: [
                71, 21, 164, 6, 198, 176, 73, 106, 213, 32, 57, 227, 71, 219, 133, 40, 203, 105,
                161, 203, 47, 206, 111, 35, 24, 85, 42, 230, 94, 16, 58, 202,
            ],
            session_id: 4711,
            pbkdf_parameters: Some(pbkdf_parameters),
            mrp_parameters_idle_retrans_timeout_ms: Some(5000),
            mrp_parameters_active_retrans_timeout_ms: Some(300),
        };

        let encoded = msg.encode_tlv();

        println!("{:02x?}", &encoded.to_slice());

        assert_eq!(
            &[
                0x15, 0x30, 0x01, 0x20, 0x47, 0x15, 0xa4, 0x06, 0xc6, 0xb0, 0x49, 0x6a, 0xd5, 0x20,
                0x39, 0xe3, 0x47, 0xdb, 0x85, 0x28, 0xcb, 0x69, 0xa1, 0xcb, 0x2f, 0xce, 0x6f, 0x23,
                0x18, 0x55, 0x2a, 0xe6, 0x5e, 0x10, 0x3a, 0xca, 0x30, 0x02, 0x20, 0x47, 0x15, 0xa4,
                0x06, 0xc6, 0xb0, 0x49, 0x6a, 0xd5, 0x20, 0x39, 0xe3, 0x47, 0xdb, 0x85, 0x28, 0xcb,
                0x69, 0xa1, 0xcb, 0x2f, 0xce, 0x6f, 0x23, 0x18, 0x55, 0x2a, 0xe6, 0x5e, 0x10, 0x3a,
                0xca, 0x25, 0x03, 0x67, 0x12, 0x35, 0x04, 0x25, 0x01, 0x22, 0x30, 0x30, 0x02, 0x20,
                0x47, 0x15, 0xa4, 0x06, 0xc6, 0xb0, 0x49, 0x6a, 0xd5, 0x20, 0x39, 0xe3, 0x47, 0xdb,
                0x85, 0x28, 0xcb, 0x69, 0xa1, 0xcb, 0x2f, 0xce, 0x6f, 0x23, 0x18, 0x55, 0x2a, 0xe6,
                0x5e, 0x10, 0x3a, 0xca, 0x18, 0x35, 0x05, 0x25, 0x01, 0x88, 0x13, 0x25, 0x02, 0x2c,
                0x01, 0x18, 0x18
            ],
            &encoded.to_slice()
        );

        // TODO are there official test cases?
    }
}
