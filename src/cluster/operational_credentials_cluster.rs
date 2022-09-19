use crate::tlv_codec::{decode, ElementSize, Encoder, TagControl, Tlv, TlvType, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateChainRequest {
    pub cert_type: u8,
}

impl CertificateChainRequest {
    pub fn from_tlv(data: &[u8]) -> CertificateChainRequest {
        let mut cert_type: Option<u8> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }

            match tlv.get_control() {
                TagControl::ContextSpecific(0) => {
                    cert_type = Some(tlv.get_value().unsigned_value() as u8);
                }
                _ => (),
            }

            tlv = tlv.next_in_container();
        }

        CertificateChainRequest {
            cert_type: cert_type.unwrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateChainResponse {
    pub certificate: heapless::Vec<u8, 1024>,
}

impl CertificateChainResponse {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.certificate.len()),
            TagControl::ContextSpecific(0),
            Value::ByteString(heapless::Vec::from_slice(&self.certificate).unwrap()),
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
pub struct RequestWithNonce {
    pub nonce: heapless::Vec<u8, 1024>,
}

impl RequestWithNonce {
    pub fn from_tlv(data: &[u8]) -> RequestWithNonce {
        let mut nonce: Option<heapless::Vec<u8, 1024>> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }

            match tlv.get_control() {
                TagControl::ContextSpecific(0) => {
                    if let Value::ByteString(v) = tlv.get_value() {
                        nonce = Some(heapless::Vec::from_slice(&v).unwrap());
                    }
                }
                _ => (),
            }

            tlv = tlv.next_in_container();
        }

        RequestWithNonce {
            nonce: nonce.unwrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttestationResponse {
    pub elements: heapless::Vec<u8, 1024>,
    pub signature: heapless::Vec<u8, 1024>,
}

impl AttestationResponse {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.elements.len()),
            TagControl::ContextSpecific(0),
            Value::ByteString(heapless::Vec::from_slice(&self.elements).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.signature.len()),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.signature).unwrap()),
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
pub struct Attestation {
    pub declaration: heapless::Vec<u8, 1024>,
    pub nonce: heapless::Vec<u8, 1024>,
    pub timestamp: u32,
    pub firmware_info: Option<heapless::Vec<u8, 1024>>,
}

impl Attestation {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.declaration.len()),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.declaration).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.nonce.len()),
            TagControl::ContextSpecific(2),
            Value::ByteString(heapless::Vec::from_slice(&self.nonce).unwrap()),
        );

        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte4),
            TagControl::ContextSpecific(3),
            Value::Unsigned32(self.timestamp),
        );

        if self.firmware_info.is_some() {
            let firmware_info = self.firmware_info.as_ref().unwrap();
            encoder.write(
                TlvType::ByteString(ElementSize::Byte2, firmware_info.len()),
                TagControl::ContextSpecific(4),
                Value::ByteString(heapless::Vec::from_slice(firmware_info).unwrap()),
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
pub struct CsrResponse {
    pub elements: heapless::Vec<u8, 1024>,
    pub signature: heapless::Vec<u8, 1024>,
}

impl CsrResponse {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.elements.len()),
            TagControl::ContextSpecific(0),
            Value::ByteString(heapless::Vec::from_slice(&self.elements).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.signature.len()),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.signature).unwrap()),
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
pub struct CertificateSigningRequest {
    pub csr: heapless::Vec<u8, 1024>,
    pub nonce: heapless::Vec<u8, 1024>,
    pub vendor_reserved_1: Option<heapless::Vec<u8, 1024>>,
    pub vendor_reserved_2: Option<heapless::Vec<u8, 1024>>,
    pub vendor_reserved_3: Option<heapless::Vec<u8, 1024>>,
}

impl CertificateSigningRequest {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.csr.len()),
            TagControl::ContextSpecific(1),
            Value::ByteString(heapless::Vec::from_slice(&self.csr).unwrap()),
        );

        encoder.write(
            TlvType::ByteString(ElementSize::Byte2, self.nonce.len()),
            TagControl::ContextSpecific(2),
            Value::ByteString(heapless::Vec::from_slice(&self.nonce).unwrap()),
        );

        if self.vendor_reserved_1.is_some() {
            let data = self.vendor_reserved_1.as_ref().unwrap();
            encoder.write(
                TlvType::ByteString(ElementSize::Byte2, data.len()),
                TagControl::ContextSpecific(3),
                Value::ByteString(heapless::Vec::from_slice(&data).unwrap()),
            );
        }

        if self.vendor_reserved_2.is_some() {
            let data = self.vendor_reserved_2.as_ref().unwrap();
            encoder.write(
                TlvType::ByteString(ElementSize::Byte2, data.len()),
                TagControl::ContextSpecific(4),
                Value::ByteString(heapless::Vec::from_slice(&data).unwrap()),
            );
        }

        if self.vendor_reserved_3.is_some() {
            let data = self.vendor_reserved_3.as_ref().unwrap();
            encoder.write(
                TlvType::ByteString(ElementSize::Byte2, data.len()),
                TagControl::ContextSpecific(5),
                Value::ByteString(heapless::Vec::from_slice(&data).unwrap()),
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
pub struct AddTrustedRootCertificateRequest {
    pub certificate: heapless::Vec<u8, 1024>,
}

impl AddTrustedRootCertificateRequest {
    pub fn from_tlv(data: &[u8]) -> AddTrustedRootCertificateRequest {
        let mut certificate: Option<heapless::Vec<u8, 1024>> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }

            match tlv.get_control() {
                TagControl::ContextSpecific(0) => {
                    if let Value::ByteString(v) = tlv.get_value() {
                        certificate = Some(heapless::Vec::from_slice(&v).unwrap());
                    }
                }
                _ => (),
            }

            tlv = tlv.next_in_container();
        }

        AddTrustedRootCertificateRequest {
            certificate: certificate.unwrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AddNocRequest {
    pub noc_cert: heapless::Vec<u8, 1024>,
    pub ica_cert: heapless::Vec<u8, 1024>,
    pub ipk_value: heapless::Vec<u8, 1024>,
    pub case_admin_node: u64,
    pub admin_vendor_id: u32,
}

impl AddNocRequest {
    pub fn from_tlv(data: &[u8]) -> AddNocRequest {
        let mut noc_cert: Option<heapless::Vec<u8, 1024>> = None;
        let mut ica_cert: Option<heapless::Vec<u8, 1024>> = None;
        let mut ipk_value: Option<heapless::Vec<u8, 1024>> = None;
        let mut case_admin_node: Option<u64> = None;
        let mut admin_vendor_id: Option<u32> = None;

        let mut tlv = decode(data);
        loop {
            if tlv.is_last() {
                break;
            }

            match tlv.get_control() {
                TagControl::ContextSpecific(0) => {
                    if let Value::ByteString(v) = tlv.get_value() {
                        noc_cert = Some(heapless::Vec::from_slice(&v).unwrap());
                    }
                }
                TagControl::ContextSpecific(1) => {
                    if let Value::ByteString(v) = tlv.get_value() {
                        ica_cert = Some(heapless::Vec::from_slice(&v).unwrap());
                    }
                }
                TagControl::ContextSpecific(2) => {
                    if let Value::ByteString(v) = tlv.get_value() {
                        ipk_value = Some(heapless::Vec::from_slice(&v).unwrap());
                    }
                }
                TagControl::ContextSpecific(3) => {
                    case_admin_node = Some(tlv.get_value().unsigned_value());
                }
                TagControl::ContextSpecific(4) => {
                    admin_vendor_id = Some(tlv.get_value().unsigned_value() as u32);
                }
                _ => (),
            }

            tlv = tlv.next_in_container();
        }

        AddNocRequest {
            noc_cert: noc_cert.unwrap(),
            ica_cert: ica_cert.unwrap(),
            ipk_value: ipk_value.unwrap(),
            case_admin_node: case_admin_node.unwrap(),
            admin_vendor_id: admin_vendor_id.unwrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusResponse<'a> {
    pub status: u8,
    pub fabric_index: Option<u32>,
    pub debug_text: Option<&'a str>,
}

impl<'a> StatusResponse<'a> {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(0),
            Value::Unsigned8(self.status),
        );

        if self.fabric_index.is_some() {
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte4),
                TagControl::ContextSpecific(1),
                Value::Unsigned32(self.fabric_index.unwrap()),
            );
        }

        if self.debug_text.is_some() {
            let text = self.debug_text.unwrap();
            encoder.write(
                TlvType::String(ElementSize::Byte1, text.len()),
                TagControl::ContextSpecific(2),
                Value::String(heapless::Vec::from_slice(text.as_bytes()).unwrap()),
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

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::print;
    use std::{format, println};

    use crate::tlv_codec::Tlv;

    use super::Attestation;

    extern crate std;

    #[test]
    fn test_encode_decode_attestation() {
        let big = [0xff; 527];
        let small = [0xff; 32];
        let resp = Attestation {
            declaration: heapless::Vec::from_slice(&big).unwrap(),
            nonce: heapless::Vec::from_slice(&small).unwrap(),
            timestamp: 0,
            firmware_info: None,
        };

        let encoded = resp.encode_tlv();

        let mut tlv = crate::tlv_codec::decode(encoded.to_slice());

        loop {
            if tlv.is_last() {
                break;
            }
            println!(
                "{:?} {:?} {:?}",
                tlv.get_type(),
                tlv.get_control(),
                tlv.get_value()
            );
            tlv = tlv.next_in_container();
        }
    }
}
