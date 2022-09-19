use p256::SecretKey;

use crate::crypto::NotRandom;
use crate::tlv_codec::decode;
use crate::tlv_codec::{TagControl, Tlv, TlvType, Value};

pub struct Fabric {
    pub fabric_id: u64,
    pub node_id: u64,
    pub operational_id: heapless::Vec<u8, 16>,
    pub root_public_key: heapless::Vec<u8, 128>,
    pub key_pair: SecretKey,
    pub vendor_id: u32,
    pub root_cert: heapless::Vec<u8, 1024>,
    pub identity_protection_key: heapless::Vec<u8, 1024>,
    pub intermediate_ca_cert: heapless::Vec<u8, 1024>,
    pub new_op_cert: heapless::Vec<u8, 1024>,

    pub configured: bool,
}

impl Fabric {
    pub fn new() -> Fabric {
        let key_pair = SecretKey::random(NotRandom);

        Fabric {
            fabric_id: 0,
            node_id: 0,
            vendor_id: 0,
            operational_id: heapless::Vec::new(),
            root_public_key: heapless::Vec::new(),
            key_pair,
            root_cert: heapless::Vec::new(),
            identity_protection_key: heapless::Vec::new(),
            intermediate_ca_cert: heapless::Vec::new(),
            new_op_cert: heapless::Vec::new(),

            configured: false,
        }
    }

    pub fn set_root_certificate(&mut self, cert: heapless::Vec<u8, 1024>) {
        self.root_cert = cert.clone();
        let cert = Certificate::from_tlv(&cert);
        self.root_public_key = cert.elliptic_curve_public_key.clone();

        log::info!("{:?}", cert);
    }

    pub fn configure(
        &mut self,
        noc_cert: heapless::Vec<u8, 1024>,
        ica_cert: heapless::Vec<u8, 1024>,
        ipk_value: heapless::Vec<u8, 1024>,
        _case_admin_node: u64,
        admin_vendor_id: u32,
    ) {
        let cert = Certificate::from_tlv(&noc_cert);
        self.fabric_id = cert.subject.fabric_id.unwrap();
        self.node_id = cert.subject.node_id.unwrap();

        let mut operational_id_salt = [0u8; 8];
        operational_id_salt.clone_from_slice(&self.fabric_id.to_be_bytes());
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(
            Some(&operational_id_salt[..]),
            &self.root_public_key[1..],
        );
        let mut operational_id = [0u8; 8];
        hk.expand(b"CompressedFabric", &mut operational_id)
            .expect("8 is a valid length for Sha256 to output");
        self.operational_id = heapless::Vec::from_slice(&operational_id).unwrap();

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&operational_id), &ipk_value);
        let mut ipk = [0u8; 16];
        hk.expand(b"GroupKey v1.0", &mut ipk)
            .expect("16 is a valid length for Sha256 to output");
        self.identity_protection_key = heapless::Vec::from_slice(&ipk).unwrap();

        self.new_op_cert = noc_cert;
        self.intermediate_ca_cert = ica_cert;
        self.vendor_id = admin_vendor_id;

        self.configured = true;
    }

    pub fn sign(&self, data: &[u8]) -> heapless::Vec<u8, 256> {
        crate::crypto::sign(&self.key_pair.to_be_bytes(), data)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Subject {
    pub rcac_id: Option<u32>,
    pub fabric_id: Option<u64>,
    pub node_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Extensions {
    pub basic_constraint_is_ca: bool,
    pub basic_constraint_path_len: u32,
    pub key_usage: u32,
    pub extended_key_usage: heapless::Vec<u32, 5>,
    pub subject_key_identifier: heapless::Vec<u8, 10>,
    pub authority_key_identifier: heapless::Vec<u8, 10>,
    pub future_extension: heapless::Vec<u8, 10>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Certificate {
    pub serial_number: heapless::Vec<u8, 10>,
    pub signature_algorithm: u16,
    pub issuer: Option<u32>,
    pub not_before: u32,
    pub not_after: u32,
    pub subject: Subject,
    pub public_key_algorithm: u32,
    pub elliptic_curve_identifier: u32,
    pub elliptic_curve_public_key: heapless::Vec<u8, 128>,
    pub extensions: heapless::Vec<Extensions, 5>,
}

impl Certificate {
    pub fn from_tlv(data: &[u8]) -> Certificate {
        let mut serial_number: Option<heapless::Vec<u8, 10>> = None;
        let mut signature_algorithm: Option<u16> = None;
        let mut issuer: Option<u32> = None;
        let mut not_before: Option<u32> = None;
        let mut not_after: Option<u32> = None;
        let mut rcac_id = None;
        let mut fabric_id = None;
        let mut node_id = None;
        let mut public_key_algorithm: Option<u32> = None;
        let mut elliptic_curve_identifier: Option<u32> = None;
        let mut elliptic_curve_public_key = heapless::Vec::new();
        let extensions = heapless::Vec::new();

        let tlv = decode(data);

        let mut element = tlv;
        loop {
            match element.get_control() {
                TagControl::ContextSpecific(1) => {
                    if let Value::ByteString(data) = element.get_value() {
                        serial_number = Some(heapless::Vec::from_slice(&data).unwrap());
                    }
                }
                TagControl::ContextSpecific(2) => {
                    signature_algorithm = Some(element.get_value().unsigned_value() as u16);
                }
                TagControl::ContextSpecific(3) => loop {
                    match element.get_control() {
                        TagControl::ContextSpecific(20) => {
                            issuer = Some(element.get_value().unsigned_value() as u32);
                        }
                        _ => (),
                    }

                    if element.is_last() || element.get_type() == TlvType::EndOfContainer {
                        break;
                    }
                    element = element.next_in_container();
                },
                TagControl::ContextSpecific(4) => {
                    not_before = Some(element.get_value().unsigned_value() as u32);
                }
                TagControl::ContextSpecific(5) => {
                    not_after = Some(element.get_value().unsigned_value() as u32);
                }
                TagControl::ContextSpecific(6) => {
                    element = element.next_in_container();

                    loop {
                        match element.get_control() {
                            TagControl::ContextSpecific(20) => {
                                rcac_id = Some(element.get_value().unsigned_value() as u32);
                            }
                            TagControl::ContextSpecific(21) => {
                                fabric_id = Some(element.get_value().unsigned_value() as u64);
                            }
                            TagControl::ContextSpecific(17) => {
                                node_id = Some(element.get_value().unsigned_value() as u64);
                            }
                            _ => (),
                        }

                        if element.is_last() || element.get_type() == TlvType::EndOfContainer {
                            break;
                        }
                        element = element.next_in_container();
                    }
                }
                TagControl::ContextSpecific(7) => {
                    public_key_algorithm = Some(element.get_value().unsigned_value() as u32);
                }
                TagControl::ContextSpecific(8) => {
                    elliptic_curve_identifier = Some(element.get_value().unsigned_value() as u32);
                }
                TagControl::ContextSpecific(9) => {
                    if let Value::ByteString(data) = element.get_value() {
                        elliptic_curve_public_key = heapless::Vec::from_slice(&data).unwrap();
                    }
                }
                TagControl::ContextSpecific(10) => {
                    // TODO
                }
                _ => (),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        Certificate {
            serial_number: serial_number.unwrap(),
            signature_algorithm: signature_algorithm.unwrap(),
            issuer: issuer,
            not_before: not_before.unwrap(),
            not_after: not_after.unwrap(),
            subject: Subject {
                rcac_id: rcac_id,
                fabric_id: fabric_id,
                node_id: node_id,
            },
            public_key_algorithm: public_key_algorithm.unwrap(),
            elliptic_curve_identifier: elliptic_curve_identifier.unwrap(),
            elliptic_curve_public_key: elliptic_curve_public_key,
            extensions: extensions,
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::print;
    use std::{format, println};

    extern crate std;

    #[test]
    fn test_decode_certificate() {
        let data = [
            21, 48, 1, 1, 1, 36, 2, 1, 55, 3, 36, 19, 2, 24, 38, 4, 128, 34, 129, 39, 38, 5, 128,
            37, 77, 58, 55, 6, 36, 21, 1, 36, 17, 222, 24, 36, 7, 1, 36, 8, 1, 48, 9, 65, 4, 242,
            210, 222, 154, 217, 11, 37, 236, 73, 153, 9, 246, 189, 138, 113, 231, 100, 38, 235, 16,
            27, 171, 195, 255, 230, 35, 20, 71, 87, 231, 71, 23, 220, 138, 108, 119, 217, 173, 211,
            120, 83, 158, 98, 26, 63, 126, 164, 155, 113, 138, 216, 74, 178, 148, 233, 239, 50,
            150, 142, 158, 35, 25, 34, 108, 55, 10, 53, 1, 40, 1, 24, 36, 2, 1, 54, 3, 4, 2, 4, 1,
            24, 48, 4, 20, 109, 87, 227, 12, 154, 200, 65, 177, 30, 53, 48, 28, 131, 179, 127, 36,
            11, 19, 217, 119, 48, 5, 20, 223, 185, 32, 35, 180, 37, 31, 64, 235, 251, 221, 201,
            170, 115, 146, 209, 130, 228, 202, 160, 24, 48, 11, 64, 170, 248, 140, 6, 236, 222, 82,
            69, 234, 55, 184, 174, 162, 135, 122, 205, 134, 249, 143, 70, 88, 242, 181, 216, 64,
            204, 47, 90, 104, 2, 38, 47, 19, 64, 175, 147, 3, 88, 253, 78, 53, 132, 216, 210, 141,
            160, 251, 122, 132, 30, 13, 80, 97, 225, 47, 243, 129, 56, 243, 193, 225, 19, 43, 101,
            24,
        ];
        let _decoded = super::Certificate::from_tlv(&data);

        println!("{}", format!("{:02x?}", data).replace(" ", ""));

        //panic!("{:?}", _decoded);
    }

    #[test]
    fn test_operational_id() {
        /*
                Fabric Id
        1n
        <Buffer 04 0a 5d b5 d1 0a f5 18 00 63 69 3f 40 77 96 db a6 74 be ca bf e3 3a 6d 4d 7d 6d 4b 95 16 85 51 e4 c0 7d ae 6e b7 e3 ba 8e 26 45 86 3e 16 7e ae 86 a1 ... 15 more bytes>
        <Buffer 00 00 00 00 00 00 00 01>
                */
        let fabric_id = 1u64;
        let root_public_key = [
            4, 10, 93, 181, 209, 10, 245, 24, 0, 99, 105, 63, 64, 119, 150, 219, 166, 116, 190,
            202, 191, 227, 58, 109, 77, 125, 109, 75, 149, 22, 133, 81, 228, 192, 125, 174, 110,
            183, 227, 186, 142, 38, 69, 134, 62, 22, 126, 174, 134, 161, 81, 120, 135, 249, 103,
            210, 202, 248, 215, 113, 208, 19, 99, 90, 171,
        ];
        let mut operational_id_salt = [0u8; 8];
        operational_id_salt.clone_from_slice(&fabric_id.to_be_bytes());
        let hk =
            hkdf::Hkdf::<sha2::Sha256>::new(Some(&operational_id_salt[..]), &root_public_key[1..]);
        let mut operational_id = [0u8; 8];
        hk.expand(b"CompressedFabric", &mut operational_id)
            .expect("8 is a valid length for Sha256 to output");

        panic!("{:02x?}", operational_id);
    }
}
