enum DerType {
    UnsignedInt = 0x02,
    BitString = 0x03,
    //OctetString = 0x04,
    ObjectIdentifier = 0x06,
    Sequence = 0x10,
    Set = 0x11,
    UTF8String = 0x0C,
    EndMarker = 0xA0,
}

pub enum DerValue<'a> {
    UsignedInt(u32),
    BitString(&'a [u8]),
    UTF8String(&'a str),
    Array(&'a [u8]),
    ObjectId(&'a [u8]),
    Object(&'a [u8]),
    EndMarker,
}

pub struct DerEncoder {
    buffer: heapless::Vec<u8, 1024>,
}

impl DerEncoder {
    pub fn new() -> DerEncoder {
        DerEncoder {
            buffer: heapless::Vec::new(),
        }
    }

    pub fn write(&mut self, value: DerValue) {
        match value {
            DerValue::UsignedInt(value) => self.encode_unsigned_int(value),
            DerValue::BitString(value) => self.encode_bitstring(value),
            DerValue::UTF8String(value) => self.encode_string(value),
            DerValue::Array(value) => self.encode_array(value),
            DerValue::ObjectId(id) => self.encode_object_id(id),
            DerValue::Object(value) => self.encode_object(value),
            DerValue::EndMarker => self.encode_end_marker(),
        }
    }

    fn encode_end_marker(&mut self) {
        self.encode_ansi1(DerType::EndMarker, &[], false);
    }

    fn encode_object(&mut self, value: &[u8]) {
        self.encode_ansi1(DerType::Sequence, value, true);
    }

    fn encode_object_id(&mut self, id: &[u8]) {
        self.encode_ansi1(DerType::ObjectIdentifier, id, false);
    }

    fn encode_array(&mut self, value: &[u8]) {
        self.encode_ansi1(DerType::Set, value, true);
    }

    fn encode_string(&mut self, value: &str) {
        self.encode_ansi1(DerType::UTF8String, value.as_bytes(), false);
    }

    fn encode_bitstring(&mut self, value: &[u8]) {
        let mut data: heapless::Vec<u8, 1024> = heapless::Vec::new();
        data.push(0).unwrap();
        data.extend_from_slice(value).unwrap();
        self.encode_ansi1(DerType::BitString, &data, false);
    }

    fn encode_unsigned_int(&mut self, value: u32) {
        let buffer: [u8; 4] = value.to_be_bytes();
        let mut start = 0;

        if value != 0 {
            loop {
                if buffer[start] != 0 {
                    break;
                }
                if buffer[start + 1] >= 0x80 {
                    break;
                }
                start += 1;
                if start == 4 {
                    break;
                }
            }
        } else {
            start = 3;
        }

        self.encode_ansi1(DerType::UnsignedInt, &buffer[start..], false);
    }

    fn encode_ansi1(&mut self, tag: DerType, data: &[u8], constructed: bool) {
        self.buffer
            .push(tag as u8 | if constructed { 0x20 } else { 0 })
            .unwrap();
        self.encode_length_bytes(data.len());
        self.buffer.extend_from_slice(data).unwrap();
    }

    fn encode_length_bytes(&mut self, len: usize) {
        let mut buffer: heapless::Vec<u8, 5> = heapless::Vec::new();
        buffer.push(0).unwrap();
        buffer
            .extend_from_slice(&(len as u32).to_be_bytes())
            .unwrap();
        let mut start = 0;
        loop {
            if buffer[start] != 0 {
                break;
            }
            start += 1;
            if start == 4 {
                break;
            }
        }
        let length_len = buffer.len() - start;
        if length_len > 1 || buffer[start] >= 0x80 {
            start -= 1;
            buffer[start] = 0x80 + length_len as u8;
        }
        self.buffer.extend_from_slice(&buffer[start..]).unwrap();
    }

    pub fn to_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn to_vec<const N: usize>(&self) -> heapless::Vec<u8, N> {
        heapless::Vec::from_slice(self.to_slice()).unwrap()
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::print;
    use std::{format, println};

    use super::{DerEncoder, DerValue};

    extern crate std;

    #[test]
    fn test_encode_uint() {
        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::UsignedInt(1));

        println!("{:02x?}", encoder.to_slice());
        assert_eq!(&hex_literal::hex!("020101"), encoder.to_slice());
    }

    #[test]
    fn test_encode_uint0() {
        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::UsignedInt(0));

        println!("{:02x?}", encoder.to_slice());
        assert_eq!(&hex_literal::hex!("020100"), encoder.to_slice());
    }

    #[test]
    fn test_encode_uint_max() {
        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::UsignedInt(u32::MAX));

        println!("{:02x?}", encoder.to_slice());
        assert_eq!(&hex_literal::hex!("0204ffffffff"), encoder.to_slice());
    }

    #[test]
    fn test_encode_bitstring() {
        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::BitString(&[1, 2, 3, 4, 5]));

        println!("{:02x?}", encoder.to_slice());
        assert_eq!(&hex_literal::hex!("0306000102030405"), encoder.to_slice());
    }

    #[test]
    fn test_encode_string() {
        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::UTF8String("Hello World"));

        println!("{:02x?}", encoder.to_slice());
        assert_eq!(
            &hex_literal::hex!("0c0b48656c6c6f20576f726c64"),
            encoder.to_slice()
        );
    }

    #[test]
    fn test_encode_array() {
        let mut data = DerEncoder::new();
        data.write(DerValue::UsignedInt(1));
        data.write(DerValue::UsignedInt(2));
        data.write(DerValue::UsignedInt(3));
        data.write(DerValue::UsignedInt(4));
        data.write(DerValue::UsignedInt(5));

        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::Array(data.to_slice()));

        println!("{:02x?}", encoder.to_slice());
        assert_eq!(
            &hex_literal::hex!("310f020101020102020103020104020105"),
            encoder.to_slice()
        );
    }

    #[test]
    fn test_encode_object_id() {
        let mut data = DerEncoder::new();
        data.write(DerValue::UTF8String("CSR"));

        let id = hex_literal::hex!("55040A");

        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::ObjectId(&id));

        println!(
            "{}",
            format!("{:02x?}", encoder.to_slice()).replace(", ", "")
        );
        assert_eq!(&hex_literal::hex!("060355040a"), encoder.to_slice());
    }

    #[test]
    fn test_encode_object() {
        let mut data = DerEncoder::new();
        data.write(DerValue::UTF8String("hello"));
        data.write(DerValue::UTF8String("world"));

        let mut encoder = DerEncoder::new();
        encoder.write(DerValue::Object(data.to_slice()));

        println!(
            "{}",
            format!("{:02x?}", encoder.to_slice()).replace(", ", "")
        );
        assert_eq!(
            &hex_literal::hex!("300e0c0568656c6c6f0c05776f726c64"),
            encoder.to_slice()
        );
    }

    #[test]
    fn test_encode_csr_request() {
        let mut organization = DerEncoder::new();
        organization.write(DerValue::ObjectId(&hex_literal::hex!("55040A")));
        organization.write(DerValue::UTF8String("CSR"));

        let mut organization_content = DerEncoder::new();
        organization_content.write(DerValue::Object(organization.to_slice()));

        let mut subject_content = DerEncoder::new();
        subject_content.write(DerValue::Array(organization_content.to_slice()));

        let mut pk_type_contents = DerEncoder::new();
        pk_type_contents.write(DerValue::ObjectId(&hex_literal::hex!("2A8648CE3D0201")));
        pk_type_contents.write(DerValue::ObjectId(&hex_literal::hex!("2A8648CE3D030107")));

        let mut pk_content = DerEncoder::new();
        pk_content.write(DerValue::Object(pk_type_contents.to_slice()));
        pk_content.write(DerValue::BitString(&hex_literal::hex!("00044BD687ABD29B59D8B12E8C6614BD1664ADB2D402455B6CA3EF4E581E3BE344B83212E614F27EA4EEC8F31C75747438739B1D451A7EAB3A30542A0A7D1882A459")));

        let mut request_content = DerEncoder::new();
        request_content.write(DerValue::UsignedInt(0)); // version
        request_content.write(DerValue::Object(subject_content.to_slice()));
        request_content.write(DerValue::Object(pk_content.to_slice()));
        request_content.write(DerValue::EndMarker);

        let mut algorithm_content = DerEncoder::new();
        algorithm_content.write(DerValue::ObjectId(&hex_literal::hex!("2A8648CE3D040302")));

        let mut cert_req_content = DerEncoder::new();
        cert_req_content.write(DerValue::Object(request_content.to_slice()));
        cert_req_content.write(DerValue::Object(algorithm_content.to_slice()));
        cert_req_content.write(DerValue::BitString(&hex_literal::hex!("00304602210080861AD536EFF01CAD42816A8172F71BE3E4FD7230CF73A45E34945FE89D5D7202210087FC1F47ADB6D150580706865E2E21E2963C9C15006B64DAB5658BFB980A2AD3")));

        let mut cert_req = DerEncoder::new();
        cert_req.write(DerValue::Object(cert_req_content.to_slice()));

        println!(
            "{}",
            format!("{:02x?}", cert_req.to_slice()).replace(", ", "")
        );
        assert_eq!(&hex_literal::hex!("3081cb3071020100300e310c300a060355040a0c03435352305a301306072a8648ce3d020106082a8648ce3d03010703430000044bd687abd29b59d8b12e8c6614bd1664adb2d402455b6ca3ef4e581e3be344b83212e614f27ea4eec8f31c75747438739b1d451a7eab3a30542a0a7d1882a459a000300a06082a8648ce3d040302034a0000304602210080861ad536eff01cad42816a8172f71be3e4fd7230cf73a45e34945fe89d5d7202210087fc1f47adb6d150580706865e2e21e2963c9c15006b64dab5658bfb980a2ad3"), cert_req.to_slice());
    }
}
