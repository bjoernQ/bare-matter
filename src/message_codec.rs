#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeader {
    pub session_id: u16,
    pub session_type: u8,
    pub source_node_id: Option<u64>,
    pub message_id: u32,
    pub dst_group_id: Option<u16>,
    pub dst_node_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PayloadHeader {
    pub protocol_id: u32,
    pub is_initiator_msg: bool,
    pub exchange_id: u16,
    pub message_type: u8,
    pub requires_ack: bool,
    pub acked_msg_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub message_header: MessageHeader,
    pub payload_header: PayloadHeader,
    pub payload: heapless::Vec<u8, 2048>,
}

const HEADER_VERSION: u8 = 0x00;
const COMMON_VENDOR_ID: u16 = 0x0000;

// enum SessionType {
//     Group = 1,
//     Unicast = 0,
// }

enum PacketHeaderFlag {
    HasDestNodeId = 0b00000001,
    HasDestGroupId = 0b00000010,
    HasSourceNodeId = 0b00000100,
    // Reserved = 0b00001000,
    VersionMask = 0b11110000,
}

enum PayloadHeaderFlag {
    IsInitiatorMessage = 0b00000001,
    IsAckMessage = 0b00000010,
    RequiresAck = 0b00000100,
    HasSecureExtension = 0b00001000,
    HasVendorId = 0b00010000,
}

pub fn encode_message_header(msg: MessageHeader, data: &mut heapless::Vec<u8, 1024>) {
    data.push(
        (HEADER_VERSION << 4)
            | (if msg.dst_group_id.is_some() {
                PacketHeaderFlag::HasDestGroupId as u8
            } else {
                0
            })
            | (if msg.dst_node_id.is_some() {
                PacketHeaderFlag::HasDestNodeId as u8
            } else {
                0
            })
            | (if msg.source_node_id.is_some() {
                PacketHeaderFlag::HasSourceNodeId as u8
            } else {
                0
            }),
    )
    .unwrap();
    data.extend_from_slice(&msg.session_id.to_le_bytes())
        .unwrap();
    let security_flags = msg.session_type;
    data.push(security_flags).unwrap();
    data.extend_from_slice(&msg.message_id.to_le_bytes())
        .unwrap();

    if msg.source_node_id.is_some() {
        data.extend_from_slice(&msg.source_node_id.unwrap().to_le_bytes())
            .unwrap();
    }
    if msg.dst_node_id.is_some() {
        data.extend_from_slice(&msg.dst_node_id.unwrap().to_le_bytes())
            .unwrap();
    }
    if msg.dst_group_id.is_some() {
        data.extend_from_slice(&msg.dst_group_id.unwrap().to_le_bytes())
            .unwrap();
    }
}

pub fn encode_payload_header(msg: PayloadHeader, data: &mut heapless::Vec<u8, 1024>) {
    let vendor_id = ((msg.protocol_id & 0xFFFF0000) >> 16) as u16;
    let flags = (if msg.is_initiator_msg {
        PayloadHeaderFlag::IsInitiatorMessage as u8
    } else {
        0
    }) | (if msg.acked_msg_id.is_some() {
        PayloadHeaderFlag::IsAckMessage as u8
    } else {
        0
    }) | (if msg.requires_ack {
        PayloadHeaderFlag::RequiresAck as u8
    } else {
        0
    }) | (if vendor_id != COMMON_VENDOR_ID {
        PayloadHeaderFlag::HasVendorId as u8
    } else {
        0
    });
    data.push(flags).unwrap();
    data.push(msg.message_type).unwrap();
    data.extend_from_slice(&msg.exchange_id.to_le_bytes())
        .unwrap();

    // ???
    if vendor_id != COMMON_VENDOR_ID {
        data.extend_from_slice(&msg.protocol_id.to_le_bytes())
            .unwrap();
    } else {
        data.extend_from_slice(&(msg.protocol_id as u16).to_le_bytes())
            .unwrap();
    }

    if msg.acked_msg_id.is_some() {
        data.extend_from_slice(&msg.acked_msg_id.unwrap().to_le_bytes())
            .unwrap();
    }
}

pub fn encode(msg: Message) -> heapless::Vec<u8, 1024> {
    let mut data = heapless::Vec::new();

    encode_message_header(msg.message_header, &mut data);
    encode_payload_header(msg.payload_header, &mut data);
    data.extend_from_slice(&msg.payload).unwrap();

    data
}

pub fn decode_message_header(data: &[u8]) -> (MessageHeader, usize) {
    // Read and parse flags
    let flags = data[0];
    let mut idx = 1;
    let version = (flags & PacketHeaderFlag::VersionMask as u8) >> 4;
    let has_dest_node_id = (flags & PacketHeaderFlag::HasDestNodeId as u8) != 0;
    let has_dest_group_id = (flags & PacketHeaderFlag::HasDestGroupId as u8) != 0;
    let has_source_node_id = (flags & PacketHeaderFlag::HasSourceNodeId as u8) != 0;

    if has_dest_node_id && has_dest_group_id {
        panic!("The header cannot contain destination group and node at the same time")
    };
    if version != HEADER_VERSION {
        panic!("Unsupported header version {}", version)
    };

    let session_id = u16::from_le_bytes(data[idx..][..2].try_into().unwrap());
    idx += 2;
    let security_flags = data[idx];
    idx += 1;
    let message_id = u32::from_le_bytes(data[idx..][..4].try_into().unwrap());
    idx += 4;
    let source_node_id = if has_source_node_id {
        let res = Some(u64::from_le_bytes(data[idx..][..8].try_into().unwrap()));
        idx += 8;
        res
    } else {
        None
    };
    let dst_node_id = if has_dest_node_id {
        let res = Some(u64::from_le_bytes(data[idx..][..8].try_into().unwrap()));
        idx += 8;
        res
    } else {
        None
    };
    let dst_group_id = if has_dest_group_id {
        let res = Some(u16::from_le_bytes(data[24..][..2].try_into().unwrap()));
        idx += 2;
        res
    } else {
        None
    };

    let session_type = security_flags & 0b00000011;

    let mh = MessageHeader {
        session_id,
        session_type,
        source_node_id,
        message_id,
        dst_group_id,
        dst_node_id,
    };

    (mh, idx)
}

pub fn decode_payload_header(data: &[u8], offset: usize) -> (PayloadHeader, usize) {
    let mut idx = offset;

    let exchange_flags = data[idx];
    idx += 1;
    let is_initiator_msg = (exchange_flags & PayloadHeaderFlag::IsInitiatorMessage as u8) != 0;
    let is_ack_message = (exchange_flags & PayloadHeaderFlag::IsAckMessage as u8) != 0;
    let requires_ack = (exchange_flags & PayloadHeaderFlag::RequiresAck as u8) != 0;
    let has_secured_extension = (exchange_flags & PayloadHeaderFlag::HasSecureExtension as u8) != 0;
    let has_vendor_id = (exchange_flags & PayloadHeaderFlag::HasVendorId as u8) != 0;
    if has_secured_extension {
        //panic!("Secured extension is not supported");
    }

    let message_type = data[idx];
    idx += 1;
    let exchange_id = u16::from_le_bytes(data[idx..][..2].try_into().unwrap());
    idx += 2;
    let vendor_id = if has_vendor_id {
        let res = u16::from_le_bytes(data[idx..][..2].try_into().unwrap());
        idx += 2;
        res
    } else {
        COMMON_VENDOR_ID
    };
    let protocol_id = ((vendor_id as u32) << 16u32) as u32
        | u16::from_le_bytes(data[idx..][..2].try_into().unwrap()) as u32;
    idx += 2;
    let acked_msg_id = if is_ack_message {
        let res = Some(u32::from_le_bytes(data[idx..][..4].try_into().unwrap()));
        idx += 4;
        res
    } else {
        None
    };

    let ph = PayloadHeader {
        protocol_id,
        is_initiator_msg,
        exchange_id,
        message_type,
        requires_ack,
        acked_msg_id,
    };

    (ph, idx)
}

pub fn decode(data: &[u8]) -> Message {
    let (mh, idx) = decode_message_header(data);
    let (ph, idx) = decode_payload_header(data, idx);
    let payload = heapless::Vec::from_slice(&data[idx..]).unwrap();

    Message {
        message_header: mh,
        payload_header: ph,
        payload,
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use crate::message_codec::{MessageHeader, PayloadHeader};

    use super::Message;

    extern crate std;

    #[test]
    fn test_decode1() {
        let encoded = hex_literal::hex!("040000000a4ff2177ea0c8a7cb6a63520520d3640000153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca250233dc240300280435052501881325022c011818");

        let wanted_mh = MessageHeader {
            session_id: 0,
            session_type: 0,
            source_node_id: Some(5936706156730294398),
            message_id: 401755914,
            dst_group_id: None,
            dst_node_id: None,
        };

        let wanted_ph = PayloadHeader {
            protocol_id: 0,
            is_initiator_msg: true,
            exchange_id: 25811,
            message_type: 0x20,
            requires_ack: true,
            acked_msg_id: None,
        };

        let wanted = Message {
            message_header: wanted_mh,
            payload_header: wanted_ph,
            payload: heapless::Vec::from_slice(&hex_literal::hex!("153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca250233dc240300280435052501881325022c011818")).unwrap(),
        };

        let decoded = super::decode(&encoded);

        assert_eq!(decoded, wanted);
        assert_eq!(super::encode(decoded).as_slice(), &encoded);
    }

    #[test]
    fn test_decode2() {
        let encoded = hex_literal::hex!("01000000218712797ea0c8a7cb6a63520621d36400000a4ff217153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca3002201783302d95a4a9fb0decb8fdd6564b90a957681459aeee069961bea61d7b247125039d8935042501e80330022099f813dd41bd081a1c63e811828f0662594bca89cd9d4ed26f7427fdb2a027361835052501881325022c011818");

        let wanted_mh = MessageHeader {
            session_id: 0,
            session_type: 0,
            source_node_id: None,
            message_id: 2031257377,
            dst_group_id: None,
            dst_node_id: Some(5936706156730294398),
        };

        let wanted_ph = PayloadHeader {
            protocol_id: 0,
            is_initiator_msg: false,
            exchange_id: 25811,
            message_type: 0x21,
            requires_ack: true,
            acked_msg_id: Some(401755914),
        };

        let wanted = Message {
            message_header: wanted_mh,
            payload_header: wanted_ph,
            payload: heapless::Vec::from_slice(&hex_literal::hex!("153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca3002201783302d95a4a9fb0decb8fdd6564b90a957681459aeee069961bea61d7b247125039d8935042501e80330022099f813dd41bd081a1c63e811828f0662594bca89cd9d4ed26f7427fdb2a027361835052501881325022c011818")).unwrap(),
        };

        let decoded = super::decode(&encoded);

        assert_eq!(decoded, wanted);
        assert_eq!(super::encode(decoded).as_slice(), &encoded);
    }

    #[test]
    fn test_encode_decode() {
        let wanted_mh = MessageHeader {
            session_id: 101,
            session_type: 1,
            source_node_id: None,
            message_id: 2031257377,
            dst_group_id: None,
            dst_node_id: Some(5936706156730294398),
        };

        let wanted_ph = PayloadHeader {
            protocol_id: 1,
            is_initiator_msg: false,
            exchange_id: 25811,
            message_type: 0x21,
            requires_ack: false,
            acked_msg_id: Some(401755914),
        };

        let wanted = Message {
            message_header: wanted_mh,
            payload_header: wanted_ph,
            payload: heapless::Vec::from_slice(&hex_literal::hex!("153001204715a406c6b0496ad52039e347db8528cb69a1cb2fce6f2318552ae65e103aca3002201783302d95a4a9fb0decb8fdd6564b90a957681459aeee069961bea61d7b247125039d8935042501e80330022099f813dd41bd081a1c63e811828f0662594bca89cd9d4ed26f7427fdb2a027361835052501881325022c011818")).unwrap(),
        };

        let decoded = super::decode(super::encode(wanted.clone()).as_slice());

        assert_eq!(decoded, wanted);
    }
}
