#![no_std]

mod buffer;
pub mod case_messages;
pub mod cluster;
pub mod crypto;
pub mod der;
pub mod dns_sd;
pub mod dns_sd_codec;
pub mod endpoint;
pub mod fabric;
pub mod interaction_messages;
pub mod interaction_model;
pub mod message_codec;
pub mod pase_messages;
pub mod protocol;
pub mod spake2p;
pub mod tlv_codec;
pub mod x509;

use core::cell::RefCell;

use critical_section::Mutex;
use crypto_bigint::rand_core::{CryptoRng, RngCore};
use dns_sd::DnsSd;
use fabric::Fabric;
use interaction_model::Device;
use message_codec::{MessageHeader, PayloadHeader};
use protocol::{
    interaction_model::InteractionModel,
    secure_channel::{CaseContext, SecureChannel},
    ProtocolHandler, SecureSessionParameters,
};

use crate::protocol::ProtocolHandlerResponseMessage;

pub type TlvAnyData = heapless::Vec<u8, 1024>;
pub type MessageRawData = heapless::Vec<u8, 1024>;

pub trait UdpSocket {
    fn send(&mut self, addr: [u8; 4], port: u16, buffer: heapless::Vec<u8, 1024>)
        -> Result<(), ()>;

    fn receive(&mut self) -> Result<(heapless::Vec<u8, 1024>, [u8; 4], u16), ()>;

    fn bind(&mut self, port: u16) -> Result<(), ()>;
}

pub trait UdpMulticastSocket {
    fn send(&mut self, addr: [u8; 4], port: u16, buffer: heapless::Vec<u8, 2048>)
        -> Result<(), ()>;

    fn receive(&mut self) -> Result<(heapless::Vec<u8, 2048>, [u8; 4], u16), ()>;

    fn bind(&mut self, multiaddr: &[u8; 4], port: u16) -> Result<(), ()>;
}

const MATTER_UDP_PORT: u16 = 5540;

pub enum Protocol {
    SecureChannel = 0x0000,
    InteractionModel = 0x0001,
}

pub enum MessageType {
    StatusResponse = 0x01,
    ReadRequest = 0x02,
    SubscribeRequest = 0x03,
    SubscribeResponse = 0x04,
    ReportData = 0x05,
    WriteRequest = 0x06,
    WriteResponse = 0x07,
    InvokeCommandRequest = 0x08,
    InvokeCommandResponse = 0x09,
    TimedRequest = 0x0a,

    StandaloneAck = 0x10,
    PbkdfParamRequest = 0x20,
    PbkdfParamResponse = 0x21,
    PasePake1 = 0x22,
    PasePake2 = 0x23,
    PasePake3 = 0x24,
    Sigma1 = 0x30,
    Sigma2 = 0x31,
    Sigma3 = 0x32,
    Sigma2Resume = 0x33,
    StatusReport = 0x40,
    Unknown = 0xff,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => MessageType::StatusResponse,
            0x02 => MessageType::ReadRequest,
            0x03 => MessageType::SubscribeRequest,
            0x04 => MessageType::SubscribeResponse,
            0x05 => MessageType::ReportData,
            0x06 => MessageType::WriteRequest,
            0x07 => MessageType::WriteResponse,
            0x08 => MessageType::InvokeCommandRequest,
            0x09 => MessageType::InvokeCommandResponse,
            0x0a => MessageType::TimedRequest,
            0x10 => MessageType::StandaloneAck,
            0x20 => MessageType::PbkdfParamRequest,
            0x21 => MessageType::PbkdfParamResponse,
            0x22 => MessageType::PasePake1,
            0x23 => MessageType::PasePake2,
            0x24 => MessageType::PasePake3,
            0x30 => MessageType::Sigma1,
            0x31 => MessageType::Sigma2,
            0x32 => MessageType::Sigma3,
            0x33 => MessageType::Sigma2Resume,
            0x40 => MessageType::StatusReport,
            _ => MessageType::Unknown,
        }
    }
}

pub struct Certificates {
    pub device_private_key: [u8; 32],
    pub device_certificate: heapless::Vec<u8, 1024>,
    pub product_intermediate_certificate: heapless::Vec<u8, 1024>,
    pub certificate_declaration: heapless::Vec<u8, 1024>,
}

pub struct MatterContext {
    certificates: Certificates,
    fabric: Mutex<RefCell<Fabric>>,
    case_context: Mutex<RefCell<CaseContext>>,
    secure_session_parameters: Mutex<RefCell<heapless::Vec<SecureSessionParameters, 3>>>,
}

impl MatterContext {
    pub fn new(certificates: Certificates) -> MatterContext {
        MatterContext {
            certificates,
            fabric: Mutex::new(RefCell::new(Fabric::new())),
            case_context: Mutex::new(RefCell::new(CaseContext::new())),
            secure_session_parameters: Mutex::new(RefCell::new(heapless::Vec::new())),
        }
    }

    pub fn with_fabric<T>(&self, f: impl Fn(&mut Fabric) -> T) -> T {
        critical_section::with(|cs| f(&mut *self.fabric.borrow_ref_mut(cs)))
    }

    pub fn with_case_context<T>(&self, f: impl Fn(&mut CaseContext) -> T) -> T {
        critical_section::with(|cs| f(&mut *self.case_context.borrow_ref_mut(cs)))
    }

    pub fn with_secure_sessions<T>(
        &self,
        f: impl Fn(&mut heapless::Vec<SecureSessionParameters, 3>) -> T,
    ) -> T {
        critical_section::with(|cs| f(&mut *self.secure_session_parameters.borrow_ref_mut(cs)))
    }
}

pub struct MatterServer<'a> {
    udp_socket: &'a mut dyn UdpSocket,

    socket_bound: bool,
    msg_id: heapless::FnvIndexMap<u32, u32, 8>,

    dns_sd: DnsSd<'a>,

    secure_channel: SecureChannel<'a>,
    interaction_model: InteractionModel<'a>,

    context: &'a MatterContext,
}

impl<'a> MatterServer<'a> {
    pub fn new<RNG>(
        udp_socket: &'a mut dyn UdpSocket,
        multicast_socket: &'a mut dyn UdpMulticastSocket,
        local_ip: [u8; 4],
        rng: &mut RNG,
        device: &'a mut Device<'a>,
        context: &'a MatterContext,
    ) -> MatterServer<'a>
    where
        RNG: CryptoRng + RngCore,
    {
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        MatterServer {
            udp_socket,
            socket_bound: false,
            msg_id: heapless::FnvIndexMap::new(),
            dns_sd: DnsSd::new(local_ip, multicast_socket, context),
            secure_channel: SecureChannel::new(context, random, salt),
            interaction_model: InteractionModel::new(device, context),
            context,
        }
    }

    pub fn poll(&mut self, millis: u64) {
        self.dns_sd.handle_incoming();
        self.dns_sd.handle_announce(millis);

        if !self.socket_bound {
            self.socket_bound = true;
            self.udp_socket.bind(MATTER_UDP_PORT).unwrap();
        }

        let received = self.udp_socket.receive();
        if let Ok((received_data, addr, port)) = received {
            let (header, offset) = message_codec::decode_message_header(&received_data);
            log::info!("Received {:?}", header);

            let (secure, payload_header, payload) =
                self.decode_remaining(&header, &received_data[..offset], &received_data[offset..]);

            log::info!(
                "Received message {:?} {:?} with {} bytes of payload",
                &header,
                &payload_header,
                payload.len()
            );

            let response = if payload_header.protocol_id == Protocol::InteractionModel as u32 {
                self.interaction_model
                    .on_message(&header, &payload_header, &payload)
            } else {
                self.secure_channel
                    .on_message(&header, &payload_header, &payload)
            };

            let answer = match response {
                protocol::ProtocolHandlerResponse::Response(message_data) => Some(message_data),
                protocol::ProtocolHandlerResponse::InitiateSecureSession(secure_session) => {
                    self.context.with_secure_sessions(|sessions| {
                        sessions.push(secure_session.clone()).unwrap();
                    });

                    let mut payload: heapless::Vec<u8, 128> = heapless::Vec::new();
                    payload
                        .extend_from_slice(&u16::to_le_bytes(0x0000))
                        .unwrap(); // general status code
                    payload
                        .extend_from_slice(&u32::to_le_bytes(0x0000))
                        .unwrap(); // export const SECURE_CHANNEL_PROTOCOL_ID = 0x00000000;
                    payload
                        .extend_from_slice(&u16::to_le_bytes(0x0000))
                        .unwrap(); // protocol status code

                    Some(ProtocolHandlerResponseMessage {
                        message_type: MessageType::StatusReport,
                        is_initiator_msg: false,
                        requires_ack: true,
                        payload: heapless::Vec::from_slice(&payload).unwrap(),
                    })
                }
                protocol::ProtocolHandlerResponse::None => None,
            };

            if let Some(response) = answer {
                let message_header = crate::message_codec::MessageHeader {
                    session_id: header.session_id,
                    session_type: header.session_type,
                    source_node_id: header.dst_node_id,
                    message_id: self.next_message_id(header.session_id as u32),
                    dst_group_id: None,
                    dst_node_id: header.source_node_id,
                };

                let payload_header = crate::message_codec::PayloadHeader {
                    protocol_id: payload_header.protocol_id,
                    is_initiator_msg: response.is_initiator_msg,
                    exchange_id: payload_header.exchange_id,
                    message_type: response.message_type as u8,
                    requires_ack: true,
                    acked_msg_id: Some(header.message_id),
                };

                let packet = crate::message_codec::Message {
                    message_header,
                    payload_header,
                    payload: heapless::Vec::from_slice(&response.payload).unwrap(),
                };

                if secure {
                    log::info!("SEND ENCRYPTED RESPONSE {:02x?}", &packet);
                    // encrypted send ...
                    let mut buffer = heapless::Vec::new();
                    message_codec::encode_message_header(
                        packet.message_header.clone(),
                        &mut buffer,
                    );
                    let session_params = self
                        .find_session_params(packet.message_header.session_id)
                        .unwrap();
                    log::warn!(
                        "session = {}, param = {:?}",
                        packet.message_header.session_id,
                        session_params
                    );
                    let node_id = session_params.node_id;
                    let nonce =
                        generate_nonce(buffer[3], packet.message_header.message_id, node_id);

                    let mut unencrypted = heapless::Vec::new();
                    message_codec::encode_payload_header(
                        packet.payload_header.clone(),
                        &mut unencrypted,
                    );
                    unencrypted.extend_from_slice(&packet.payload).unwrap();

                    let aad = &buffer;

                    let encrypted = crate::crypto::encrypt(
                        &session_params.encrypt_key,
                        &unencrypted,
                        &nonce,
                        Some(aad),
                    );
                    buffer.extend_from_slice(&encrypted).unwrap();

                    self.udp_socket.send(addr, port, buffer).unwrap();
                } else {
                    log::info!("SEND UNENCRYPTED RESPONSE {:02x?}", &packet);
                    let buffer = message_codec::encode(packet);
                    self.udp_socket.send(addr, port, buffer).unwrap();
                }
            }
        }
    }

    fn find_session_params(&self, session_id: u16) -> Option<SecureSessionParameters> {
        let res = self.context.with_secure_sessions(|sessions| {
            let mut res = None;
            for secure_session in sessions {
                if secure_session.session_id == session_id {
                    res = Some(secure_session.clone());
                }
            }

            res
        });

        res
    }

    fn decode_remaining(
        &self,
        header: &MessageHeader,
        header_bytes: &[u8],
        data: &[u8],
    ) -> (bool, PayloadHeader, heapless::Vec<u8, 1024>) {
        let secure_session = self.find_session_params(header.session_id);

        if let Some(secure_session) = secure_session {
            let node_id = secure_session.peer_node_id;
            let nonce = generate_nonce(header_bytes[3], header.message_id, node_id);

            let aad = header_bytes;

            let decrypted =
                crate::crypto::decrypt(&secure_session.decrypt_key, data, &nonce, Some(aad));

            let (ph, offset) = crate::message_codec::decode_payload_header(&decrypted, 0);
            let payload = &decrypted[offset..];

            return (true, ph, heapless::Vec::from_slice(payload).unwrap());
        }

        let (payload_header, offset) = message_codec::decode_payload_header(&data, 0);
        let payload = &data[offset..];

        (
            false,
            payload_header,
            heapless::Vec::from_slice(payload).unwrap(),
        )
    }

    fn next_message_id(&mut self, session_id: u32) -> u32 {
        if !self.msg_id.contains_key(&session_id) {
            self.msg_id.insert(session_id, 0).unwrap();
        }

        let current = self.msg_id.get(&session_id).unwrap();
        let next = current.wrapping_add(1);
        self.msg_id.insert(session_id, next).unwrap();

        next
    }
}

fn generate_nonce(sec_flags: u8, msg_id: u32, node_id: u64) -> [u8; 13] {
    let mut res = [0u8; 13];
    res[0] = sec_flags;
    res[1..][..4].copy_from_slice(&msg_id.to_le_bytes());
    res[5..].copy_from_slice(&node_id.to_le_bytes());
    res
}
