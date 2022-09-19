use crate::{
    message_codec::{MessageHeader, PayloadHeader},
    MessageType,
};

pub mod interaction_model;
pub mod secure_channel;

#[derive(Debug, Clone, PartialEq)]
pub struct SecureSessionParameters {
    pub session_id: u16,
    pub node_id: u64,
    pub peer_node_id: u64,
    pub decrypt_key: [u8; 16],
    pub encrypt_key: [u8; 16],
    pub attestation_key: [u8; 16],
}

pub struct ProtocolHandlerResponseMessage {
    pub message_type: MessageType,
    pub is_initiator_msg: bool,
    pub requires_ack: bool,
    pub payload: heapless::Vec<u8, 1024>,
}

pub enum ProtocolHandlerResponse {
    Response(ProtocolHandlerResponseMessage),
    InitiateSecureSession(SecureSessionParameters),
    None,
}

impl ProtocolHandlerResponse {
    pub fn response(
        message_type: MessageType,
        is_initiator_msg: bool,
        requires_ack: bool,
        payload: &[u8],
    ) -> ProtocolHandlerResponse {
        ProtocolHandlerResponse::Response(ProtocolHandlerResponseMessage {
            message_type,
            is_initiator_msg,
            requires_ack,
            payload: heapless::Vec::from_slice(&payload).unwrap(),
        })
    }

    pub fn initiate_secure_session(
        session_id: u16,
        node_id: u64,
        peer_node_id: u64,
        decrypt_key: [u8; 16],
        encrypt_key: [u8; 16],
        attestation_key: [u8; 16],
    ) -> ProtocolHandlerResponse {
        ProtocolHandlerResponse::InitiateSecureSession(SecureSessionParameters {
            session_id,
            node_id,
            peer_node_id,
            decrypt_key,
            encrypt_key,
            attestation_key,
        })
    }
}

pub trait ProtocolHandler {
    fn on_message(
        &mut self,
        header: &MessageHeader,
        payload_header: &PayloadHeader,
        payload: &[u8],
    ) -> ProtocolHandlerResponse;

    fn encrypted(&self) -> bool;
}
