use crate::{
    interaction_messages::{
        self, AttributePath, AttributeValue, InvokeResponse, ReadResponse, Response, ResponseField,
        ResponsePath, Result,
    },
    interaction_model::{Attribute, Device},
    message_codec::{MessageHeader, PayloadHeader},
    MatterContext, MessageType,
};

use super::{ProtocolHandler, ProtocolHandlerResponse};

pub struct InteractionModel<'a> {
    device: &'a mut Device<'a>,
    context: &'a MatterContext,
}

impl<'a> InteractionModel<'a> {
    pub fn new(device: &'a mut Device<'a>, context: &'a MatterContext) -> InteractionModel<'a> {
        InteractionModel { device, context }
    }
}

impl<'a> ProtocolHandler for InteractionModel<'a> {
    fn on_message(
        &mut self,
        _header: &MessageHeader,
        payload_header: &PayloadHeader,
        payload: &[u8],
    ) -> ProtocolHandlerResponse {
        match payload_header.message_type.into() {
            MessageType::ReadRequest => {
                let decoded = interaction_messages::ReadRequest::from_tlv(payload);

                log::info!("GOT READ REQUEST {:?}", decoded);

                let mut attribs: heapless::Vec<(AttributePath, &Attribute), 10> =
                    heapless::Vec::new();

                for path in decoded.attributes {
                    attribs
                        .extend_from_slice(&self.device.attribute_values(path))
                        .unwrap();
                }

                let mut attributes = heapless::Vec::new();
                for (path, attrib) in attribs {
                    attributes
                        .push(AttributeValue {
                            version: attrib.version,
                            path,
                            value: attrib.value.clone(),
                        })
                        .unwrap();
                }

                let resp = ReadResponse {
                    attributes,
                    is_fabric_filtered: false,
                    interaction_model_revision: 1,
                };

                let encoded = resp.encode_tlv();
                ProtocolHandlerResponse::response(
                    MessageType::ReportData,
                    false,
                    true,
                    encoded.to_slice(),
                )
            }
            MessageType::InvokeCommandRequest => {
                let decoded = interaction_messages::InvokeRequest::from_tlv(payload);

                log::info!("GOT INVOKE REQUEST {:?}", decoded);

                // TODO!!! find the right one for the session!!!!
                //xxx                let attestation_key = &self.secure_session_parameters[0].attestation_key;

                let mut res_list: heapless::Vec<ResponseField, 10> = heapless::Vec::new();
                let idx = 0;
                for (path, arg) in &decoded.invokes {
                    let invoke_result = self.device.invoke(path.clone(), arg.clone(), self.context);
                    let p = &decoded.invokes[idx].0;

                    match invoke_result {
                        crate::interaction_model::InvokeHandlerResponse::Message(message) => {
                            res_list
                                .push(ResponseField {
                                    response: Some(Response {
                                        path: ResponsePath {
                                            endpoint_id: p.endpoint_id,
                                            cluster_id: p.cluster_id,
                                            response_id: self.device.get_response_id(p), // TODO find in device! OR better get in result from device.invoke!
                                        },
                                        response: message,
                                    }),
                                    result: None,
                                })
                                .unwrap();
                        }
                        crate::interaction_model::InvokeHandlerResponse::Result(res) => {
                            res_list
                                .push(ResponseField {
                                    response: None,
                                    result: Some(Result {
                                        path: p.clone(),
                                        result: res,
                                    }),
                                })
                                .unwrap();
                        }
                        crate::interaction_model::InvokeHandlerResponse::None => (),
                    };
                }

                let resp = InvokeResponse {
                    supress_response: false,
                    responses: heapless::Vec::from_slice(&res_list).unwrap(),
                    interaction_model_revision: 1,
                };

                let encoded = resp.encode_tlv();
                ProtocolHandlerResponse::response(
                    MessageType::InvokeCommandResponse,
                    false,
                    true,
                    &encoded,
                )
            }
            MessageType::StatusResponse => {
                // todo!();

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

                ProtocolHandlerResponse::response(MessageType::StatusReport, false, true, &payload)
            }
            _ => panic!(
                "Unknown or unexpected message type {:?}",
                payload_header.message_type
            ),
        }
    }

    fn encrypted(&self) -> bool {
        true
    }
}
