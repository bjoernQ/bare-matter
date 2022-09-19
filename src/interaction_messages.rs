use crate::{tlv_codec::*, TlvAnyData};

#[derive(Debug, Clone, PartialEq)]
pub struct AttributePath {
    pub endpoint_id: Option<u8>,
    pub cluster_id: Option<u8>,
    pub attribute_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadRequest {
    pub attributes: heapless::Vec<AttributePath, 10>,
    pub is_fabric_filtered: bool,
    pub interaction_model_revision: u8,
}

impl ReadRequest {
    pub fn from_tlv(data: &[u8]) -> ReadRequest {
        let tlv = decode(data);

        let mut is_fabric_filtered = false;
        let mut interaction_model_revision = 0;
        let mut attributes = heapless::Vec::<AttributePath, 10>::new();

        let mut tmp_attribute_path = AttributePath {
            endpoint_id: None,
            cluster_id: None,
            attribute_id: None,
        };

        let mut element = tlv;
        let mut in_attributes = false;
        let mut in_attribute_path = false;
        loop {
            if element.get_type() == TlvType::EndOfContainer && in_attributes && !in_attribute_path
            {
                in_attributes = false;
            }

            if element.get_type() == TlvType::EndOfContainer && in_attributes && in_attribute_path {
                in_attribute_path = false;
                attributes.push(tmp_attribute_path.clone()).unwrap();
                tmp_attribute_path.endpoint_id = None;
                tmp_attribute_path.cluster_id = None;
                tmp_attribute_path.attribute_id = None;
            }

            if element.get_type() == TlvType::List && in_attributes && !in_attribute_path {
                in_attribute_path = true;
            }

            match element.get_control() {
                TagControl::ContextSpecific(0) => {
                    in_attributes = true;
                }

                TagControl::ContextSpecific(2) if in_attribute_path => {
                    if let Value::Unsigned8(value) = element.get_value() {
                        tmp_attribute_path.endpoint_id = Some(value);
                    }
                }

                TagControl::ContextSpecific(3) if in_attribute_path => {
                    if let Value::Unsigned8(value) = element.get_value() {
                        tmp_attribute_path.cluster_id = Some(value);
                    }
                }

                TagControl::ContextSpecific(4) if in_attribute_path => {
                    tmp_attribute_path.attribute_id =
                        Some(element.get_value().unsigned_value() as u32);
                }

                TagControl::ContextSpecific(3) if !in_attribute_path => {
                    if let Value::Boolean(value) = element.get_value() {
                        is_fabric_filtered = value;
                    }
                }

                TagControl::ContextSpecific(255) if !in_attribute_path => {
                    if let Value::Unsigned8(value) = element.get_value() {
                        interaction_model_revision = value;
                    }
                }

                _ => (),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        ReadRequest {
            attributes,
            is_fabric_filtered,
            interaction_model_revision,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttributeValue {
    pub version: u8,
    pub path: AttributePath,
    pub value: TlvAnyData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadResponse {
    pub attributes: heapless::Vec<AttributeValue, 10>,
    pub is_fabric_filtered: bool,
    pub interaction_model_revision: u8,
}

impl ReadResponse {
    pub fn encode_tlv(&self) -> Encoder {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::Array,
            TagControl::ContextSpecific(1),
            Value::Container,
        );

        for attrib in &self.attributes {
            encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

            encoder.write(
                TlvType::Structure,
                TagControl::ContextSpecific(1),
                Value::Container,
            );

            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte1),
                TagControl::ContextSpecific(0),
                Value::Unsigned8(attrib.version),
            );

            encoder.write(
                TlvType::List,
                TagControl::ContextSpecific(1),
                Value::Container,
            );

            if attrib.path.endpoint_id.is_some() {
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte1),
                    TagControl::ContextSpecific(2),
                    Value::Unsigned8(attrib.path.endpoint_id.unwrap()),
                );
            }
            if attrib.path.cluster_id.is_some() {
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte1),
                    TagControl::ContextSpecific(3),
                    Value::Unsigned8(attrib.path.cluster_id.unwrap()),
                );
            }
            if attrib.path.attribute_id.is_some() {
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte4),
                    TagControl::ContextSpecific(4),
                    Value::Unsigned32(attrib.path.attribute_id.unwrap()),
                );
            }

            encoder.write(
                TlvType::EndOfContainer,
                TagControl::Anonymous,
                Value::Container,
            );

            encoder.write_raw(TagControl::ContextSpecific(2), &attrib.value);

            encoder.write(
                TlvType::EndOfContainer,
                TagControl::Anonymous,
                Value::Container,
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

        encoder.write(
            TlvType::Boolean(self.is_fabric_filtered),
            TagControl::ContextSpecific(4),
            Value::Boolean(self.is_fabric_filtered),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(255),
            Value::Unsigned8(self.interaction_model_revision),
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
pub struct CommandPath {
    pub endpoint_id: u8,
    pub cluster_id: u8,
    pub command_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InvokeRequest {
    pub suppress_response: bool,
    pub timed_request: bool,
    pub invokes: heapless::Vec<(CommandPath, heapless::Vec<u8, 1024>), 10>,
}

impl InvokeRequest {
    pub fn from_tlv(data: &[u8]) -> InvokeRequest {
        let tlv = decode(data);

        let mut endpoint_id: Option<u8> = None;
        let mut cluster_id: Option<u8> = None;
        let mut command_id: Option<u32> = None;

        let mut suppress_response: Option<bool> = None;
        let mut timed_request: Option<bool> = None;

        let mut invokes: heapless::Vec<(CommandPath, TlvAnyData), 10> = heapless::Vec::new();
        let mut arg: Option<TlvAnyData> = None;

        let mut element = tlv;
        loop {
            if element.is_last() {
                break;
            }

            match element.get_control() {
                TagControl::ContextSpecific(0) => {
                    if let Value::Boolean(v) = element.get_value() {
                        suppress_response = Some(v);
                    }
                }
                TagControl::ContextSpecific(1) => {
                    if let Value::Boolean(v) = element.get_value() {
                        timed_request = Some(v);
                    }
                }

                TagControl::ContextSpecific(2) => {
                    element = element.next_in_container();
                    loop {
                        if element.is_last() {
                            break;
                        }
                        if element.get_type() == TlvType::EndOfContainer {
                            invokes
                                .push((
                                    CommandPath {
                                        endpoint_id: endpoint_id.unwrap(),
                                        cluster_id: cluster_id.unwrap(),
                                        command_id: command_id.unwrap(),
                                    },
                                    arg.as_ref().unwrap().clone(),
                                ))
                                .unwrap();
                            break;
                        }

                        match element.get_control() {
                            TagControl::ContextSpecific(0) => {
                                element = element.next_in_container();
                                loop {
                                    if element.is_last() {
                                        break;
                                    }
                                    if element.get_type() == TlvType::EndOfContainer {
                                        break;
                                    }

                                    match element.get_control() {
                                        TagControl::ContextSpecific(0) => {
                                            endpoint_id =
                                                Some(element.get_value().unsigned_value() as u8);
                                        }
                                        TagControl::ContextSpecific(1) => {
                                            cluster_id =
                                                Some(element.get_value().unsigned_value() as u8);
                                        }
                                        TagControl::ContextSpecific(2) => {
                                            command_id =
                                                Some(element.get_value().unsigned_value() as u32);
                                        }
                                        _ => (),
                                    }

                                    element = element.next_in_container();
                                }
                            }
                            TagControl::ContextSpecific(1) => {
                                let (next_element, data) = element.read_to_bytes();
                                arg = Some(data);
                                element = next_element;
                            }
                            _ => (),
                        }

                        element = element.next_in_container();
                    }
                }
                _ => (),
            }

            element = element.next_in_container();
        }

        InvokeRequest {
            suppress_response: suppress_response.unwrap(),
            timed_request: timed_request.unwrap(),
            invokes,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponsePath {
    pub endpoint_id: u8,
    pub cluster_id: u8,
    pub response_id: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub path: ResponsePath,
    pub response: TlvAnyData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Result {
    pub path: CommandPath,
    pub result: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponseField {
    pub response: Option<Response>,
    pub result: Option<Result>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InvokeResponse {
    pub supress_response: bool,
    pub responses: heapless::Vec<ResponseField, 10>,
    pub interaction_model_revision: u8,
}

impl InvokeResponse {
    pub fn encode_tlv(&self) -> heapless::Vec<u8, 1024> {
        let mut encoder = Encoder::new();

        encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

        encoder.write(
            TlvType::Boolean(self.supress_response),
            TagControl::ContextSpecific(0),
            Value::Boolean(self.supress_response),
        );

        encoder.write(
            TlvType::Array,
            TagControl::ContextSpecific(1),
            Value::Container,
        );
        for response_field in &self.responses {
            encoder.write(TlvType::Structure, TagControl::Anonymous, Value::Container);

            if response_field.response.is_some() {
                let response = response_field.response.as_ref().unwrap();
                encoder.write(
                    TlvType::Structure,
                    TagControl::ContextSpecific(0),
                    Value::Container,
                );

                encoder.write(
                    TlvType::List,
                    TagControl::ContextSpecific(0),
                    Value::Container,
                );
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte1),
                    TagControl::ContextSpecific(0),
                    Value::Unsigned8(response.path.endpoint_id),
                );
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte1),
                    TagControl::ContextSpecific(1),
                    Value::Unsigned8(response.path.cluster_id),
                );
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte2),
                    TagControl::ContextSpecific(2),
                    Value::Unsigned16(response.path.response_id),
                );
                encoder.write(
                    TlvType::EndOfContainer,
                    TagControl::Anonymous,
                    Value::Container,
                );

                encoder.write_raw(TagControl::ContextSpecific(1), &response.response);

                encoder.write(
                    TlvType::EndOfContainer,
                    TagControl::Anonymous,
                    Value::Container,
                );
            }

            if response_field.result.is_some() {
                let result = response_field.result.as_ref().unwrap();
                encoder.write(
                    TlvType::Structure,
                    TagControl::ContextSpecific(1),
                    Value::Container,
                );

                encoder.write(
                    TlvType::List,
                    TagControl::ContextSpecific(0),
                    Value::Container,
                );
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte1),
                    TagControl::ContextSpecific(0),
                    Value::Unsigned8(result.path.endpoint_id),
                );
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte1),
                    TagControl::ContextSpecific(1),
                    Value::Unsigned8(result.path.cluster_id),
                );
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte4),
                    TagControl::ContextSpecific(2),
                    Value::Unsigned32(result.path.command_id),
                );
                encoder.write(
                    TlvType::EndOfContainer,
                    TagControl::Anonymous,
                    Value::Container,
                );

                encoder.write(
                    TlvType::Structure,
                    TagControl::ContextSpecific(1),
                    Value::Container,
                );
                encoder.write(
                    TlvType::UnsignedInt(ElementSize::Byte1),
                    TagControl::ContextSpecific(0),
                    Value::Unsigned8(result.result),
                );
                encoder.write(
                    TlvType::EndOfContainer,
                    TagControl::Anonymous,
                    Value::Container,
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
        }
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            Value::Container,
        );

        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(255),
            Value::Unsigned8(self.interaction_model_revision),
        );

        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            Value::Container,
        );

        heapless::Vec::from_slice(encoder.to_slice()).unwrap()
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use std::print;
    use std::{format, println};

    use crate::interaction_messages::AttributeValue;
    use crate::tlv_codec::{Tlv, Value};

    use super::ReadRequest;
    use super::ReadResponse;
    use super::{AttributePath, InvokeResponse, ResponseField};

    extern crate std;

    #[test]
    fn test_decode_read_request() {
        let encoded = [
            0x15u8, 0x36, 0x0, 0x17, 0x24, 0x3, 0x31, 0x25, 0x4, 0xfc, 0xff, 0x18, 0x17, 0x24, 0x2,
            0x0, 0x24, 0x3, 0x30, 0x24, 0x4, 0x0, 0x18, 0x17, 0x24, 0x2, 0x0, 0x24, 0x3, 0x30,
            0x24, 0x4, 0x1, 0x18, 0x17, 0x24, 0x2, 0x0, 0x24, 0x3, 0x30, 0x24, 0x4, 0x2, 0x18,
            0x17, 0x24, 0x2, 0x0, 0x24, 0x3, 0x30, 0x24, 0x4, 0x3, 0x18, 0x17, 0x24, 0x2, 0x0,
            0x24, 0x3, 0x28, 0x24, 0x4, 0x2, 0x18, 0x17, 0x24, 0x2, 0x0, 0x24, 0x3, 0x28, 0x24,
            0x4, 0x4, 0x18, 0x17, 0x24, 0x3, 0x31, 0x24, 0x4, 0x3, 0x18, 0x18, 0x28, 0x3, 0x24,
            0xff, 0x1, 0x18,
        ];
        let msg = super::ReadRequest::from_tlv(&encoded);

        let wanted_attributes = heapless::Vec::from_slice(&[
            AttributePath {
                endpoint_id: None,
                cluster_id: Some(49),
                attribute_id: Some(65532),
            },
            AttributePath {
                endpoint_id: Some(0),
                cluster_id: Some(48),
                attribute_id: Some(0),
            },
            AttributePath {
                endpoint_id: Some(0),
                cluster_id: Some(48),
                attribute_id: Some(1),
            },
            AttributePath {
                endpoint_id: Some(0),
                cluster_id: Some(48),
                attribute_id: Some(2),
            },
            AttributePath {
                endpoint_id: Some(0),
                cluster_id: Some(48),
                attribute_id: Some(3),
            },
            AttributePath {
                endpoint_id: Some(0),
                cluster_id: Some(40),
                attribute_id: Some(2),
            },
            AttributePath {
                endpoint_id: Some(0),
                cluster_id: Some(40),
                attribute_id: Some(4),
            },
            AttributePath {
                endpoint_id: None,
                cluster_id: Some(49),
                attribute_id: Some(3),
            },
        ])
        .unwrap();
        let wanted = super::ReadRequest {
            attributes: wanted_attributes,
            is_fabric_filtered: false,
            interaction_model_revision: 1,
        };

        assert_eq!(wanted, msg);
    }

    #[test]
    fn test_encode_read_response() {
        let attributes = heapless::Vec::from_slice(&[
            AttributeValue {
                version: 0,
                path: AttributePath {
                    endpoint_id: Some(0),
                    cluster_id: Some(0x30),
                    attribute_id: Some(0x0),
                },
                value: Value::Unsigned16(0).to_simple_tlv(),
            },
            AttributeValue {
                version: 0,
                path: AttributePath {
                    endpoint_id: Some(0),
                    cluster_id: Some(0x30),
                    attribute_id: Some(0x1),
                },
                value: Value::Unsigned16(60).to_simple_tlv(),
            },
            AttributeValue {
                version: 0,
                path: AttributePath {
                    endpoint_id: Some(0),
                    cluster_id: Some(0x30),
                    attribute_id: Some(0x2),
                },
                value: Value::Unsigned16(0).to_simple_tlv(),
            },
            AttributeValue {
                version: 0,
                path: AttributePath {
                    endpoint_id: Some(0),
                    cluster_id: Some(0x30),
                    attribute_id: Some(0x3),
                },
                value: Value::Unsigned16(2).to_simple_tlv(),
            },
            AttributeValue {
                version: 0,
                path: AttributePath {
                    endpoint_id: Some(0),
                    cluster_id: Some(0x2b),
                    attribute_id: Some(0x0),
                },
                value: Value::Unsigned16(65521).to_simple_tlv(),
            },
            AttributeValue {
                version: 0,
                path: AttributePath {
                    endpoint_id: Some(0),
                    cluster_id: Some(0x2b),
                    attribute_id: Some(0x4),
                },
                value: Value::Unsigned16(32769).to_simple_tlv(),
            },
        ])
        .unwrap();

        let msg = ReadResponse {
            attributes,
            is_fabric_filtered: false,
            interaction_model_revision: 1,
        };

        let encoded = msg.encode_tlv();
        println!("{:02x?}", &encoded.to_slice());
        for v in encoded.to_slice().iter() {
            print!("{:02x},", v);
        }
        println!();

        //todo!();
    }

    #[test]
    fn test_decode_invoke_request() {
        env_logger::init();
        let payload = [
            0x15, 0x28, 0x00, 0x28, 0x01, 0x36, 0x02, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24,
            0x01, 0x30, 0x24, 0x02, 0x00, 0x18, 0x35, 0x01, 0x24, 0x00, 0x3c, 0x24, 0x01, 0x03,
            0x18, 0x18, 0x18, 0x24, 0xff, 0x01, 0x18,
        ];
        let decoded = super::InvokeRequest::from_tlv(&payload);

        assert_eq!(decoded.suppress_response, false);
        assert_eq!(decoded.timed_request, false);
        assert_eq!(decoded.invokes.len(), 1);
        assert_eq!(decoded.invokes[0].0.endpoint_id, 0);
        assert_eq!(decoded.invokes[0].0.cluster_id, 0x30);
        assert_eq!(decoded.invokes[0].0.command_id, 0);

        let mut data = crate::tlv_codec::decode(&decoded.invokes[0].1);

        data = data.next_in_container();
        assert_eq!(data.get_value().unsigned_value(), 60);
        data = data.next_in_container();
        assert_eq!(data.get_value().unsigned_value(), 3);
    }

    #[test]
    fn test_encode_invoke_response() {
        let _data = InvokeResponse {
            supress_response: false,
            responses: heapless::Vec::from_slice(&[ResponseField {
                response: Some(super::Response {
                    path: super::ResponsePath {
                        endpoint_id: 1,
                        cluster_id: 2,
                        response_id: 3,
                    },
                    response: Value::Unsigned16(1234).to_simple_tlv(),
                }),
                result: Some(super::Result {
                    path: super::CommandPath {
                        endpoint_id: 4,
                        cluster_id: 5,
                        command_id: 6,
                    },
                    result: 5,
                }),
            }])
            .unwrap(),
            interaction_model_revision: 0,
        };

        //todo!("{:02x?}", data.encode_tlv());
    }
}
