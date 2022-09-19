#[macro_export]
macro_rules! create_on_off_endpoint {
    ($on_handler: ident, $off_handler: ident, $toggle_handler: ident) => {
        {
            use $crate::interaction_model::{
                Attribute, Cluster, Command, DeviceDescription, Endpoint, InvokeHandlerResponse,
            };
            use $crate::tlv_codec::{ElementSize, Encoder, TagControl, TlvType, Value};

            Endpoint {
                id: 1,
                device: DeviceDescription {
                    name: "MA-onofflight",
                    code: 0x0100,
                },
                clusters: &[
                    Cluster {
                        id: 0x06,
                        name: "On/Off",
                        attributes: &[Attribute {
                            value: Value::Boolean(false).to_simple_tlv(),
                            version: 0,
                            id: 0,
                            name: "OnOff",
                        }],
                        commands: &[
                            Command {
                                invoke_id: 0,
                                response_id: 0,
                                name: "Off",
                                handler: &$off_handler,
                            },
                            Command {
                                invoke_id: 1,
                                response_id: 1,
                                name: "On",
                                handler: &$on_handler,
                            },
                            Command {
                                invoke_id: 2,
                                response_id: 2,
                                name: "Toggle",
                                handler: &$toggle_handler,
                            },
                        ],
                    },
                    Cluster {
                        id: 0x1d,
                        name: "Descriptor",
                        attributes: &[
                            Attribute {
                                value: {
                                    let mut encoder = Encoder::new();
                                    encoder.write(
                                        TlvType::Array,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );
                                    encoder.write(
                                        TlvType::UnsignedInt(ElementSize::Byte2),
                                        TagControl::ContextSpecific(0),
                                        Value::Unsigned16(0x0100),
                                    ); // = device.code
                                    encoder.write(
                                        TlvType::UnsignedInt(ElementSize::Byte1),
                                        TagControl::ContextSpecific(1),
                                        Value::Unsigned8(1),
                                    ); // = revision
                                    encoder.write(
                                        TlvType::EndOfContainer,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );

                                    heapless::Vec::from_slice(encoder.to_slice()).unwrap()
                                },
                                version: 0,
                                id: 0,
                                name: "DeviceList",
                            },
                            Attribute {
                                value: {
                                    let mut encoder = Encoder::new();
                                    encoder.write(
                                        TlvType::Array,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );
                                    encoder.write(
                                        TlvType::UnsignedInt(ElementSize::Byte1),
                                        TagControl::Anonymous,
                                        Value::Unsigned8(0x1d),
                                    ); // = id descriptor cluster
                                    encoder.write(
                                        TlvType::UnsignedInt(ElementSize::Byte1),
                                        TagControl::Anonymous,
                                        Value::Unsigned8(0x06),
                                    ); // = on/off cluster
                                    encoder.write(
                                        TlvType::EndOfContainer,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );

                                    heapless::Vec::from_slice(encoder.to_slice()).unwrap()
                                },
                                version: 0,
                                id: 1,
                                name: "ServerList",
                            },
                            Attribute {
                                value: {
                                    let mut encoder = Encoder::new();
                                    encoder.write(
                                        TlvType::Array,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );
                                    encoder.write(
                                        TlvType::EndOfContainer,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );

                                    heapless::Vec::from_slice(encoder.to_slice()).unwrap()
                                },
                                version: 0,
                                id: 3,
                                name: "ClientList",
                            },
                            Attribute {
                                value: {
                                    let mut encoder = Encoder::new();
                                    encoder.write(
                                        TlvType::Array,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );
                                    // new Attribute(4, "PartsList", ArrayT(UnsignedIntT), endpoint.id === 0 ? allEndpoints.map(endpoint => endpoint.id).filter(endpointId => endpointId !== 0) : []),
                                    encoder.write(
                                        TlvType::EndOfContainer,
                                        TagControl::Anonymous,
                                        Value::Container,
                                    );

                                    heapless::Vec::from_slice(encoder.to_slice()).unwrap()
                                },
                                version: 0,
                                id: 4,
                                name: "PartsList",
                            },
                        ],
                        commands: &[],
                    },
                ],
            }
        }
    }
}

pub use create_on_off_endpoint;
