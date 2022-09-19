use core::{fmt::Debug, marker::PhantomData};

use crate::{
    interaction_messages::{AttributePath, CommandPath},
    MatterContext, TlvAnyData,
};

#[derive(Debug)]
pub struct Attribute<'a> {
    pub value: TlvAnyData,
    pub version: u8,
    pub id: u32,
    pub name: &'a str,
}

pub enum InvokeHandlerResponse {
    Message(TlvAnyData),
    Result(u8),
    None,
}

impl InvokeHandlerResponse {
    pub fn message(data: TlvAnyData) -> InvokeHandlerResponse {
        InvokeHandlerResponse::Message(data)
    }

    pub fn result(result: u8) -> InvokeHandlerResponse {
        InvokeHandlerResponse::Result(result)
    }
}

pub struct Command<'a> {
    pub invoke_id: u32,
    pub response_id: u16,
    pub name: &'a str,
    pub handler: &'a dyn Fn(TlvAnyData, &MatterContext) -> InvokeHandlerResponse,
}

impl<'a> Debug for Command<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Command")
            .field("invoke_id", &self.invoke_id)
            .field("response_id", &self.response_id)
            .field("name", &self.name)
            .finish()
    }
}

#[derive(Debug)]
pub struct Cluster<'a> {
    pub id: u8,
    pub name: &'a str,
    pub attributes: &'a [Attribute<'a>],
    pub commands: &'a [Command<'a>],
}

#[derive(Debug)]
pub struct DeviceDescription<'a> {
    pub name: &'a str,
    pub code: u16,
}

#[derive(Debug)]
pub struct Endpoint<'a> {
    pub id: u8,
    pub device: DeviceDescription<'a>,
    pub clusters: &'a [Cluster<'a>],
}

#[derive(Debug)]
pub struct Device<'a> {
    pub endpoints: &'a [Endpoint<'a>],
    pub _phantom: PhantomData<&'a ()>,
}

impl<'a> Device<'a> {
    pub fn new(endpoints: &'a [Endpoint<'a>]) -> Device<'a> {
        Device {
            endpoints,
            _phantom: PhantomData::default(),
        }
    }

    pub fn all_attribute_values(
        &mut self,
    ) -> heapless::Vec<(AttributePath, &'a Attribute<'a>), 10> {
        let mut res = heapless::Vec::new();

        for endpoint in self.endpoints {
            for cluster in endpoint.clusters {
                for attribute in cluster.attributes {
                    let path = AttributePath {
                        endpoint_id: Some(endpoint.id),
                        cluster_id: Some(cluster.id),
                        attribute_id: Some(attribute.id),
                    };
                    res.push((path, attribute)).unwrap();
                }
            }
        }

        res
    }

    pub fn attribute_values(
        &mut self,
        to_find: AttributePath,
    ) -> heapless::Vec<(AttributePath, &'a Attribute<'a>), 10> {
        let mut res = heapless::Vec::new();

        for endpoint in self.endpoints {
            if to_find.endpoint_id.is_some()
                && endpoint.id != *to_find.endpoint_id.as_ref().unwrap()
            {
                continue;
            }

            for cluster in endpoint.clusters {
                if to_find.cluster_id.is_some()
                    && cluster.id != *to_find.cluster_id.as_ref().unwrap()
                {
                    continue;
                }

                for attribute in cluster.attributes {
                    if to_find.attribute_id.is_some()
                        && attribute.id != *to_find.attribute_id.as_ref().unwrap()
                    {
                        continue;
                    }

                    let path = AttributePath {
                        endpoint_id: Some(endpoint.id),
                        cluster_id: Some(cluster.id),
                        attribute_id: Some(attribute.id),
                    };
                    res.push((path, attribute)).unwrap();
                }
            }
        }

        res
    }

    pub fn invoke(
        &mut self,
        command_path: CommandPath,
        arg: TlvAnyData,
        context: &MatterContext,
    ) -> InvokeHandlerResponse {
        for endpoint in self.endpoints {
            if endpoint.id == command_path.endpoint_id {
                for cluster in endpoint.clusters {
                    if cluster.id == command_path.cluster_id {
                        for command in cluster.commands {
                            if command_path.command_id == command.invoke_id {
                                return (command.handler)(arg.clone(), context);
                            }
                        }
                    }
                }
            }
        }

        panic!("Nothing found to invoke ... that shouldn't be a panic!");
    }

    pub(crate) fn get_response_id(&self, command_path: &CommandPath) -> u16 {
        for endpoint in self.endpoints {
            if endpoint.id == command_path.endpoint_id {
                for cluster in endpoint.clusters {
                    if cluster.id == command_path.cluster_id {
                        for command in cluster.commands {
                            if command_path.command_id == command.invoke_id {
                                return command.response_id;
                            }
                        }
                    }
                }
            }
        }

        panic!("No command found ... that shouldn't be a panic!");
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use core::cell::RefCell;
    use std::print;
    use std::{format, println};

    use crate::fabric::Fabric;
    use crate::protocol::secure_channel::CaseContext;
    use crate::tlv_codec::Value;
    use crate::tlv_codec::{decode, Encoder, TagControl, Tlv, TlvData, TlvType};

    use super::*;

    extern crate std;

    #[test]
    fn test_define_device() {
        let var = RefCell::new(0u32);
        let handler1 = |_v, _s: &MatterContext| todo!();
        let handler2 = |v: TlvAnyData, _s: &MatterContext| {
            let tlv = decode(&v);
            var.replace(tlv.get_value().unsigned_value() as u32);
            InvokeHandlerResponse::None
        };

        let endpoints = [
            Endpoint {
                id: 0,
                device: DeviceDescription {
                    name: "MA-rootdevice",
                    code: 0x0016,
                },
                clusters: &[Cluster {
                    id: 0x0,
                    name: "cluster",
                    attributes: &[Attribute {
                        value: Value::Signed8(0).to_simple_tlv(),
                        version: 0,
                        id: 0x1234,
                        name: "cluster-name",
                    }],
                    commands: &[Command {
                        invoke_id: 0x4321,
                        response_id: 0x5678,
                        name: "Command Name",
                        handler: &handler1,
                    }],
                }],
            },
            Endpoint {
                id: 1,
                device: DeviceDescription {
                    name: "MA2",
                    code: 0x0032,
                },
                clusters: &[Cluster {
                    id: 0x3,
                    name: "cluster2",
                    attributes: &[Attribute {
                        value: Value::Signed8(5).to_simple_tlv(),
                        version: 0,
                        id: 0x1235,
                        name: "cluster-name",
                    }],
                    commands: &[Command {
                        invoke_id: 0x4322,
                        response_id: 0x5679,
                        name: "Command Name2",
                        handler: &handler2,
                    }],
                }],
            },
        ];
        let mut device = Device::new(&endpoints);

        println!("{:?}", device);

        let attrs = device.all_attribute_values();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].1.id, 0x1234);

        let attrs = device.attribute_values(AttributePath {
            endpoint_id: None,
            cluster_id: None,
            attribute_id: None,
        });
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].1.id, 0x1234);

        let attrs = device.attribute_values(AttributePath {
            endpoint_id: None,
            cluster_id: None,
            attribute_id: Some(0x1235),
        });
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].1.id, 0x1235);

        let mut arg = Encoder::new();
        arg.write(
            TlvType::UnsignedInt(crate::tlv_codec::ElementSize::Byte1),
            TagControl::Anonymous,
            Value::Unsigned8(42),
        );

        let ctx = MatterContext::new(crate::Certificates {
            device_private_key: [0u8; 32],
            device_certificate: heapless::Vec::new(),
            product_intermediate_certificate: heapless::Vec::new(),
            certificate_declaration: heapless::Vec::new(),
        });

        device.invoke(
            CommandPath {
                endpoint_id: 1,
                cluster_id: 3,
                command_id: 0x4322,
            },
            TlvAnyData::from_slice(arg.to_slice()).unwrap(),
            &ctx,
        );

        assert_eq!(*(var.borrow()), 42);
    }
}
