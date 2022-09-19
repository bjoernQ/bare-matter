use crate::{
    cluster::{
        general_commissioning_cluster::{
            ArmFailSafeRequest, SetRegulatoryConfigRequest, SuccessFailureReponse,
        },
        operational_credentials_cluster::{
            AddNocRequest, AddTrustedRootCertificateRequest, Attestation, AttestationResponse,
            CertificateChainRequest, CertificateChainResponse, CertificateSigningRequest,
            CsrResponse, RequestWithNonce, StatusResponse,
        },
    },
    interaction_model::InvokeHandlerResponse,
    MatterContext, TlvAnyData,
};

enum CertificateType {
    DeviceAttestation = 1,
    ProductAttestationIntermediate = 2,
}

impl From<u8> for CertificateType {
    fn from(v: u8) -> Self {
        match v {
            1 => CertificateType::DeviceAttestation,
            2 => CertificateType::ProductAttestationIntermediate,
            _ => panic!(),
        }
    }
}

#[macro_export]
macro_rules! create_root_device {
    () => {
        {
            use $crate::interaction_model::{
                Attribute, Cluster, Command, DeviceDescription, Endpoint, InvokeHandlerResponse,
            };
            use $crate::tlv_codec::{ElementSize, Encoder, TagControl, TlvType, Value};

            Endpoint {

            id: 0,
            device: DeviceDescription {
                name: "MA-rootdevice",
                code: 0x0016,
            },
            clusters: &[
                Cluster {
                    id: 0x28,
                    name: "Basic",
                    attributes: &[
                        Attribute {
                            value: Value::String(
                                heapless::Vec::from_slice(b"node-matter").unwrap(),
                            )
                            .to_simple_tlv(),
                            version: 0,
                            id: 1,
                            name: "VendorName",
                        },
                        Attribute {
                            value: Value::Unsigned16(0xFFF1).to_simple_tlv(),
                            version: 0,
                            id: 2,
                            name: "VendorID",
                        },
                        Attribute {
                            value: Value::String(
                                heapless::Vec::from_slice(b"Matter test device").unwrap(),
                            )
                            .to_simple_tlv(),
                            version: 0,
                            id: 3,
                            name: "ProductName",
                        },
                        Attribute {
                            value: Value::Unsigned16(0x8001).to_simple_tlv(),
                            version: 0,
                            id: 4,
                            name: "ProductID",
                        },
                    ],
                    commands: &[],
                },
                Cluster {
                    id: 0x30,
                    name: "General Commissioning",
                    attributes: &[],
                    commands: &[
                        Command {
                            invoke_id: 0,
                            response_id: 1,
                            name: "ArmFailSafe",
                            handler: &$crate::endpoint::rootdevice::arm_failsafe_handler,
                        },
                        Command {
                            invoke_id: 2,
                            response_id: 3,
                            name: "SetRegulatoryConfig",
                            handler: &$crate::endpoint::rootdevice::set_regulatory_config_handler,
                        },
                        Command {
                            invoke_id: 4,
                            response_id: 5,
                            name: "CommissioningComplete",
                            handler: &$crate::endpoint::rootdevice::commissioning_complete_handler,
                        },
                    ],
                },
                Cluster {
                    id: 0x3e,
                    name: "Operational Credentials",
                    attributes: &[],
                    commands: &[
                        Command {
                            invoke_id: 0,
                            response_id: 1,
                            name: "AttestationRequest",
                            handler: &$crate::endpoint::rootdevice::attestation_request_handler,
                        },
                        Command {
                            invoke_id: 2,
                            response_id: 3,
                            name: "CertificateChainRequest",
                            handler: &$crate::endpoint::rootdevice::cerfificate_chain_request_handler,
                        },
                        Command {
                            invoke_id: 4,
                            response_id: 5,
                            name: "CSRRequest",
                            handler: &$crate::endpoint::rootdevice::csr_request_handler,
                        },
                        Command {
                            invoke_id: 6,
                            response_id: 8,
                            name: "AddNOC",
                            handler: &$crate::endpoint::rootdevice::add_noc_handler,
                        },
                        Command {
                            invoke_id: 11,
                            response_id: 11,
                            name: "AddTrustedRootCertificate",
                            handler: &$crate::endpoint::rootdevice::add_trust_root_certificate_handler,
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
                                    TlvType::UnsignedInt(ElementSize::Byte1),
                                    TagControl::ContextSpecific(0),
                                    Value::Unsigned8(0x0016),
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
                                    Value::Unsigned8(0x28),
                                ); // = basic cluster
                                encoder.write(
                                    TlvType::UnsignedInt(ElementSize::Byte1),
                                    TagControl::Anonymous,
                                    Value::Unsigned8(0x30),
                                ); // = general commissioning  cluster
                                encoder.write(
                                    TlvType::UnsignedInt(ElementSize::Byte1),
                                    TagControl::Anonymous,
                                    Value::Unsigned8(0x3e),
                                ); // = operational cluster
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
                                    TlvType::UnsignedInt(ElementSize::Byte1),
                                    TagControl::Anonymous,
                                    Value::Unsigned8(1),
                                ); // = all endpoints but 0
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
    };
}

pub use create_root_device;

pub fn arm_failsafe_handler(value: TlvAnyData, _context: &MatterContext) -> InvokeHandlerResponse {
    let _req = ArmFailSafeRequest::from_tlv(&value);
    let resp = SuccessFailureReponse {
        error_code: 0,
        debug_text: "",
    };

    InvokeHandlerResponse::message(resp.encode_tlv().to_vec())
}

pub fn commissioning_complete_handler(
    _value: TlvAnyData,
    _context: &MatterContext,
) -> InvokeHandlerResponse {
    let resp = SuccessFailureReponse {
        error_code: 0,
        debug_text: "",
    };

    InvokeHandlerResponse::message(resp.encode_tlv().to_vec())
}

pub fn set_regulatory_config_handler(
    value: TlvAnyData,
    _context: &MatterContext,
) -> InvokeHandlerResponse {
    let _req = SetRegulatoryConfigRequest::from_tlv(&value);

    let resp = SuccessFailureReponse {
        error_code: 0,
        debug_text: "",
    };

    InvokeHandlerResponse::message(resp.encode_tlv().to_vec())
}

pub fn attestation_request_handler(
    value: TlvAnyData,
    context: &MatterContext,
) -> InvokeHandlerResponse {
    let req = RequestWithNonce::from_tlv(&value);

    let attestation_key = context.with_secure_sessions(|sessions| {
        // TODO find the one for this session!
        sessions.first().unwrap().attestation_key
    });

    let elements = Attestation {
        declaration: heapless::Vec::from_slice(&context.certificates.certificate_declaration)
            .unwrap(),
        nonce: req.nonce,
        timestamp: 0,
        firmware_info: None,
    };
    let elements_encoded = elements.encode_tlv();

    /*
    this.signWithDeviceKey(session, elements)

    private signWithDeviceKey(session: Session, data: Buffer) {
        return Crypto.sign(this.conf.devicePrivateKey, [data, session.getAttestationChallengeKey()]);
    }
    */
    let mut data: heapless::Vec<u8, 1024> = heapless::Vec::new();
    data.extend_from_slice(elements_encoded.to_slice()).unwrap();
    data.extend_from_slice(&attestation_key).unwrap();
    let signature = crate::crypto::sign(&context.certificates.device_private_key, &data);
    let resp = AttestationResponse {
        elements: heapless::Vec::from_slice(elements_encoded.to_slice()).unwrap(),
        signature: heapless::Vec::from_slice(&signature).unwrap(),
    };

    InvokeHandlerResponse::message(resp.encode_tlv().to_vec())
}

pub fn cerfificate_chain_request_handler(
    value: TlvAnyData,
    context: &MatterContext,
) -> InvokeHandlerResponse {
    let req = CertificateChainRequest::from_tlv(&value);

    let resp = CertificateChainResponse {
        certificate: {
            match req.cert_type.into() {
                CertificateType::DeviceAttestation => {
                    heapless::Vec::from_slice(&context.certificates.device_certificate).unwrap()
                }
                CertificateType::ProductAttestationIntermediate => heapless::Vec::from_slice(
                    &context.certificates.product_intermediate_certificate,
                )
                .unwrap(),
            }
        },
    };

    InvokeHandlerResponse::message(resp.encode_tlv().to_vec())
}

pub fn csr_request_handler(value: TlvAnyData, context: &MatterContext) -> InvokeHandlerResponse {
    let req = RequestWithNonce::from_tlv(&value);

    let attestation_key = context.with_secure_sessions(|sessions| {
        // TODO find the one for this session!
        sessions.first().unwrap().attestation_key
    });

    let key_pair = context.with_fabric(|f| f.key_pair.clone());
    let csr: heapless::Vec<u8, 1024> = crate::x509::create_certificate_signing_request(key_pair);
    let elements = CertificateSigningRequest {
        csr: csr,
        nonce: req.nonce,
        vendor_reserved_1: None,
        vendor_reserved_2: None,
        vendor_reserved_3: None,
    };

    let elements_encoded = elements.encode_tlv();

    let mut data: heapless::Vec<u8, 1024> = heapless::Vec::new();
    data.extend_from_slice(elements_encoded.to_slice()).unwrap();
    data.extend_from_slice(&attestation_key).unwrap();
    let signature = crate::crypto::sign(&context.certificates.device_private_key, &data);

    let resp = CsrResponse {
        elements: elements.encode_tlv().to_vec(),
        signature: heapless::Vec::from_slice(&signature).unwrap(),
    };

    InvokeHandlerResponse::message(resp.encode_tlv().to_vec())
}

pub fn add_noc_handler(value: TlvAnyData, context: &MatterContext) -> InvokeHandlerResponse {
    let req = AddNocRequest::from_tlv(&value);

    // this.fabricBuilder.setNewOpCert(nocCert);
    // if (icaCert.length > 0) this.fabricBuilder.setIntermediateCACert(icaCert);
    // this.fabricBuilder.setVendorId(adminVendorId);
    // this.fabricBuilder.setIdentityProtectionKey(ipkValue);

    // const fabric = await this.fabricBuilder.build();
    // this.fabricBuilder = undefined;
    // session.getServer().getFabricManager().addFabric(fabric);
    // session.setFabric(fabric);

    // // TODO: create ACL with caseAdminNode

    // const mdnsServer = session.getServer().getMdnsServer();
    // mdnsServer.addRecordsForFabric(fabric);
    // await mdnsServer.announce();

    context.with_fabric(|fabric| {
        fabric.configure(
            req.noc_cert.clone(),
            req.ica_cert.clone(),
            req.ipk_value.clone(),
            req.case_admin_node,
            req.admin_vendor_id,
        );
    });

    let resp = StatusResponse {
        status: 0,
        fabric_index: None,
        debug_text: None,
    };

    InvokeHandlerResponse::message(resp.encode_tlv().to_vec())
}

pub fn add_trust_root_certificate_handler(
    value: TlvAnyData,
    context: &MatterContext,
) -> InvokeHandlerResponse {
    let req = AddTrustedRootCertificateRequest::from_tlv(&value);

    context.with_fabric(|fabric| {
        fabric.set_root_certificate(req.certificate.clone());
    });

    // this.rootPublicKey = TlvObjectCodec.decode(certificate, CertificateT).ellipticCurvePublicKey;
    // TODO persist the certificate

    InvokeHandlerResponse::Result(0)
}
