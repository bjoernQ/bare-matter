use crypto_bigint::generic_array::GenericArray;
use elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdh::SharedSecret;

use crate::{
    case_messages::{
        CaseSigma1, CaseSigma2, CaseSigma3, TagBasedEcryptionData, TagBasedSignatureData,
    },
    fabric::Certificate,
    pase_messages::{self, PbkdfParamRequest},
    protocol::ProtocolHandlerResponse,
    spake2p::MatterSpake,
    MatterContext, MessageType,
};

use super::{ProtocolHandler, SecureSessionParameters};

pub struct SecureChannel<'a> {
    random: [u8; 32],
    salt: [u8; 32],
    peer_random: [u8; 32],
    setup_pin: u32,
    pbkdf_request_payload: Option<heapless::Vec<u8, 256>>,
    pbkdf_response_payload: Option<heapless::Vec<u8, 256>>,
    shared_secret: Option<heapless::Vec<u8, 32>>,
    session_id: Option<u16>,
    context: &'a MatterContext,
}

impl<'a> SecureChannel<'a> {
    pub fn new(context: &'a MatterContext, random: [u8; 32], salt: [u8; 32]) -> SecureChannel {
        SecureChannel {
            random,
            salt,
            peer_random: [0u8; 32],
            setup_pin: 20202021,
            pbkdf_request_payload: None,
            pbkdf_response_payload: None,
            shared_secret: None,
            session_id: None,
            context,
        }
    }

    fn make_secure_session_parameters(
        &mut self,
        session_id: u16,
        salt: &[u8],
        node_id: u64,
        peer_node_id: u64,
    ) -> SecureSessionParameters {
        let keys = crate::crypto::hkdf(
            self.shared_secret.as_ref().unwrap(),
            salt,
            b"SessionKeys",
            48,
        );

        let is_initiator = false;
        let decrypt_key = if is_initiator {
            &keys[16..32]
        } else {
            &keys[0..16]
        };
        let encrypt_key = if is_initiator {
            &keys[0..16]
        } else {
            &keys[16..32]
        };
        let attestation_key = &keys[32..48];

        SecureSessionParameters {
            session_id: session_id,
            node_id,
            peer_node_id,
            decrypt_key: decrypt_key.try_into().unwrap(),
            encrypt_key: encrypt_key.try_into().unwrap(),
            attestation_key: attestation_key.try_into().unwrap(),
        }
    }
}

impl<'a> ProtocolHandler for SecureChannel<'a> {
    fn on_message(
        &mut self,
        _header: &crate::message_codec::MessageHeader,
        payload_header: &crate::message_codec::PayloadHeader,
        payload: &[u8],
    ) -> ProtocolHandlerResponse {
        match payload_header.message_type.into() {
            MessageType::StandaloneAck => {
                log::info!("StandaloneAck");
                // ??? close ???
                ProtocolHandlerResponse::None
            }
            MessageType::PbkdfParamRequest => {
                log::info!("PbkdfParamRequest");

                self.pbkdf_request_payload = Some(heapless::Vec::from_slice(&payload).unwrap());
                let decoded = PbkdfParamRequest::from_tlv(&payload);
                self.peer_random = decoded.random;

                let resp = pase_messages::PbkdfParamResponse {
                    peer_random: decoded.random,
                    random: self.random.clone(),
                    session_id: decoded.session_id,
                    pbkdf_parameters: Some(pase_messages::PbkdfParameters {
                        iteration: 1000,
                        salt: self.salt.clone(),
                    }),
                    mrp_parameters_idle_retrans_timeout_ms: Some(5000),
                    mrp_parameters_active_retrans_timeout_ms: Some(300),
                };

                let encoded = resp.encode_tlv();

                self.pbkdf_response_payload =
                    Some(heapless::Vec::from_slice(encoded.to_slice()).unwrap());

                self.session_id = Some(decoded.session_id);

                ProtocolHandlerResponse::response(
                    MessageType::PbkdfParamResponse,
                    false,
                    true,
                    encoded.to_slice(),
                )
            }
            MessageType::PasePake1 => {
                log::info!("PasePake1");

                let decoded = pase_messages::PasePake1::from_tlv(payload);

                let mut to_hash: heapless::Vec<u8, 256> = heapless::Vec::new();
                to_hash
                    .extend_from_slice(b"CHIP PAKE V1 Commissioning")
                    .unwrap();
                to_hash
                    .extend_from_slice(&self.pbkdf_request_payload.as_ref().unwrap())
                    .unwrap();
                to_hash
                    .extend_from_slice(&self.pbkdf_response_payload.as_ref().unwrap())
                    .unwrap();
                let hash = crate::crypto::hash(&to_hash);

                let spake =
                    MatterSpake::create(&hash, self.setup_pin, &self.salt, 1000, &self.random);

                let x = decoded.x;
                let y = spake.compute_y();
                let (ke, _hay, hbx) = spake.compute_secret_and_verifiers_from_x(&x, &y);

                self.shared_secret = Some(ke.as_slice().try_into().unwrap());

                // try to answer this request ...
                let resp = pase_messages::PasePake2 {
                    y: y.as_slice().try_into().unwrap(),
                    verifier: hbx.as_slice().try_into().unwrap(),
                };
                log::info!("PasePake2 {:x?}", resp);

                let encoded = resp.encode_tlv();

                ProtocolHandlerResponse::response(
                    MessageType::PasePake2,
                    false,
                    true,
                    encoded.to_slice(),
                )
            }
            MessageType::PasePake3 => {
                log::info!("PasePake3");

                // then send success like `sendStatusReport(GeneralStatusCode.Success, ProtocolStatusCode.Success)`
                // export const enum GeneralStatusCode {
                //     Success = 0x0000,
                //     Error = 0x0001,
                // }
                // export const enum ProtocolStatusCode {
                //     Success = 0x0000,
                //     InvalidParam = 0x0002,
                // }

                //self.enter_encrypted();

                ProtocolHandlerResponse::InitiateSecureSession(self.make_secure_session_parameters(
                    self.session_id.unwrap(),
                    &[],
                    0,
                    0,
                ))
            }
            MessageType::Sigma1 => {
                let sigma1 = CaseSigma1::from_tlv(payload);
                log::info!("{:?}", sigma1);

                if sigma1.resumption_id.is_some() {
                    log::warn!("CASE session resume not yet supported");
                }

                let (secret, shared_secret) = crate::crypto::ecdh(&sigma1.ecdh_public_key);
                let pk_encoded_point = secret.public_key().to_encoded_point(false);
                let public_key_bytes = pk_encoded_point.as_bytes();
                let ipk = &self
                    .context
                    .with_fabric(|f| f.identity_protection_key.clone());
                let op_cert = self.context.with_fabric(|f| f.new_op_cert.clone());

                let mut sigma2_salt: heapless::Vec<u8, 256> = heapless::Vec::new();
                sigma2_salt.extend_from_slice(ipk).unwrap();
                sigma2_salt.extend_from_slice(&self.random).unwrap();
                sigma2_salt.extend_from_slice(public_key_bytes).unwrap();
                sigma2_salt
                    .extend_from_slice(&crate::crypto::hash(&payload))
                    .unwrap();

                let hkdf: hkdf::Hkdf<sha2::Sha256> =
                    hkdf::Hkdf::new(Some(&sigma2_salt), &shared_secret.raw_secret_bytes());
                let mut sigma2_key = [0u8; 16];
                hkdf.expand(b"Sigma2", &mut sigma2_key)
                    .expect("16 is a valid length");

                let signature_data = TagBasedSignatureData {
                    new_op_cert: op_cert.clone(),
                    intermediate_ca_cert: None,
                    ecdh_public_key: heapless::Vec::from_slice(public_key_bytes).unwrap(),
                    peer_ecdh_public_key: heapless::Vec::from_slice(&sigma1.ecdh_public_key)
                        .unwrap(),
                }
                .encode_tlv();
                let signature = self
                    .context
                    .with_fabric(|f| f.sign(signature_data.to_slice()));

                let resumption_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]; // TODO this should be random!

                let encrypted_data = TagBasedEcryptionData {
                    new_op_cert: op_cert.clone(),
                    intermediate_ca_cert: None,
                    signature: heapless::Vec::from_slice(&signature).unwrap(),
                    resumption_id: Some(heapless::Vec::from_slice(&resumption_id).unwrap()),
                }
                .encode_tlv();

                let encrypted = crate::crypto::encrypt(
                    &sigma2_key,
                    encrypted_data.to_slice(),
                    b"NCASE_Sigma2N",
                    None,
                );
                let new_session_id = self
                    .context
                    .with_secure_sessions(|s| s.iter().map(|f| f.session_id).max())
                    .unwrap()
                    + 1;
                self.context
                    .with_case_context(|c| c.future_session_id = new_session_id);

                let res = CaseSigma2 {
                    random: heapless::Vec::from_slice(&self.random).unwrap(),
                    session_id: new_session_id,
                    ecdh_public_key: heapless::Vec::from_slice(public_key_bytes).unwrap(),
                    encrypted: heapless::Vec::from_slice(&encrypted).unwrap(),
                    mrp_parameters_idle_retrans_timeout_ms: sigma1
                        .mrp_parameters_idle_retrans_timeout_ms,
                    mrp_parameters_active_retrans_timeout_ms: sigma1
                        .mrp_parameters_active_retrans_timeout_ms,
                };

                log::info!("Sigma2 {:?}", res);
                let encoded = res.encode_tlv();

                self.context.with_case_context(|ctx| {
                    ctx.sigma1_bytes = Some(heapless::Vec::from_slice(&payload).unwrap());
                    ctx.sigma2_bytes = Some(heapless::Vec::from_slice(encoded.to_slice()).unwrap());
                    ctx.shared_secret =
                        Some(heapless::Vec::from_slice(&shared_secret.raw_secret_bytes()).unwrap());
                    ctx.ecdh_public_key =
                        Some(heapless::Vec::from_slice(&public_key_bytes).unwrap());
                    ctx.peer_ecdh_public_key = Some(sigma1.ecdh_public_key.clone());
                });

                ProtocolHandlerResponse::response(
                    MessageType::Sigma2,
                    false,
                    true,
                    encoded.to_slice(),
                )
            }
            MessageType::Sigma2 => todo!(),
            MessageType::Sigma3 => {
                let sigma3 = CaseSigma3::from_tlv(payload);
                log::info!("{:?}", sigma3);

                let ipk = &self
                    .context
                    .with_fabric(|f| f.identity_protection_key.clone());

                let mut sigma3_salt: heapless::Vec<u8, 256> = heapless::Vec::new();
                sigma3_salt.extend_from_slice(ipk).unwrap();
                let mut message_bytes: heapless::Vec<u8, 1024> = heapless::Vec::new();
                let sigma1_bytes = self
                    .context
                    .with_case_context(|ctx| ctx.sigma1_bytes.as_ref().unwrap().clone());
                let sigma2_bytes = self
                    .context
                    .with_case_context(|ctx| ctx.sigma2_bytes.as_ref().unwrap().clone());
                message_bytes.extend_from_slice(&sigma1_bytes).unwrap();
                message_bytes.extend_from_slice(&sigma2_bytes).unwrap();
                sigma3_salt
                    .extend_from_slice(&crate::crypto::hash(&message_bytes))
                    .unwrap();

                let shared_secret: SharedSecret = self.context.with_case_context(|ctx| {
                    let bytes: &[u8] = ctx.shared_secret.as_ref().unwrap();
                    let ga = GenericArray::from_slice(bytes);
                    SharedSecret::from(*ga)
                });

                let mut sigma3_key = [0u8; 16];
                shared_secret
                    .extract::<sha2::Sha256>(Some(&sigma3_salt))
                    .expand(b"Sigma3", &mut sigma3_key)
                    .expect("16 is a valid length");

                let peer_encrypted_data =
                    crate::crypto::decrypt(&sigma3_key, &sigma3.encrypted, b"NCASE_Sigma3N", None);

                // const { newOpCert: peerNewOpCert, intermediateCACert: peerIntermediateCACert, signature: peerSignature } = TlvObjectCodec.decode(peerEncryptedData, TagBasedEcryptionDataT);
                let encrypted_data = TagBasedEcryptionData::from_tlv(&peer_encrypted_data);

                // !!! TODO fabric.verifyCredentials(peerNewOpCert, peerIntermediateCACert);

                let peer_ecdh_public_key = self
                    .context
                    .with_case_context(|ctx| ctx.peer_ecdh_public_key.as_ref().unwrap().clone());
                let ecdh_public_key = self
                    .context
                    .with_case_context(|ctx| ctx.ecdh_public_key.as_ref().unwrap().clone());
                let _peer_signature_data = TagBasedSignatureData {
                    new_op_cert: encrypted_data.new_op_cert.clone(),
                    intermediate_ca_cert: encrypted_data.intermediate_ca_cert,
                    ecdh_public_key: ecdh_public_key,
                    peer_ecdh_public_key: peer_ecdh_public_key,
                }
                .encode_tlv();

                let peer_noc_certificate = Certificate::from_tlv(&encrypted_data.new_op_cert);
                let peer_node_id = peer_noc_certificate.subject.node_id;

                log::info!("peer_noc_certificate {:?}", peer_noc_certificate);

                // !!! TODO Crypto.verify(peerPublicKey, peerSignatureData, peerSignature);

                // All good! Create secure session

                let mut secure_session_salt: heapless::Vec<u8, 2048> = heapless::Vec::new();
                secure_session_salt.extend_from_slice(&ipk).unwrap();
                let mut message_bytes: heapless::Vec<u8, 1024> = heapless::Vec::new();
                message_bytes.extend_from_slice(&sigma1_bytes).unwrap();
                message_bytes.extend_from_slice(&sigma2_bytes).unwrap();
                message_bytes.extend_from_slice(&payload).unwrap();
                secure_session_salt
                    .extend_from_slice(&crate::crypto::hash(&message_bytes))
                    .unwrap();

                // const secureSessionSalt = Buffer.concat([
                //      identityProtectionKey, Crypto.hash([ sigma1Bytes, sigma2Bytes, sigma3Bytes ])]);
                // await server.createSecureSession(sessionId, nodeId, peerNodeId, peerSessionId, sharedSecret,
                //      secureSessionSalt, false, mrpParams?.idleRetransTimeoutMs, mrpParams?.activeRetransTimeoutMs);
                // await messenger.sendSuccess();
                // console.log(`Case: Paired succesfully with ${messenger.getChannelName()}`);

                let shared_secret_bytes = shared_secret.raw_secret_bytes();
                let shared_secret_bytes = shared_secret_bytes.as_slice();
                self.shared_secret = Some(shared_secret_bytes.try_into().unwrap());

                //self.enter_encrypted();

                let session_id = self.context.with_case_context(|c| c.future_session_id);
                let node_id = self.context.with_fabric(|f| f.node_id);

                ProtocolHandlerResponse::InitiateSecureSession(self.make_secure_session_parameters(
                    session_id,
                    &secure_session_salt,
                    node_id,
                    peer_node_id.unwrap(),
                ))
            }
            MessageType::Sigma2Resume => todo!(),
            MessageType::StatusReport => {
                log::info!("Got status report {:02x?}", payload);
                todo!()
            }
            _ => panic!(
                "Unknown or unexpected message type {:?}",
                payload_header.message_type
            ),
        }
    }

    fn encrypted(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use core::cell::RefCell;
    use std::{format, println};

    use critical_section::Mutex;
    use crypto_bigint::generic_array::GenericArray;
    use elliptic_curve::group::GroupEncoding;
    use p256::{ecdh::SharedSecret, AffinePoint};

    use crate::{
        case_messages::{TagBasedEcryptionData, TagBasedSignatureData},
        fabric::Fabric,
    };

    extern crate std;

    #[test]
    fn test_sigma1() {
        let payload = hex_literal::hex!("153001208681a088651b1803d3027e7994756aedb4c4bd56ca1f5e1c54cf6da4a104fffa25028830300320066ab9dc4e84686b9fb7850d4b8306e8c42189f39c919459a552cf27ad34004230044104ae6e458cf40ad53761ee90bc458aa577e6a1acf75410524551bb0bc4c708832c6525991ee2eed47df35ce2d83dad743bff6769ebbf731395d62453cb37303e0335052501881325022c011818");
        let noc = hex_literal::hex!("153001010124020137032414001826048012542826058015203b370624150124115a1824070124080130094104531a14e4c1b4cc7ac69aa5e403d5ccc3c5152c29fddedc29ac98ecff6c8f8695317446029cf3eb3e295ee18f0fd0ba9f06f7fa229138db0bc8d8c6f9875c9707370a3501280118240201360304020401183004149038f60c3542d5e610f29abc5f42ac09b07ee0d7300514e766069362d7e35b79687161644d222bdde93a6818300b40cbd9a06e77e9a7bcd19d02da0f2e50042f7d78201e8be26e793e995ca8f02f1094b34d0fd53b1f1458908d0d29183f2611e6132c6401d15dfff081d1021358ad18");
        let ipk = hex_literal::hex!("0c677d9b5ac585827b577470bd9bd516");
        let random =
            hex_literal::hex!("75d1443943a23371699bb017958a87e9ec6bbcad5f990aa3822a45bec7786489");
        let sharedSecret: [u8; 32] =
            hex_literal::hex!("08ec3182f7111854fd22fe527951527e4fe905d29a959f99013279cd9c9299f1");
        let public_key_bytes = hex_literal::hex!("04e2690445cc017a388853eaeca3a1ffd2712f6898e0bb523b8b496590804a39bf1555300bbd2a159e927b428397fb07a41e26c8cdf858ec62a310d0480d94eb64");
        let peerPubKey = hex_literal::hex!("04ae6e458cf40ad53761ee90bc458aa577e6a1acf75410524551bb0bc4c708832c6525991ee2eed47df35ce2d83dad743bff6769ebbf731395d62453cb37303e03");
        let fabricPubKey = hex_literal::hex!("04531a14e4c1b4cc7ac69aa5e403d5ccc3c5152c29fddedc29ac98ecff6c8f8695317446029cf3eb3e295ee18f0fd0ba9f06f7fa229138db0bc8d8c6f9875c9707");

        let mut sigma2_salt: heapless::Vec<u8, 256> = heapless::Vec::new();
        sigma2_salt.extend_from_slice(&ipk).unwrap();
        sigma2_salt.extend_from_slice(&random).unwrap();
        sigma2_salt.extend_from_slice(&public_key_bytes).unwrap();
        sigma2_salt
            .extend_from_slice(&crate::crypto::hash(&payload))
            .unwrap();

        assert_eq!(
            &sigma2_salt,
            &hex_literal::hex!("0c677d9b5ac585827b577470bd9bd51675d1443943a23371699bb017958a87e9ec6bbcad5f990aa3822a45bec778648904e2690445cc017a388853eaeca3a1ffd2712f6898e0bb523b8b496590804a39bf1555300bbd2a159e927b428397fb07a41e26c8cdf858ec62a310d0480d94eb64df506d7014c72ed4a18169954cf24a5cacf44fc7c13eb39906c06a50864f8106"),
        );

        let hkdf: hkdf::Hkdf<sha2::Sha256> = hkdf::Hkdf::new(Some(&sigma2_salt), &sharedSecret);
        let mut sigma2_key = [0u8; 16];
        hkdf.expand(b"Sigma2", &mut sigma2_key)
            .expect("16 is a valid length");

        assert_eq!(
            &sigma2_key,
            &hex_literal::hex!("7ed5e720195c511dc2d97535e262f935")
        );

        let signature_data = TagBasedSignatureData {
            new_op_cert: heapless::Vec::from_slice(&noc).unwrap(),
            intermediate_ca_cert: None,
            ecdh_public_key: heapless::Vec::from_slice(&public_key_bytes).unwrap(),
            peer_ecdh_public_key: heapless::Vec::from_slice(&peerPubKey).unwrap(),
        }
        .encode_tlv();

        assert_eq!(signature_data.to_slice(), &hex_literal::hex!("153001f1153001010124020137032414001826048012542826058015203b370624150124115a1824070124080130094104531a14e4c1b4cc7ac69aa5e403d5ccc3c5152c29fddedc29ac98ecff6c8f8695317446029cf3eb3e295ee18f0fd0ba9f06f7fa229138db0bc8d8c6f9875c9707370a3501280118240201360304020401183004149038f60c3542d5e610f29abc5f42ac09b07ee0d7300514e766069362d7e35b79687161644d222bdde93a6818300b40cbd9a06e77e9a7bcd19d02da0f2e50042f7d78201e8be26e793e995ca8f02f1094b34d0fd53b1f1458908d0d29183f2611e6132c6401d15dfff081d1021358ad1830034104e2690445cc017a388853eaeca3a1ffd2712f6898e0bb523b8b496590804a39bf1555300bbd2a159e927b428397fb07a41e26c8cdf858ec62a310d0480d94eb6430044104ae6e458cf40ad53761ee90bc458aa577e6a1acf75410524551bb0bc4c708832c6525991ee2eed47df35ce2d83dad743bff6769ebbf731395d62453cb37303e0318"));

        let signature = hex_literal::hex!("1736972364d84c4ae069f642f491256c6e74c86eda9f5ed4d89dfd7cadb68b67574f032afa2764fcc890e9218eaedcc484576d2d65e4df1ae22dd916f12ab59e");
        assert_eq!(
            true,
            crate::crypto::verify(&fabricPubKey, signature_data.to_slice(), &signature)
        );

        let resumption_id = hex_literal::hex!("8731f8cec507136df7558fca9360e9fc");
        let encrypted_data = TagBasedEcryptionData {
            new_op_cert: heapless::Vec::from_slice(&noc).unwrap(),
            intermediate_ca_cert: None,
            signature: heapless::Vec::from_slice(&signature).unwrap(),
            resumption_id: Some(heapless::Vec::from_slice(&resumption_id).unwrap()),
        }
        .encode_tlv();
        assert_eq!(encrypted_data.to_slice(), &hex_literal::hex!("153001f1153001010124020137032414001826048012542826058015203b370624150124115a1824070124080130094104531a14e4c1b4cc7ac69aa5e403d5ccc3c5152c29fddedc29ac98ecff6c8f8695317446029cf3eb3e295ee18f0fd0ba9f06f7fa229138db0bc8d8c6f9875c9707370a3501280118240201360304020401183004149038f60c3542d5e610f29abc5f42ac09b07ee0d7300514e766069362d7e35b79687161644d222bdde93a6818300b40cbd9a06e77e9a7bcd19d02da0f2e50042f7d78201e8be26e793e995ca8f02f1094b34d0fd53b1f1458908d0d29183f2611e6132c6401d15dfff081d1021358ad183003401736972364d84c4ae069f642f491256c6e74c86eda9f5ed4d89dfd7cadb68b67574f032afa2764fcc890e9218eaedcc484576d2d65e4df1ae22dd916f12ab59e3004108731f8cec507136df7558fca9360e9fc18"));

        let encrypted = crate::crypto::encrypt(
            &sigma2_key,
            encrypted_data.to_slice(),
            b"NCASE_Sigma2N",
            None,
        );
        assert_eq!(&encrypted, &hex_literal::hex!("7db57138c40bd8f37deb377764270e35143ec2cadfa73ef138d5ff3818ca3f003db767061051a19cb2cb1756ff214a855b6c32a07798c22756ff22338928928baa9ed8ab9484e3a662612616a95a7dbd11ac8d84ebe33b141366349452e47ebac98423140dffa764c83257c079c29a925f5a065ba98c491ae54289fc3d09d8bd8519e9f82dd51dfe4317e22b8481ada14462f01a1b837dc7af1000a3869bc1f9539d69cf73e0eb2377e35b5f9799ccb38b14dab2735edf37660a641669031820133122b5b62267b8b543e797977278b4bef14b6a820749ce66617251356ab8b759ccb3b3cdb376ec1862268aacb46145527f7940794fbc77c852a02bafb64e8e461e50349a342c34f493ac20abc7442ecf78531b4e07047af37dbe2e4746fb344169dd302f1ecc9339cb54a40b11957e2d395e4bcfb98a560247dffa5c22454febdb94b82c40838a279143a089b6ef8df76222ecdf4e04bcd6e6e222"));
    }
}

pub struct CaseContext {
    pub sigma1_bytes: Option<heapless::Vec<u8, 1024>>,
    pub sigma2_bytes: Option<heapless::Vec<u8, 1024>>,
    pub sigma3_bytes: Option<heapless::Vec<u8, 1024>>,
    pub shared_secret: Option<heapless::Vec<u8, 256>>,
    pub ecdh_public_key: Option<heapless::Vec<u8, 67>>,
    pub peer_ecdh_public_key: Option<heapless::Vec<u8, 67>>,
    pub future_session_id: u16,
}

impl CaseContext {
    pub fn new() -> CaseContext {
        CaseContext {
            sigma1_bytes: None,
            sigma2_bytes: None,
            sigma3_bytes: None,
            shared_secret: None,
            ecdh_public_key: None,
            peer_ecdh_public_key: None,
            future_session_id: 0,
        }
    }
}
