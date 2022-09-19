use elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;

use crate::der::{DerEncoder, DerValue};

const ORGANIZATION_NAME_ID: [u8; 3] = hex_literal::hex!("55040A");
const EC_PUBLIC_KEY_ID: [u8; 7] = hex_literal::hex!("2A8648CE3D0201");
const CURVE_P256_V1_ID: [u8; 8] = hex_literal::hex!("2A8648CE3D030107");
const ECDSA_WITH_SHA256_ID: [u8; 8] = hex_literal::hex!("2A8648CE3D040302");

pub fn create_certificate_signing_request(secret_key: SecretKey) -> heapless::Vec<u8, 1024> {
    let public_key_ep = secret_key.public_key().to_encoded_point(false);
    let public_key = public_key_ep.as_bytes();
    let private_key = secret_key.to_be_bytes();

    let mut organization = DerEncoder::new();
    organization.write(DerValue::ObjectId(&ORGANIZATION_NAME_ID));
    organization.write(DerValue::UTF8String("CSR"));

    let mut organization_content = DerEncoder::new();
    organization_content.write(DerValue::Object(organization.to_slice()));

    let mut subject_content = DerEncoder::new();
    subject_content.write(DerValue::Array(organization_content.to_slice()));

    let mut pk_type_contents = DerEncoder::new();
    pk_type_contents.write(DerValue::ObjectId(&EC_PUBLIC_KEY_ID));
    pk_type_contents.write(DerValue::ObjectId(&CURVE_P256_V1_ID));

    let mut pk_content = DerEncoder::new();
    pk_content.write(DerValue::Object(pk_type_contents.to_slice()));
    pk_content.write(DerValue::BitString(&public_key));

    let mut request_content = DerEncoder::new();
    request_content.write(DerValue::UsignedInt(0)); // version
    request_content.write(DerValue::Object(subject_content.to_slice()));
    request_content.write(DerValue::Object(pk_content.to_slice()));
    request_content.write(DerValue::EndMarker);

    let mut algorithm_content = DerEncoder::new();
    algorithm_content.write(DerValue::ObjectId(&ECDSA_WITH_SHA256_ID));

    let mut req_to_sign = DerEncoder::new();
    req_to_sign.write(DerValue::Object(request_content.to_slice()));
    let signature = crate::crypto::sign_der(&private_key, req_to_sign.to_slice());

    let mut cert_req_content = DerEncoder::new();
    cert_req_content.write(DerValue::Object(request_content.to_slice()));
    cert_req_content.write(DerValue::Object(algorithm_content.to_slice()));
    cert_req_content.write(DerValue::BitString(&signature));

    let mut cert_req = DerEncoder::new();
    cert_req.write(DerValue::Object(cert_req_content.to_slice()));

    cert_req.to_vec()
}
