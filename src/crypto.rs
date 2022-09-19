use crate::buffer::Buffer;
use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, KeyInit},
    consts::{U13, U16},
    AeadInPlace, Ccm, Nonce,
};
use crypto_bigint::rand_core::RngCore;
use ecdsa::signature::Signature;

use elliptic_curve::ecdh::SharedSecret;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::{ecdh::EphemeralSecret, ecdsa::signature::Signer, NistP256, PublicKey};

pub type Aes128Ccm = Ccm<Aes128, U16, U13>;

use sha2::Digest;

pub fn hash(data: &[u8]) -> heapless::Vec<u8, 256> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    heapless::Vec::from_slice(&hash).unwrap()
}

pub fn encrypt(
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: Option<&[u8]>,
) -> heapless::Vec<u8, 1024> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128Ccm::new(&key);
    let nonce = Nonce::from_slice(nonce);

    let mut buffer: Buffer<1024> = Buffer::new_from_slice(data);

    let aad = match aad {
        Some(aad) => aad,
        None => b"",
    };

    cipher.encrypt_in_place(nonce, aad, &mut buffer).unwrap();
    heapless::Vec::from_slice(buffer.slice()).unwrap()
}

pub fn decrypt(
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: Option<&[u8]>,
) -> heapless::Vec<u8, 1024> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128Ccm::new(&key);
    let nonce = Nonce::from_slice(nonce);

    let mut buffer: Buffer<1024> = Buffer::new_from_slice(data);

    let aad = match aad {
        Some(aad) => aad,
        None => b"",
    };

    cipher.decrypt_in_place(nonce, aad, &mut buffer).unwrap();
    heapless::Vec::from_slice(buffer.slice()).unwrap()
}

pub fn sign(pk: &[u8], data: &[u8]) -> heapless::Vec<u8, 256> {
    let key = SigningKey::from_bytes(pk).unwrap();
    let sig = key.sign(data);

    let mut res = heapless::Vec::new();
    res.extend_from_slice(sig.as_ref()).unwrap();
    res
}

pub fn sign_der(pk: &[u8], data: &[u8]) -> heapless::Vec<u8, 256> {
    let key = SigningKey::from_bytes(pk).unwrap();
    let sig = key.sign(data).to_der();

    let mut res = heapless::Vec::new();
    res.extend_from_slice(sig.as_ref()).unwrap();
    res
}

pub fn verify(pk: &[u8], data: &[u8], signature: &[u8]) -> bool {
    use ecdsa::signature::Verifier;

    let key = VerifyingKey::from_sec1_bytes(pk);
    if let Err(_) = key {
        return false;
    }
    let key = key.unwrap();

    let sig = Signature::from_bytes(signature);
    if let Err(_) = sig {
        return false;
    }
    let sig = sig.unwrap();

    match key.verify(data, &sig) {
        Ok(()) => true,
        Err(_) => false,
    }
}

pub fn hkdf(secret: &[u8], salt: &[u8], info: &[u8], _length: usize) -> [u8; 48] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt[..]), &secret);
    let mut okm = [0u8; 48];
    hk.expand(&info, &mut okm)
        .expect("42 is a valid length for Sha256 to output");

    okm
}

pub fn ecdh(public_key: &[u8]) -> (EphemeralSecret, SharedSecret<NistP256>) {
    let secret = p256::ecdh::EphemeralSecret::random(NotRandom);
    let shared_secret = secret.diffie_hellman(&PublicKey::from_sec1_bytes(&public_key).unwrap());
    (secret, shared_secret)
}

// static createKeyPair(): KeyPair {
//     const ecdh = crypto.createECDH(EC_CURVE);
//     ecdh.generateKeys();
//     return { publicKey: ecdh.getPublicKey(), privateKey: ecdh.getPrivateKey() };
// }

// TODO pass the RNG here .... not this stuff!
pub struct NotRandom;

impl crypto_bigint::rand_core::CryptoRng for NotRandom {}

impl RngCore for NotRandom {
    fn next_u32(&mut self) -> u32 {
        42
    }

    fn next_u64(&mut self) -> u64 {
        23
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = 23;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), crypto_bigint::rand_core::Error> {
        for b in dest {
            *b = 23;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::{PublicKey, SecretKey};

    use crate::crypto::NotRandom;

    extern crate std;

    #[test]
    fn test_encrypt() {
        let key_2 = hex_literal::hex!("4e4c1353a133397f7a7557c1fbd9ca38");
        let encrypted_data_2 = hex_literal::hex!("cb50871ccd35d430b9d9f9f2a50c07f6b0e68ac78f671de670bc6622c3538b10184ac58e70475301edae3d45dd169bfad3a4367cb8eb821676b162");
        let plain_data_2 = hex_literal::hex!("0609523c01000fe399001528003601153501370024000024013e24020b1835012400001818181824ff0118");
        let nonce_2 = hex_literal::hex!("00ec8ceb000000000000000000");
        let additional_auth_data_2 = hex_literal::hex!("00c7a200ec8ceb00");

        let result = super::encrypt(
            &key_2,
            &plain_data_2,
            &nonce_2,
            Some(&additional_auth_data_2),
        );
        assert_eq!(result.as_slice(), &encrypted_data_2);

        let result = super::decrypt(
            &key_2,
            &encrypted_data_2,
            &nonce_2,
            Some(&additional_auth_data_2),
        );
        assert_eq!(&result.as_slice(), &plain_data_2);
    }

    #[test]
    fn test_decrypt() {
        let key = hex_literal::hex!("abf227feffea8c38e688ddcbffc459f1");
        let encrypted_data =
            hex_literal::hex!("c4527bd6965518e8382edbbd28f27f42492d0766124f9961a772");
        let plain_data = hex_literal::hex!("03104f3c0000e98ceb00");
        let nonce = hex_literal::hex!("000ce399000000000000000000");
        let additional_auth_data = hex_literal::hex!("00456a000ce39900");

        let result = super::decrypt(&key, &encrypted_data, &nonce, Some(&additional_auth_data));

        assert_eq!(&result.as_slice(), &plain_data);
    }

    #[test]
    fn test_sign() {
        let private_key =
            hex_literal::hex!("727F1005CBA47ED7822A9D930943621617CFD3B79D9AF528B801ECF9F1992204");
        let public_key = hex_literal::hex!("0462e2b6e1baff8d74a6fd8216c4cb67a3363a31e691492792e61aee610261481396725ef95e142686ba98f339b0ff65bc338bec7b9e8be0bdf3b2774982476220");
        let encrypted_data =
            hex_literal::hex!("c4527bd6965518e8382edbbd28f27f42492d0766124f9961a772");

        let result = super::sign(&private_key, &encrypted_data);
        assert!(super::verify(&public_key, &encrypted_data, &result));

        // TODO this is a bad test - should verify the signature at least
    }

    #[test]
    fn test_sign2() {
        let encrypted_data =
            hex_literal::hex!("c4527bd6965518e8382edbbd28f27f42492d0766124f9961a772");

        let secret_key = SecretKey::random(NotRandom);

        let private_key = secret_key.to_be_bytes();

        let result = super::sign(&private_key, &encrypted_data);
    }
}
