use crypto_bigint::Encoding;
use crypto_bigint::U384;
use ecdsa::elliptic_curve::PrimeField;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hmac::Mac;
use p256::EncodedPoint;
use sha2::Digest;

pub struct MatterSpake {
    context: heapless::Vec<u8, 64>,
    random: heapless::Vec<u8, 64>,
    w0: heapless::Vec<u8, 64>,
    w1: heapless::Vec<u8, 64>,
}

impl MatterSpake {
    pub fn new(context: &[u8], random: &[u8], w0: &[u8], w1: &[u8]) -> MatterSpake {
        MatterSpake {
            context: heapless::Vec::from_slice(context).unwrap(),
            random: heapless::Vec::from_slice(random).unwrap(),
            w0: heapless::Vec::from_slice(w0).unwrap(),
            w1: heapless::Vec::from_slice(w1).unwrap(),
        }
    }

    pub fn create(
        context: &[u8],
        pin: u32,
        salt: &[u8; 32],
        iteration: u32,
        random: &[u8],
    ) -> MatterSpake {
        let pin_bytes: [u8; 4] = pin.to_le_bytes().try_into().unwrap();

        let mut ws = [0u8; 80];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&pin_bytes, salt, iteration, &mut ws);

        let w0 = &ws[0..40];
        let w1 = &ws[40..80];

        let operand: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut expanded = [0u8; 384 / 8];
        expanded[16..].copy_from_slice(&operand);
        let big_operand = U384::from_be_slice(&expanded);

        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(&w0);
        let big_w0 = U384::from_be_slice(&expanded);

        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(&w1);
        let big_w1 = U384::from_be_slice(&expanded);

        let w0_res = big_w0.reduce(&big_operand).unwrap();
        let w1_res = big_w1.reduce(&big_operand).unwrap();

        let mut w0_out = [0u8; 32];
        w0_out.copy_from_slice(&w0_res.to_be_bytes()[16..]);

        let mut w1_out = [0u8; 32];
        w1_out.copy_from_slice(&w1_res.to_be_bytes()[16..]);

        MatterSpake::new(context, &random, &w0_out, &w1_out)
    }

    pub fn compute_x(&self) -> heapless::Vec<u8, 256> {
        let m = p256::AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&hex_literal::hex!(
                "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
            ))
            .unwrap(),
        )
        .unwrap();
        let g = p256::AffinePoint::GENERATOR;

        let random_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.random),
        )
        .unwrap();
        let w0_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.w0),
        )
        .unwrap();
        let a = g * random_s + m * w0_s;

        heapless::Vec::from_slice(&a.to_encoded_point(false).as_bytes()).unwrap()
    }

    pub fn compute_y(&self) -> heapless::Vec<u8, 256> {
        let n = p256::AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&hex_literal::hex!(
                "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
            ))
            .unwrap(),
        )
        .unwrap();
        let g = p256::AffinePoint::GENERATOR;

        let random_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.random),
        )
        .unwrap();
        let w0_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.w0),
        )
        .unwrap();
        let a = g * random_s + n * w0_s;

        heapless::Vec::from_slice(&a.to_encoded_point(false).as_bytes()).unwrap()
    }

    pub fn compute_secret_and_verifiers_from_y(
        &self,
        x: &[u8],
        y: &[u8],
    ) -> (
        heapless::Vec<u8, 256>,
        heapless::Vec<u8, 256>,
        heapless::Vec<u8, 256>,
    ) {
        let n = p256::ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&hex_literal::hex!(
                "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
            ))
            .unwrap(),
        )
        .unwrap();

        let y_point =
            p256::ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&y).unwrap())
                .unwrap();

        let w0_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.w0),
        )
        .unwrap();

        let y_nwo = y_point + -(n * w0_s);

        let random_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.random),
        )
        .unwrap();
        let z = y_nwo * random_s;

        let w1_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.w1),
        )
        .unwrap();
        let v = y_nwo * w1_s;

        let z_ep = z.to_encoded_point(false);
        let z_bytes = z_ep.as_bytes();
        let v_ep = v.to_encoded_point(false);
        let v_bytes = v_ep.as_bytes();

        self.compute_secret_and_verifiers(x, y, &z_bytes, &v_bytes)
    }

    pub fn compute_secret_and_verifiers_from_x(
        &self,
        x: &[u8],
        y: &[u8],
    ) -> (
        heapless::Vec<u8, 256>,
        heapless::Vec<u8, 256>,
        heapless::Vec<u8, 256>,
    ) {
        let m = p256::ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&hex_literal::hex!(
                "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
            ))
            .unwrap(),
        )
        .unwrap();

        let x_point =
            p256::ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&x).unwrap())
                .unwrap();

        let w0_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.w0),
        )
        .unwrap();

        let w1_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.w1),
        )
        .unwrap();

        let random_s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&self.random),
        )
        .unwrap();

        let z = (x_point + -(m * w0_s)) * random_s;

        let g = p256::AffinePoint::GENERATOR;

        let v = g * w1_s * random_s;

        let z_ep = z.to_encoded_point(false);
        let z_bytes = z_ep.as_bytes();
        let v_ep = v.to_encoded_point(false);
        let v_bytes = v_ep.as_bytes();

        self.compute_secret_and_verifiers(x, y, &z_bytes, &v_bytes)
    }

    fn compute_secret_and_verifiers(
        &self,
        x: &[u8],
        y: &[u8],
        z: &[u8],
        v: &[u8],
    ) -> (
        heapless::Vec<u8, 256>,
        heapless::Vec<u8, 256>,
        heapless::Vec<u8, 256>,
    ) {
        let tt_hash = self.compute_transcript_hash(x, y, z, v);

        let ka = &tt_hash.as_slice()[0..16];
        let ke = &tt_hash.as_slice()[16..32];

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&[]), &ka);
        let mut okm = [0u8; 32];
        hk.expand(b"ConfirmationKeys", &mut okm).unwrap();

        let kca = &okm[0..16];
        let kcb = &okm[16..32];

        type HmacSha256 = hmac::Hmac<sha2::Sha256>;

        let mut hmac_a = HmacSha256::new_from_slice(kca).unwrap();
        hmac_a.update(y);
        let hay = hmac_a.finalize().into_bytes();

        let mut hmac_b = HmacSha256::new_from_slice(kcb).unwrap();
        hmac_b.update(x);
        let hbx = hmac_b.finalize().into_bytes();

        (
            heapless::Vec::from_slice(ke).unwrap(),
            heapless::Vec::from_slice(&hay).unwrap(),
            heapless::Vec::from_slice(&hbx).unwrap(),
        )
    }

    fn compute_transcript_hash(
        &self,
        x: &[u8],
        y: &[u8],
        z: &[u8],
        v: &[u8],
    ) -> heapless::Vec<u8, 256> {
        let m = p256::AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&hex_literal::hex!(
                "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
            ))
            .unwrap(),
        )
        .unwrap();

        let n = p256::AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&hex_literal::hex!(
                "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
            ))
            .unwrap(),
        )
        .unwrap();

        let mut tt = heapless::Vec::new();

        add_to_context(&mut tt, &self.context);
        add_to_context(&mut tt, b"");
        add_to_context(&mut tt, b"");
        add_to_context(&mut tt, m.to_encoded_point(false).as_bytes());
        add_to_context(&mut tt, n.to_encoded_point(false).as_bytes());
        add_to_context(&mut tt, x);
        add_to_context(&mut tt, y);
        add_to_context(&mut tt, z);
        add_to_context(&mut tt, v);
        add_to_context(&mut tt, &self.w0);

        let mut hasher = sha2::Sha256::new();
        hasher.update(tt.as_slice());
        let result = hasher.finalize();

        heapless::Vec::from_slice(&result[..]).unwrap()
    }
}

fn add_to_context(spake_context: &mut heapless::Vec<u8, 1024>, data: &[u8]) {
    spake_context
        .extend_from_slice(&(data.len() as u64).to_le_bytes())
        .unwrap();
    spake_context.extend_from_slice(data).unwrap();
}

#[cfg(test)]
#[allow(unused_imports)] // Rust Analyzer complains without reason!
mod test {
    use core::ops::Mul;
    use std::println;

    use ecdsa::elliptic_curve::PrimeField;
    use elliptic_curve::{
        group::{prime::PrimeCurveAffine, GroupEncoding},
        sec1::{FromEncodedPoint, ToCompactEncodedPoint, ToEncodedPoint},
        AffineArithmetic,
    };
    use p256::{AffinePoint, EncodedPoint};

    extern crate std;

    #[allow(non_snake_case)]
    #[test]
    fn test() {
        let context = b"SPAKE2+-P256-SHA256-HKDF draft-01";
        let w0 =
            hex_literal::hex!("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c");
        let w1 =
            hex_literal::hex!("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512");
        let x =
            hex_literal::hex!("5b478619804f4938d361fbba3a20648725222f0a54cc4c876139efe7d9a21786");
        let y =
            hex_literal::hex!("766770dad8c8eecba936823c0aed044b8c3c4f7655e8beec44a15dcbcaf78e5e");
        let X = hex_literal::hex!("04a6db23d001723fb01fcfc9d08746c3c2a0a3feff8635d29cad2853e7358623425cf39712e928054561ba71e2dc11f300f1760e71eb177021a8f85e78689071cd");
        let Y = hex_literal::hex!("04390d29bf185c3abf99f150ae7c13388c82b6be0c07b1b8d90d26853e84374bbdc82becdb978ca3792f472424106a2578012752c11938fcf60a41df75ff7cf947");
        let Ke = hex_literal::hex!("ea3276d68334576097e04b19ee5a3a8b");
        let hAY =
            hex_literal::hex!("71d9412779b6c45a2c615c9df3f1fd93dc0aaf63104da8ece4aa1b5a3a415fea");
        let hBX =
            hex_literal::hex!("095dc0400355cc233fde7437811815b3c1524aae80fd4e6810cf531cf11d20e3");

        let spake2p_initiator = super::MatterSpake::new(context, &x, &w0, &w1);
        let spake2p_receiver = super::MatterSpake::new(context, &y, &w0, &w1);

        // generates X
        let res = spake2p_initiator.compute_x();
        println!("X = {:02x?}", &res);
        assert_eq!(&X[..], &res[..]);

        // generates Y
        let res = spake2p_receiver.compute_y();
        println!("Y = {:02x?}", &res);
        assert_eq!(&Y[..], &res[..]);

        // generates shared secret and key confirmation for the initiator
        let result = spake2p_initiator.compute_secret_and_verifiers_from_y(&X, &Y);
        assert_eq!(&result.0, &Ke[..]);
        assert_eq!(&result.1, &hAY[..]);
        assert_eq!(&result.2, &hBX[..]);

        // generates shared secret and key confirmation for the receiver
        let result = spake2p_receiver.compute_secret_and_verifiers_from_x(&X, &Y);
        assert_eq!(&result.0, &Ke[..]);
        assert_eq!(&result.1, &hAY[..]);
        assert_eq!(&result.2, &hBX[..]);
    }

    #[test]
    fn generate_ws0_from_pin() {
        let random = [
            71, 21, 164, 6, 198, 176, 73, 106, 213, 32, 57, 227, 71, 219, 133, 40, 203, 105, 161,
            203, 47, 206, 111, 35, 24, 85, 42, 230, 94, 16, 58, 202,
        ];

        // Test data captured from https://github.com/project-chip/connectedhomeip/
        let pin = 20202021;
        let salt =
            hex_literal::hex!("438df2ea5143215c4ec5f1bbf7a4d9b1374f62320f2c88e25cc18ff5e5d1bbf6");
        let iteration = 1000;

        let spake2p = super::MatterSpake::create(&[], pin, &salt, iteration, &random);
        let result = spake2p.w0;

        assert_eq!(
            result,
            hex_literal::hex!("987aede3f3f32756971b905820b0bbdad2a6e236838a865b043e64878b5db6d0")
        );
    }

    #[test]
    fn generate_hash() {
        // Test data captured from https://github.com/project-chip/connectedhomeip/
        let mut to_hash: heapless::Vec<u8, 256> = heapless::Vec::new();

        // "CHIP PAKE V1 Commissioning"
        to_hash
            .extend_from_slice(&hex_literal::hex!(
                "434849502050414b4520563120436f6d6d697373696f6e696e67"
            ))
            .ok();
        // PbkdfParamRequest bytes
        to_hash.extend_from_slice(&hex_literal::hex!("15300120b2901e92036f7bca007a3a1bf24bd71f18772105e83479c92b7a8af35e8182742502498d240300280435052501881325022c011818")).ok();
        // PbkdfParamResponse bytes
        to_hash.extend_from_slice(&hex_literal::hex!("15300120b2901e92036f7bca007a3a1bf24bd71f18772105e83479c92b7a8af35e81827430022008070f685f2077779b824adf91e4bab6253b9d1a3c0f6615c6d447780f0feef325039c8d35042501e803300220163f8501fbbc0e6a8f69a9b999d038ca388ecffccc18fe259c4253f26e494dda1835052501881325022c011818")).ok();
        let result = crate::crypto::hash(&to_hash);

        assert_eq!(
            &result,
            &hex_literal::hex!("c49718b0275b6f81fd6a081f6c34c5833382b75b3bd997895d13a51c71a02855")
        );
    }
}
