//! A pure-Rust implementation of group operations on secp256k1.

pub(crate) mod affine;
mod field;
mod mul;
pub(crate) mod projective;
pub(crate) mod scalar;

#[cfg(test)]
mod dev;

pub use field::FieldElement;
pub use mul::lincomb;

use affine::AffinePoint;
use projective::ProjectivePoint;
use scalar::Scalar;

const CURVE_EQUATION_B_SINGLE: u32 = 7u32;

#[rustfmt::skip]
pub(crate) const CURVE_EQUATION_B: FieldElement = FieldElement::from_bytes_unchecked(&[
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, CURVE_EQUATION_B_SINGLE as u8,
]);

#[cfg(test)]
mod tests {
    use super::CURVE_EQUATION_B;
    use hex_literal::hex;

    const CURVE_EQUATION_B_BYTES: [u8; 32] =
        hex!("0000000000000000000000000000000000000000000000000000000000000007");

    #[test]
    fn verify_constants() {
        assert_eq!(CURVE_EQUATION_B.to_bytes(), CURVE_EQUATION_B_BYTES.into());
    }

    #[test]
    fn generate_secret_key() {
        use crate::SecretKey;
        use elliptic_curve_flow::rand_core::OsRng;
        let key = SecretKey::random(&mut OsRng);

        // Sanity check
        assert!(!key.to_be_bytes().iter().all(|b| *b == 0))
    }
}
