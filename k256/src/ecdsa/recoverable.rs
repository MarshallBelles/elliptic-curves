use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};
use ecdsa_core::{signature::Signature as _, Error};

use crate::{
    ecdsa::{
        signature::{digest::Digest, DigestVerifier},
        VerifyingKey,
    },
    elliptic_curve::{consts::U32, ops::Invert, subtle::Choice, DecompressPoint},
    lincomb, AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar,
};

pub const SIZE: usize = 65;

#[derive(Copy, Clone)]
pub struct Signature {
    bytes: [u8; SIZE],
}

impl Signature {
    pub fn new(signature: &super::Signature, recovery_id: Id) -> Result<Self, Error> {
        let mut bytes = [0u8; SIZE];
        bytes[..64].copy_from_slice(signature.as_ref());
        bytes[64] = recovery_id.0;
        Ok(Self { bytes })
    }

    pub fn recovery_id(self) -> Id {
        self.bytes[64].try_into().expect("invalid recovery ID")
    }

    pub fn from_digest_trial_recovery<D>(
        public_key: &VerifyingKey,
        digest: D,
        signature: &super::Signature,
    ) -> Result<Self, Error>
    where
        D: Clone + Digest<OutputSize = U32>,
    {
        let signature = signature.normalize_s().unwrap_or(*signature);

        for recovery_id in 0..=1 {
            if let Ok(recoverable_signature) = Signature::new(&signature, Id(recovery_id)) {
                if let Ok(recovered_key) =
                    recoverable_signature.recover_verify_key_from_digest(digest.clone())
                {
                    if public_key == &recovered_key
                        && public_key.verify_digest(digest.clone(), &signature).is_ok()
                    {
                        return Ok(recoverable_signature);
                    }
                }
            }
        }

        Err(Error::new())
    }

    pub fn recover_verify_key(&self, msg: &[u8]) -> Result<VerifyingKey, Error> {
        self.recover_verify_key_from_digest(Keccak256::new().chain(msg))
    }

    pub fn recover_verify_key_from_digest<D>(&self, msg_digest: D) -> Result<VerifyingKey, Error>
    where
        D: Digest<OutputSize = U32>,
    {
        self.recover_verify_key_from_digest_bytes(&msg_digest.finalize())
    }

    pub fn recover_verify_key_from_digest_bytes(
        &self,
        digest_bytes: &FieldBytes,
    ) -> Result<VerifyingKey, Error> {
        let r = self.r();
        let s = self.s();
        let z = Scalar::from_bytes_reduced(digest_bytes);
        let R = AffinePoint::decompress(&r.to_bytes(), self.recovery_id().is_y_odd());

        if R.is_some().into() {
            let R = ProjectivePoint::from(R.unwrap());
            let r_inv = r.invert().unwrap();
            let u1 = -(r_inv * z);
            let u2 = r_inv * *s;
            let pk = lincomb(&ProjectivePoint::generator(), &u1, &R, &u2).to_affine();

            Ok(VerifyingKey::from(&pk))
        } else {
            Err(Error::new())
        }
    }

    pub fn r(&self) -> NonZeroScalar {
        NonZeroScalar::try_from(&self.bytes[..32])
            .expect("r-component ensured valid in constructor")
    }

    pub fn s(&self) -> NonZeroScalar {
        NonZeroScalar::try_from(&self.bytes[32..64])
            .expect("s-component ensured valid in constructor")
    }
}

impl ecdsa_core::signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..]
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoverableSignature {{ bytes: {:?}) }}", self.as_ref())
    }
}

impl Eq for Signature {}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE {
            return Err(Error::new());
        }

        let signature = super::Signature::try_from(&bytes[..64])?;
        let recovery_id = Id::try_from(bytes[64])?;
        Self::new(&signature, recovery_id)
    }
}

impl From<Signature> for super::Signature {
    fn from(sig: Signature) -> Self {
        Self::from_bytes(&sig.bytes[..64]).unwrap()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Id(pub(super) u8);

impl Id {
    /// Create a new [`Id`] from the given byte value
    pub fn new(byte: u8) -> Result<Self, Error> {
        match byte {
            0 | 1 => Ok(Self(byte)),
            _ => Err(Error::new()),
        }
    }

    /// Is `y` odd?
    fn is_y_odd(self) -> Choice {
        self.0.into()
    }
}

impl TryFrom<u8> for Id {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Self, Error> {
        Self::new(byte)
    }
}

impl From<Id> for u8 {
    fn from(recovery_id: Id) -> u8 {
        recovery_id.0
    }
}

#[cfg(all(test, feature = "ecdsa", feature = "sha256"))]
mod tests {
    use super::Signature;
    use crate::EncodedPoint;
    use core::convert::TryFrom;
    use hex_literal::hex;
    use sha3::{Digest, Sha3_256};

    /// Signature recovery test vectors
    struct TestVector {
        pk: [u8; 33],
        sig: [u8; 65],
        msg: &'static [u8],
    }

    const VECTORS: &[TestVector] = &[
        // Recovery ID 0
        TestVector {
            pk: hex!("021a7a569e91dbf60581509c7fc946d1003b60c7dee85299538db6353538d59574"),
            sig: hex!(
                "ce53abb3721bafc561408ce8ff99c909f7f0b18a2f788649d6470162ab1aa03239
                 71edc523a6d6453f3fb6128d318d9db1a5ff3386feb1047d9816e780039d5200"
            ),
            msg: b"example message",
        },
        // Recovery ID 1
        TestVector {
            pk: hex!("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"),
            sig: hex!(
                "46c05b6368a44b8810d79859441d819b8e7cdc8bfd371e35c53196f4bcacdb5135
                 c7facce2a97b95eacba8a586d87b7958aaf8368ab29cee481f76e871dbd9cb01"
            ),
            msg: b"example message",
        },
    ];

    #[test]
    fn public_key_recovery() {
        for vector in VECTORS {
            let sig = Signature::try_from(&vector.sig[..]).unwrap();
            let prehash = Sha3_256::new().chain(vector.msg);
            let pk = sig.recover_verify_key_from_digest(prehash).unwrap();
            assert_eq!(&vector.pk[..], EncodedPoint::from(&pk).as_bytes());
        }
    }
}
