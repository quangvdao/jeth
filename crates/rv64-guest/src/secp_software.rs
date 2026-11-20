#[cfg(target_arch = "riscv64")]
use alloc::sync::Arc;
#[cfg(target_arch = "riscv64")]
use alloy_consensus::crypto::install_default_provider;
use alloy_consensus::crypto::{CryptoProvider, RecoveryError};
use alloy_primitives::{keccak256, Address, B256};
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey},
    elliptic_curve::{
        bigint::CheckedAdd,
        ops::{Invert, LinearCombination, Reduce},
        point::DecompressPoint,
        Curve, FieldBytesEncoding, PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, Secp256k1, U256,
};
#[cfg(target_arch = "riscv64")]
use revm_precompile::install_crypto;
use revm_precompile::{Crypto, PrecompileHalt};

#[derive(Debug)]
struct SoftwareSecp;

#[cfg(target_arch = "riscv64")]
pub(crate) fn install() {
    install_default_provider(Arc::new(SoftwareSecp)).expect("install Alloy crypto provider");
    assert!(install_crypto(SoftwareSecp), "install REVM crypto provider");
}

impl CryptoProvider for SoftwareSecp {
    fn recover_signer_unchecked(
        &self,
        signature: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let (recid, compact) = signature.split_last().ok_or_else(RecoveryError::new)?;
        let key = recover_key(compact, msg, *recid).ok_or_else(RecoveryError::new)?;
        Ok(Address::from_word(hash_key(&key)))
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        key: &[u8; 65],
        signature: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let vk = VerifyingKey::from_sec1_bytes(key).map_err(|_| RecoveryError::new())?;
        let sig = Signature::from_slice(signature).map_err(|_| RecoveryError::new())?;
        let sig = sig.normalize_s().unwrap_or(sig);
        vk.verify_prehash(msg, &sig)
            .map_err(|_| RecoveryError::new())?;
        let encoded = vk.to_encoded_point(false);
        Ok(Address::from_word(keccak256(&encoded.as_bytes()[1..])))
    }
}

impl Crypto for SoftwareSecp {
    fn secp256k1_ecrecover(
        &self,
        signature: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let key =
            recover_key(signature, msg, recid).ok_or(PrecompileHalt::Secp256k1RecoverFailed)?;
        let mut hash = hash_key(&key);
        hash[..12].fill(0);
        Ok(hash.0)
    }
}

fn hash_key(key: &[u8; 65]) -> B256 {
    keccak256(&key[1..])
}

fn recover_key(compact: &[u8], msg: &[u8; 32], mut recid: u8) -> Option<[u8; 65]> {
    let mut signature = Signature::from_slice(compact).ok()?;
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recid ^= 1;
    }

    let recovery_id = RecoveryId::from_byte(recid)?;
    let vk = recover_normalized(msg, &signature, recovery_id)?;
    vk.to_encoded_point(false).as_bytes().try_into().ok()
}

fn recover_normalized(
    msg: &[u8; 32],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> Option<VerifyingKey> {
    // Matches ecdsa 0.16.9 recovery for fixed-length prehashes and normalized s.
    // For a nonidentity Q, verification reconstructs R since s is nonzero
    // and rQ = sR - zG. R was decompressed with x = r or x = r + n.
    let (r, s) = signature.split_scalars();
    let z = <Scalar as Reduce<U256>>::reduce_bytes(msg.into());
    let mut x = r.to_repr();
    if recovery_id.is_x_reduced() {
        let restored = <U256 as FieldBytesEncoding<Secp256k1>>::decode_field_bytes(&x)
            .checked_add(&Secp256k1::ORDER);
        x = FieldBytesEncoding::<Secp256k1>::encode_field_bytes(&Option::<U256>::from(restored)?);
    }
    let r_point = Option::<AffinePoint>::from(AffinePoint::decompress(
        &x,
        u8::from(recovery_id.is_y_odd()).into(),
    ))?;
    let r_inv = *Invert::invert(&r);
    let key = ProjectivePoint::lincomb(
        &ProjectivePoint::GENERATOR,
        &-(r_inv * z),
        &r_point.into(),
        &(r_inv * *s),
    );
    VerifyingKey::from_affine(key.into()).ok()
}

// The vendored EIP-7702 hook expects the same padded address as ECRECOVER.
#[cfg(target_arch = "riscv64")]
#[no_mangle]
unsafe extern "C" fn jeth_ecrecover_prehash(
    sig: *const [u8; 64],
    recid: u8,
    msg: *const [u8; 32],
    out: *mut [u8; 32],
) -> u8 {
    // SAFETY: the only caller constructs separate, live arrays of these lengths.
    match SoftwareSecp.secp256k1_ecrecover(unsafe { &*sig }, recid, unsafe { &*msg }) {
        Ok(address) => {
            // SAFETY: the caller supplies a writable 32-byte output array.
            unsafe { out.write(address) };
            1
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{
        ecdsa::SigningKey,
        elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    };

    fn compact(r: [u8; 32], s: [u8; 32]) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&r);
        bytes[32..].copy_from_slice(&s);
        bytes
    }

    fn scalar(value: u8) -> [u8; 32] {
        let mut result = [0; 32];
        result[31] = value;
        result
    }

    #[test]
    fn software_secp_recovers_and_verifies_existing_signatures() {
        let signer = SigningKey::from_slice(&scalar(31)).unwrap();
        let public = signer.verifying_key().to_encoded_point(false);
        let public: &[u8; 65] = public.as_bytes().try_into().unwrap();
        let msg = [23; 32];
        let (signature, id) = signer.sign_prehash_recoverable(&msg).unwrap();
        let id = id.to_byte();
        let (r, s) = signature.split_scalars();
        let low: [u8; 64] = signature.to_bytes().into();
        let high = compact(r.to_repr().into(), (-*s).to_bytes().into());
        assert_eq!(recover_key(&low, &msg, id).as_ref(), Some(public));
        assert_eq!(recover_key(&high, &msg, id ^ 1).as_ref(), Some(public));

        let address = Address::from_word(hash_key(public));
        for signature in [low, high] {
            assert_eq!(
                SoftwareSecp
                    .verify_and_compute_signer_unchecked(public, &signature, &msg)
                    .unwrap(),
                address
            );
            assert!(SoftwareSecp
                .verify_and_compute_signer_unchecked(public, &signature, &[24; 32])
                .is_err());
            let mut hybrid = *public;
            hybrid[0] = 6 + (public[64] & 1);
            assert!(SoftwareSecp
                .verify_and_compute_signer_unchecked(&hybrid, &signature, &msg)
                .is_err());
        }
    }

    #[test]
    fn software_secp_keeps_recovery_edges() {
        let msg = scalar(1);
        for id in [2, 3] {
            // x = n + 2 admits two curve points, one for each recovery parity.
            let bytes = compact(scalar(2), scalar(1));
            let signature = Signature::from_slice(&bytes).unwrap();
            let expected = VerifyingKey::recover_from_prehash(
                &msg,
                &signature,
                RecoveryId::from_byte(id).unwrap(),
            )
            .unwrap()
            .to_encoded_point(false);
            assert_eq!(
                recover_key(&bytes, &msg, id).unwrap().as_slice(),
                expected.as_bytes()
            );
        }

        let generator = AffinePoint::GENERATOR.to_encoded_point(false);
        let x = generator.x().unwrap();
        // With R=G, s=z=1, the candidate key is the identity.
        assert!(recover_key(&compact((*x).into(), scalar(1)), &msg, 0).is_none());
        assert!(recover_key(&compact(scalar(0), scalar(1)), &msg, 0).is_none());
        assert!(recover_key(&compact(scalar(2), scalar(0)), &msg, 0).is_none());
        assert!(recover_key(&compact([0xff; 32], scalar(1)), &msg, 0).is_none());
        // x = n + 1 does not decompress.
        assert!(recover_key(&compact(scalar(1), scalar(1)), &msg, 2).is_none());
        // This canonical r would overflow when restoring x = r + n.
        assert!(recover_key(&compact([0x80; 32], scalar(1)), &msg, 2).is_none());
    }
}
