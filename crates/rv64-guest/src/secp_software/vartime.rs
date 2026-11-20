//! libsecp256k1 verification and recovery for public Ethereum signatures.

use core::mem::MaybeUninit;
use k256::ecdsa::Signature;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature as CompactSignature};
use secp256k1::ffi;
use secp256k1::ffi::{recovery::secp256k1_ecdsa_recover, CPtr};
use secp256k1::PublicKey;

pub(super) fn recover(signature: &Signature, prehash: &[u8; 32], recid: u8) -> Option<[u8; 65]> {
    let recid = RecoveryId::try_from(i32::from(recid)).ok()?;
    let signature = RecoverableSignature::from_compact(&signature.to_bytes(), recid).ok()?;
    let mut key = MaybeUninit::<ffi::PublicKey>::uninit();

    // SAFETY: libsecp256k1 supports its immutable static context for public-key
    // recovery. The inputs are a parsed signature and a 32-byte hash. The FFI
    // initializes the opaque public key on success.
    let key = unsafe {
        if secp256k1_ecdsa_recover(
            ffi::secp256k1_context_no_precomp,
            key.as_mut_ptr(),
            signature.as_c_ptr(),
            prehash.as_ptr(),
        ) != 1
        {
            return None;
        }
        PublicKey::from(key.assume_init())
    };
    Some(key.serialize_uncompressed())
}

pub(super) fn verify(key: &[u8; 65], prehash: &[u8; 32], signature: &Signature) -> bool {
    // libsecp256k1 also parses hybrid keys. The portable sender path takes
    // a 65-byte SEC1 uncompressed key, whose tag is 0x04.
    if key[0] != 0x04 {
        return false;
    }
    let Ok(key) = PublicKey::from_byte_array_uncompressed(key) else {
        return false;
    };
    let Ok(signature) = CompactSignature::from_compact(&signature.to_bytes()) else {
        return false;
    };

    // SAFETY: libsecp256k1 supports its immutable static context for signature
    // verification. The key and signature were initialized by its parsers and
    // the hash has the 32 bytes the FFI reads.
    unsafe {
        ffi::secp256k1_ecdsa_verify(
            ffi::secp256k1_context_no_precomp,
            signature.as_c_ptr(),
            prehash.as_ptr(),
            key.as_c_ptr(),
        ) == 1
    }
}
