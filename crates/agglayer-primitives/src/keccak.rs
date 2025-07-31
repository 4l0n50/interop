use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher as _, Keccak};

use crate::Digest;

#[cfg(target_os = "zkvm")]
/// The maximum number of hashes that can be computed
const MAX_HASHES: usize = 2 << 16;
#[cfg(target_os = "zkvm")]
/// The current hasher index within the hashers pool.
pub static mut CURRENT_HASHER_INDEX: usize = 0;
#[cfg(target_os = "zkvm")]
/// A pool of Keccak hashers to avoid allocation overhead.
pub static mut HASHERS_POOL: [Keccak; MAX_HASHES] = [const { Keccak::v256() }; MAX_HASHES];
#[cfg(target_os = "zkvm")]
/// A static output buffer for the Keccak hasher.
/// This is used to avoid allocations in the zkvm environment.
pub static mut OUTPUT: [u8; 32] = [0u8; 32];

/// Hashes the input data using a Keccak hasher with a 256-bit security level.
#[inline]
pub fn keccak256(data: &[u8]) -> Digest {
    let mut hasher = Keccak::v256();
    hasher.update(data);

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Digest(output)
}

/// Hashes the input items using a Keccak hasher with a 256-bit security level.
/// Safety: This function should only be called with fixed-size items to avoid
/// collisions.
#[inline]
#[cfg(not(target_os = "zkvm"))]
pub fn keccak256_combine<I, T>(items: I) -> Digest
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut hasher = Keccak::v256();
    for data in items {
        hasher.update(data.as_ref());
    }

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Digest(output)
}
#[cfg(target_os = "zkvm")]
pub fn keccak256_combine<I, T>(items: I) -> Digest
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut hasher = unsafe { &mut HASHERS_POOL[CURRENT_HASHER_INDEX] };
    unsafe {
        CURRENT_HASHER_INDEX += 1;
    }

    for data in items {
        hasher.update(data.as_ref());
    }
    hasher.finalize_ref(unsafe { &mut OUTPUT });
    Digest(unsafe { OUTPUT })
}

/// A hasher used in constructing a [`super::LocalExitTree`].
pub trait Hasher {
    type Digest;

    /// Hashes two digests into one.
    fn merge(left: &Self::Digest, right: &Self::Digest) -> Self::Digest;
}

/// A Keccak hasher with a 256-bit security level.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keccak256Hasher;

impl Hasher for Keccak256Hasher {
    type Digest = Digest;

    #[inline]
    fn merge(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        keccak256_combine([left.as_ref(), right.as_ref()])
    }
}
