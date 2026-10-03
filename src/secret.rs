//! Opaque secret containers.
//!
//! `Secret` zeroizes its bytes on drop and deliberately implements none of
//! `Debug`, `Display`, `Clone`, or `Serialize`, so a secret can never be
//! logged, copied, or serialized by accident. The only read path is
//! [`Secret::expose`], which must be used at a crypto/IO boundary and whose
//! result must never be stored.

use zeroize::Zeroize;

pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }

    pub fn from_str(s: &str) -> Self {
        Secret(s.as_bytes().to_vec())
    }

    /// Controlled exposure. Use at the boundary, then drop.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
