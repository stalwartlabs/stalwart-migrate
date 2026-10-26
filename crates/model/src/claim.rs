/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt,
    hash::{BuildHasher, RandomState},
    time::{SystemTime, UNIX_EPOCH},
};

const CLAIM_ID_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimId([u8; CLAIM_ID_LEN]);

impl ClaimId {
    pub const LEN: usize = CLAIM_ID_LEN;

    pub const fn from_bytes(bytes: [u8; CLAIM_ID_LEN]) -> Self {
        ClaimId(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CLAIM_ID_LEN] {
        &self.0
    }

    pub fn random() -> Self {
        let hasher = RandomState::new();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let mut bytes = [0u8; CLAIM_ID_LEN];
        for (salt, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            *chunk = hasher
                .hash_one((nanos, std::process::id(), salt))
                .to_le_bytes();
        }
        ClaimId(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(ClaimId)
    }

    pub fn parse_hex(value: &str) -> Option<Self> {
        let value = value.as_bytes();
        if value.len() != CLAIM_ID_LEN * 2 {
            return None;
        }
        let mut bytes = [0u8; CLAIM_ID_LEN];
        for (byte, [high, low]) in bytes.iter_mut().zip(value.as_chunks::<2>().0) {
            *byte = (hex_digit(*high)? << 4) | hex_digit(*low)?;
        }
        Some(ClaimId(bytes))
    }
}

const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for ClaimId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClaim {
    New(ClaimId),
    Claimed(ClaimId),
}

impl TargetClaim {
    pub const fn id(self) -> ClaimId {
        match self {
            TargetClaim::New(id) | TargetClaim::Claimed(id) => id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A claim id survives its hex form, and malformed hex is refused.
    #[test]
    fn claim_id_round_trips_through_hex() {
        let id = ClaimId::from_bytes([0xab; ClaimId::LEN]);
        let hex = id.to_string();
        assert_eq!(hex.len(), ClaimId::LEN * 2);
        assert_eq!(ClaimId::parse_hex(&hex), Some(id));
        assert_eq!(ClaimId::parse_hex("ab"), None);
        assert_eq!(ClaimId::parse_hex(&hex.to_uppercase()), None);
        assert_eq!(ClaimId::from_slice(&[1; 15]), None);
    }
}
