/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::fixture;
use std::{fmt, mem::align_of};
use store::{
    Deserialize, Serialize,
    rkyv::{
        self,
        api::high::{HighDeserializer, HighSerializer, HighValidator},
        bytecheck::CheckBytes,
        rancor,
        ser::allocator::ArenaHandle,
    },
    write::{Archive, ArchiveBytes, Archiver, Compression, Dictionary, compress},
};
use types::acl::ArchivedAclGrant;

pub const ARCHIVED_ALIGNMENT: usize = 1;

const MAILBOX_FIXTURE: &[u8] = include_bytes!("../fixtures/mailbox.bin");
const KEYWORDS_FIXTURE: &[u8] = include_bytes!("../fixtures/keywords.bin");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfCheckStage {
    Decode,
    Encode,
}

#[derive(Debug)]
pub enum SelfCheckError {
    Alignment {
        expected: usize,
        found: usize,
    },
    Codec {
        fixture: &'static str,
        stage: SelfCheckStage,
        source: trc::Error,
    },
    Mismatch {
        fixture: &'static str,
        stage: SelfCheckStage,
    },
}

pub fn self_check() -> Result<(), SelfCheckError> {
    let found = align_of::<ArchivedAclGrant>();
    if found != ARCHIVED_ALIGNMENT {
        return Err(SelfCheckError::Alignment {
            expected: ARCHIVED_ALIGNMENT,
            found,
        });
    }
    compress::init();
    check_fixture(
        "mailbox",
        MAILBOX_FIXTURE,
        fixture::mailbox(),
        Compression::None,
    )?;
    check_fixture(
        "keywords",
        KEYWORDS_FIXTURE,
        fixture::keywords(),
        Compression::Zstd(Some(Dictionary::Email)),
    )
}

fn check_fixture<T>(
    fixture: &'static str,
    bytes: &[u8],
    expected: T,
    compression: Compression,
) -> Result<(), SelfCheckError>
where
    T: PartialEq
        + rkyv::Archive
        + for<'a> rkyv::Serialize<HighSerializer<Vec<u8>, ArenaHandle<'a>, rancor::Error>>,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + rkyv::Deserialize<T, HighDeserializer<rancor::Error>>,
{
    let decode = |source| SelfCheckError::Codec {
        fixture,
        stage: SelfCheckStage::Decode,
        source,
    };
    let encode = |source| SelfCheckError::Codec {
        fixture,
        stage: SelfCheckStage::Encode,
        source,
    };
    let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes).map_err(decode)?;
    archive.unarchive_untrusted::<T>().map_err(decode)?;
    if archive.deserialize::<T>().map_err(decode)? != expected {
        return Err(SelfCheckError::Mismatch {
            fixture,
            stage: SelfCheckStage::Decode,
        });
    }
    if Archiver::with_compression(expected, compression)
        .serialize()
        .map_err(encode)?
        != bytes
    {
        return Err(SelfCheckError::Mismatch {
            fixture,
            stage: SelfCheckStage::Encode,
        });
    }
    Ok(())
}

impl fmt::Display for SelfCheckStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SelfCheckStage::Decode => "decode",
            SelfCheckStage::Encode => "encode",
        })
    }
}

impl fmt::Display for SelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelfCheckError::Alignment { expected, found } => write!(
                f,
                "v1 archived types have alignment {found}, expected {expected}: the rkyv split is broken"
            ),
            SelfCheckError::Codec {
                fixture,
                stage,
                source,
            } => write!(f, "v1 fixture {fixture} failed to {stage}: {source}"),
            SelfCheckError::Mismatch { fixture, stage } => write!(
                f,
                "v1 fixture {fixture} does not match the stock v1 encoding after {stage}"
            ),
        }
    }
}

impl std::error::Error for SelfCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SelfCheckError::Codec { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encodes the fixtures with the vendored v1 code and compares them to the stock v1 output.
    const ZSTD_COMPRESSED_MARKER: u8 = 0x08;

    // Keeps the keywords fixture on the zstd compressed archive path.
    #[test]
    fn keywords_fixture_is_compressed() {
        assert_eq!(
            KEYWORDS_FIXTURE
                .last()
                .map(|marker| marker & ZSTD_COMPRESSED_MARKER),
            Some(ZSTD_COMPRESSED_MARKER)
        );
    }

    #[test]
    fn self_check_passes() {
        self_check().expect("v1 self-check");
    }
}
