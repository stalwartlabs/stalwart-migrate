/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use rocksdb::{BoundColumnFamily, DBWithThreadMode, MultiThreaded, OptimisticTransactionDB};

use crate::{SUBSPACE_BLOBS, SUBSPACE_INDEXES, SUBSPACE_LOGS};

pub mod blob;
pub mod main;
pub mod read;
pub mod write;

pub use main::RocksDbOpenMode;

static CF_LOGS: &str = unsafe { std::str::from_utf8_unchecked(&[SUBSPACE_LOGS]) };
static CF_INDEXES: &str = unsafe { std::str::from_utf8_unchecked(&[SUBSPACE_INDEXES]) };
static CF_BLOBS: &str = unsafe { std::str::from_utf8_unchecked(&[SUBSPACE_BLOBS]) };

pub(crate) trait CfHandle {
    fn subspace_handle(&self, subspace: u8) -> Arc<BoundColumnFamily<'_>>;
}

impl CfHandle for OptimisticTransactionDB<MultiThreaded> {
    #[inline(always)]
    fn subspace_handle(&self, subspace: u8) -> Arc<BoundColumnFamily<'_>> {
        let subspace = &[subspace];
        self.cf_handle(unsafe { std::str::from_utf8_unchecked(subspace) })
            .unwrap()
    }
}

impl CfHandle for DBWithThreadMode<MultiThreaded> {
    #[inline(always)]
    fn subspace_handle(&self, subspace: u8) -> Arc<BoundColumnFamily<'_>> {
        let subspace = &[subspace];
        self.cf_handle(unsafe { std::str::from_utf8_unchecked(subspace) })
            .unwrap()
    }
}

#[derive(Clone)]
pub(crate) enum RocksDbInstance {
    ReadWrite(Arc<OptimisticTransactionDB<MultiThreaded>>),
    ReadOnly(Arc<DBWithThreadMode<MultiThreaded>>),
    BlobsReadOnly(Arc<DBWithThreadMode<MultiThreaded>>),
}

impl RocksDbInstance {
    pub(crate) fn read_write(&self) -> trc::Result<&Arc<OptimisticTransactionDB<MultiThreaded>>> {
        match self {
            RocksDbInstance::ReadWrite(db) => Ok(db),
            _ => Err(trc::StoreEvent::NotSupported
                .into_err()
                .details("RocksDB store is opened read-only")),
        }
    }

    pub(crate) fn readable(&self, subspace: u8) -> trc::Result<&Self> {
        match self {
            RocksDbInstance::BlobsReadOnly(_) if subspace != SUBSPACE_BLOBS => {
                Err(trc::StoreEvent::NotSupported
                    .into_err()
                    .details("RocksDB blob instances only serve blobs"))
            }
            _ => Ok(self),
        }
    }
}

macro_rules! with_db {
    ($instance:expr, $db:ident => $body:expr) => {
        match $instance {
            $crate::backend::rocksdb::RocksDbInstance::ReadWrite($db) => $body,
            $crate::backend::rocksdb::RocksDbInstance::ReadOnly($db)
            | $crate::backend::rocksdb::RocksDbInstance::BlobsReadOnly($db) => $body,
        }
    };
}

pub(crate) use with_db;

pub struct RocksDbStore {
    db: RocksDbInstance,
    worker_pool: rayon::ThreadPool,
}

#[inline(always)]
fn into_error(err: rocksdb::Error) -> trc::Error {
    trc::StoreEvent::RocksdbError.reason(err)
}
