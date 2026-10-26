/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::{
    mem,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use bytes::Bytes;
use model::{
    BlobCache, BlobHash, Issue, IssueKind, RecordBatch, Severity, Source, Subject, Target,
};
use rustc_hash::FxHashMap;
use state::StateStore;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::{JoinError, JoinSet},
    time::timeout,
};

use super::{
    RegistryConverter,
    context::Context,
    error::RunError,
    retry::{RetryPolicy, retry},
    stats::{add, incr},
};

pub(crate) const BLOB_MEMORY_PER_SLOT: u64 = 16 * 1024 * 1024;
const PERMIT_UNIT: u64 = 1024;
const KEPT_BLOB_BYTES: u64 = BLOB_MEMORY_PER_SLOT;
const MAX_BLOB_MEMORY_SLOTS: usize = 16;
const FOLLOW_GRACE: Duration = Duration::from_millis(50);

pub(crate) struct BlobPermits {
    slots: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    memory_units: u32,
    flights: Arc<BlobFlights>,
}

impl BlobPermits {
    pub(crate) fn new(concurrency: usize) -> Self {
        let concurrency = concurrency.max(1);
        let memory_slots = concurrency.min(MAX_BLOB_MEMORY_SLOTS) as u64;
        let memory_units =
            u32::try_from(memory_slots.saturating_mul(BLOB_MEMORY_PER_SLOT) / PERMIT_UNIT)
                .unwrap_or(u32::MAX)
                .min(u32::try_from(Semaphore::MAX_PERMITS).unwrap_or(u32::MAX));
        BlobPermits {
            slots: Arc::new(Semaphore::new(concurrency)),
            memory: Arc::new(Semaphore::new(memory_units as usize)),
            memory_units,
            flights: Arc::default(),
        }
    }

    fn units(&self, size: u64) -> u32 {
        u32::try_from(size.div_ceil(PERMIT_UNIT))
            .unwrap_or(u32::MAX)
            .clamp(1, self.memory_units)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flight {
    Running,
    Present,
    Missing,
}

#[derive(Default)]
struct BlobFlights(Mutex<FxHashMap<BlobHash, watch::Receiver<Flight>>>);

enum Claim {
    Lead(FlightLead),
    Follow(watch::Receiver<Flight>),
}

impl BlobFlights {
    fn claim(self: &Arc<Self>, hash: BlobHash) -> Claim {
        let mut flights = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(receiver) = flights.get(&hash) {
            return Claim::Follow(receiver.clone());
        }
        let (sender, receiver) = watch::channel(Flight::Running);
        flights.insert(hash, receiver);
        Claim::Lead(FlightLead {
            flights: self.clone(),
            hash,
            sender,
        })
    }
}

struct FlightLead {
    flights: Arc<BlobFlights>,
    hash: BlobHash,
    sender: watch::Sender<Flight>,
}

impl FlightLead {
    fn finish(self, flight: Flight) {
        self.sender.send_replace(flight);
    }
}

impl Drop for FlightLead {
    fn drop(&mut self) {
        self.flights
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.hash);
    }
}

async fn follow(mut receiver: watch::Receiver<Flight>) -> Flight {
    receiver
        .wait_for(|flight| *flight != Flight::Running)
        .await
        .map_or(Flight::Running, |flight| *flight)
}

pub(super) struct KeptBlobs {
    pub(super) cache: BlobCache,
    pub(super) memory: Option<OwnedSemaphorePermit>,
}

enum BlobCopy {
    Copied {
        hash: BlobHash,
        data: Bytes,
        memory: OwnedSemaphorePermit,
    },
    Missing {
        hash: BlobHash,
    },
    Followed {
        hash: BlobHash,
        size: u64,
        flight: Flight,
    },
}

type CopyTasks = JoinSet<model::Result<BlobCopy>>;

struct Collected {
    keep_bytes: u64,
    missing: Vec<BlobHash>,
    kept: Vec<(BlobHash, Bytes)>,
    kept_bytes: u64,
    held: Option<OwnedSemaphorePermit>,
    failure: Option<RunError>,
    followers: usize,
    abandoned: Vec<(BlobHash, u64)>,
}

impl Collected {
    fn evict(&mut self) {
        self.kept.clear();
        self.kept_bytes = 0;
        self.held = None;
    }
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn copy_blobs(
        &self,
        account_id: u32,
        batch: &mut RecordBatch,
    ) -> Result<KeptBlobs, RunError> {
        let mut blobs = Vec::new();
        batch.collect_blobs(&mut blobs);
        let (missing, kept, memory) = self.copy_blobs_keeping(blobs, KEPT_BLOB_BYTES).await?;
        if !missing.is_empty() {
            self.drop_missing_blob_objects(account_id, batch, missing)
                .await?;
        }
        Ok(KeptBlobs {
            cache: BlobCache::from_entries(kept),
            memory,
        })
    }

    pub(super) async fn copy_missing_blobs(
        &self,
        blobs: Vec<(BlobHash, u64)>,
    ) -> Result<Vec<BlobHash>, RunError> {
        self.copy_blobs_keeping(blobs, 0)
            .await
            .map(|(missing, _, _)| missing)
    }

    async fn copy_blobs_keeping(
        &self,
        mut blobs: Vec<(BlobHash, u64)>,
        keep_bytes: u64,
    ) -> Result<
        (
            Vec<BlobHash>,
            Vec<(BlobHash, Bytes)>,
            Option<OwnedSemaphorePermit>,
        ),
        RunError,
    > {
        if blobs.is_empty() {
            return Ok((Vec::new(), Vec::new(), None));
        }
        let mut tasks = JoinSet::new();
        let mut collected = Collected {
            keep_bytes,
            missing: Vec::new(),
            kept: Vec::new(),
            kept_bytes: 0,
            held: None,
            failure: None,
            followers: 0,
            abandoned: Vec::new(),
        };
        loop {
            blobs.sort_unstable_by_key(|(hash, _)| *hash);
            blobs.dedup_by_key(|(hash, _)| *hash);
            self.copy_round(&mut blobs, &mut tasks, &mut collected)
                .await?;
            self.drain(&mut tasks, &mut collected).await;
            if collected.failure.is_some() || collected.abandoned.is_empty() {
                break;
            }
            blobs = mem::take(&mut collected.abandoned);
        }
        let Collected {
            mut missing,
            kept,
            held,
            failure,
            ..
        } = collected;
        match failure {
            Some(failure) => Err(failure),
            None => {
                missing.sort_unstable();
                Ok((missing, kept, held))
            }
        }
    }

    async fn copy_round(
        &self,
        blobs: &mut Vec<(BlobHash, u64)>,
        tasks: &mut CopyTasks,
        collected: &mut Collected,
    ) -> Result<(), RunError> {
        let mut hashes = Vec::with_capacity(blobs.len());
        let mut leads = Vec::with_capacity(blobs.len());
        for (hash, size) in blobs.drain(..) {
            match self.blob_permits.flights.claim(hash) {
                Claim::Lead(lead) => {
                    hashes.push(hash);
                    leads.push((size, lead));
                }
                Claim::Follow(receiver) => {
                    collected.followers += 1;
                    tasks.spawn(async move {
                        Ok(BlobCopy::Followed {
                            hash,
                            size,
                            flight: follow(receiver).await,
                        })
                    });
                }
            }
        }
        if leads.is_empty() {
            return Ok(());
        }
        let exists = self.retry(|| self.target.blobs_exist(&hashes)).await?;
        if exists.len() != hashes.len() {
            return Err(model::Error::account(format!(
                "target answered {} blob existence checks for {} hashes",
                exists.len(),
                hashes.len()
            ))
            .into());
        }
        for ((size, lead), exists) in leads.into_iter().zip(exists) {
            if exists {
                lead.finish(Flight::Present);
                continue;
            }
            self.check_shutdown()?;
            let memory = self.acquire_memory(size, tasks, collected).await?;
            if collected.failure.is_some() {
                break;
            }
            let slot = loop {
                let acquire = self.blob_permits.slots.clone().acquire_owned();
                tokio::select! {
                    slot = acquire => break slot.map_err(|_| RunError::Interrupted)?,
                    Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                        self.collect(collected, tasks, joined);
                    }
                }
            };
            if collected.failure.is_some() {
                break;
            }
            let hash = lead.hash;
            let source = self.source.clone();
            let target = self.target.clone();
            let policy = self.policy();
            tasks.spawn(async move {
                let copied = copy_blob(source, target, policy, hash).await;
                drop(slot);
                match copied? {
                    Some(data) => {
                        lead.finish(Flight::Present);
                        Ok(BlobCopy::Copied { hash, data, memory })
                    }
                    None => {
                        lead.finish(Flight::Missing);
                        Ok(BlobCopy::Missing { hash })
                    }
                }
            });
        }
        Ok(())
    }

    async fn acquire_memory(
        &self,
        size: u64,
        tasks: &mut CopyTasks,
        collected: &mut Collected,
    ) -> Result<OwnedSemaphorePermit, RunError> {
        let units = self.blob_permits.units(size);
        loop {
            if let Ok(memory) = self
                .blob_permits
                .memory
                .clone()
                .try_acquire_many_owned(units)
            {
                return Ok(memory);
            }
            if collected.held.is_some() {
                collected.evict();
                continue;
            }
            let acquire = self.blob_permits.memory.clone().acquire_many_owned(units);
            tokio::select! {
                memory = acquire => return memory.map_err(|_| RunError::Interrupted),
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    self.collect(collected, tasks, joined);
                }
            }
        }
    }

    async fn drain(&self, tasks: &mut CopyTasks, collected: &mut Collected) {
        loop {
            let joined = if collected.held.is_some() && tasks.len() == collected.followers {
                match timeout(FOLLOW_GRACE, tasks.join_next()).await {
                    Ok(joined) => joined,
                    Err(_) => {
                        collected.evict();
                        continue;
                    }
                }
            } else {
                tasks.join_next().await
            };
            let Some(joined) = joined else {
                return;
            };
            self.collect(collected, tasks, joined);
        }
    }

    fn collect(
        &self,
        collected: &mut Collected,
        tasks: &mut CopyTasks,
        joined: Result<model::Result<BlobCopy>, JoinError>,
    ) {
        match joined {
            Ok(Ok(BlobCopy::Copied {
                hash,
                data,
                mut memory,
            })) => {
                let size = data.len() as u64;
                incr(&self.stats.blobs_copied);
                add(&self.stats.blob_bytes, size);
                if collected.kept_bytes.saturating_add(size) > collected.keep_bytes {
                    return;
                }
                let needed = self.blob_permits.units(size) as usize;
                if let Some(extra) = needed
                    .checked_sub(memory.num_permits())
                    .filter(|extra| *extra > 0)
                {
                    let Ok(extra) = u32::try_from(extra).map_err(|_| ()).and_then(|extra| {
                        self.blob_permits
                            .memory
                            .clone()
                            .try_acquire_many_owned(extra)
                            .map_err(|_| ())
                    }) else {
                        return;
                    };
                    memory.merge(extra);
                }
                collected.kept_bytes += size;
                collected.kept.push((hash, data));
                match &mut collected.held {
                    Some(held) => held.merge(memory),
                    None => collected.held = Some(memory),
                }
            }
            Ok(Ok(BlobCopy::Missing { hash })) => collected.missing.push(hash),
            Ok(Ok(BlobCopy::Followed { hash, size, flight })) => {
                collected.followers = collected.followers.saturating_sub(1);
                match flight {
                    Flight::Present => {}
                    Flight::Missing => collected.missing.push(hash),
                    Flight::Running => collected.abandoned.push((hash, size)),
                }
            }
            Ok(Err(err)) => {
                if collected.failure.is_none() {
                    tasks.abort_all();
                    collected.failure = Some(RunError::Data(err));
                }
            }
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                if collected.failure.is_none() {
                    tasks.abort_all();
                    collected.failure = Some(RunError::Panic(err.to_string().into_boxed_str()));
                }
            }
        }
    }

    async fn drop_missing_blob_objects(
        &self,
        account_id: u32,
        batch: &mut RecordBatch,
        missing: Vec<BlobHash>,
    ) -> Result<(), RunError> {
        let mut refs = Vec::new();
        batch.collect_blob_refs(&mut refs);
        let mut ids: Vec<u32> = refs
            .into_iter()
            .filter(|(hash, _)| missing.binary_search(hash).is_ok())
            .map(|(_, document_id)| document_id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        let collection = batch.collection();
        let page = self
            .retry(|| self.source.read(account_id, collection, &ids))
            .await?;
        let mut still_present = Vec::new();
        page.batch.collect_ids(&mut still_present);
        still_present.sort_unstable();
        let mut issues = Vec::new();
        for document_id in &ids {
            if still_present.binary_search(document_id).is_ok() {
                issues.push(Issue::new(
                    Severity::Error,
                    IssueKind::Skipped,
                    Subject::Document {
                        collection,
                        document_id: *document_id,
                    },
                    "a blob referenced by this object is missing in the source; the object was not copied",
                ));
            }
        }
        batch.retain_ids(|document_id| ids.binary_search(&document_id).is_err());
        add(&self.stats.objects_skipped, ids.len() as u64);
        self.report(Some(account_id), issues).await
    }
}

pub(super) async fn copy_blob<S: Source, T: Target>(
    source: Arc<S>,
    target: Arc<T>,
    policy: RetryPolicy,
    hash: BlobHash,
) -> model::Result<Option<Bytes>> {
    let Some(data) = retry(policy, || source.read_blob(&hash)).await? else {
        return Ok(None);
    };
    retry(policy, || target.put_blob(&hash, data.clone())).await?;
    failpoint!("blob.copied");
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_scale_with_size_and_are_capped() {
        let permits = BlobPermits::new(2);
        assert_eq!(permits.units(0), 1);
        assert_eq!(permits.units(1), 1);
        assert_eq!(permits.units(4096), 4);
        assert_eq!(permits.units(u64::MAX), permits.memory_units);
        assert_eq!(
            u64::from(permits.memory_units),
            2 * BLOB_MEMORY_PER_SLOT / PERMIT_UNIT
        );
        let wide = BlobPermits::new(64);
        assert_eq!(
            u64::from(wide.memory_units),
            MAX_BLOB_MEMORY_SLOTS as u64 * BLOB_MEMORY_PER_SLOT / PERMIT_UNIT
        );
    }
}
