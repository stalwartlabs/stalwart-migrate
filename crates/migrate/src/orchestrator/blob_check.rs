/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, pin::pin};

use futures::{StreamExt, stream};
use model::BlobHash;

use super::retry::{RetryPolicy, retry};

const BLOB_CHECK_CONCURRENCY: usize = 16;

pub(super) async fn check_each<F, Fut>(
    policy: RetryPolicy,
    hashes: &[BlobHash],
    tolerated: usize,
    check: F,
) -> model::Result<Vec<model::Result<bool>>>
where
    F: Fn(BlobHash) -> Fut,
    Fut: Future<Output = model::Result<Vec<bool>>>,
{
    let check = &check;
    let mut results = pin!(
        stream::iter(hashes.iter().copied().enumerate())
            .map(|(position, hash)| async move {
                let answer = retry(policy, || check(hash)).await;
                let exists = answer.and_then(|exists| {
                    exists.first().copied().ok_or_else(|| {
                        model::Error::account(format!("no existence answer for blob {hash}"))
                    })
                });
                (position, exists)
            })
            .buffer_unordered(BLOB_CHECK_CONCURRENCY)
    );
    let mut checked = Vec::with_capacity(hashes.len());
    let mut failed = 0;
    while let Some((position, exists)) = results.next().await {
        failed += usize::from(exists.is_err());
        match exists {
            Err(err) if failed > tolerated || !err.is_transient() => return Err(err),
            exists => checked.push((position, exists)),
        }
    }
    checked.sort_unstable_by_key(|(position, _)| *position);
    Ok(checked.into_iter().map(|(_, exists)| exists).collect())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };

    use super::*;

    const SLOW: u8 = 0;
    const BROKEN: u8 = 1;

    fn policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            budget: Duration::from_secs(60),
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
        }
    }

    fn hashes(count: u8) -> Vec<BlobHash> {
        (0..count).map(|byte| BlobHash([byte; 32])).collect()
    }

    // Answers come back in input order even when the first hash finishes last.
    #[tokio::test]
    async fn answers_keep_the_input_order() {
        let exist = check_each(policy(1), &hashes(40), 0, |hash| async move {
            if hash.0[0] == SLOW {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(vec![hash.0[0] % 2 == 0])
        })
        .await
        .expect("checks");
        let exist: Vec<bool> = exist
            .into_iter()
            .map(|exists| exists.expect("ok"))
            .collect();
        assert_eq!(exist, (0..40).map(|byte| byte % 2 == 0).collect::<Vec<_>>());
    }

    // A failing hash is retried alone, and the answers of the others are kept.
    #[tokio::test]
    async fn only_the_failing_hash_is_retried() {
        let calls = [const { AtomicU32::new(0) }; 4];
        let calls = &calls;
        let exist = check_each(policy(3), &hashes(4), 1, |hash| async move {
            let slot = usize::from(hash.0[0]);
            calls[slot].fetch_add(1, Ordering::Relaxed);
            if hash.0[0] == BROKEN {
                Err(model::Error::transient("stalled"))
            } else {
                Ok(vec![true])
            }
        })
        .await
        .expect("checks");
        assert!(exist[0].as_ref().is_ok_and(|exists| *exists));
        assert!(exist[1].is_err());
        assert!(exist[3].as_ref().is_ok_and(|exists| *exists));
        let calls: Vec<u32> = calls.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        assert_eq!(calls, [1, 3, 1, 1]);
    }

    // More failures than tolerated, or a failure that is not transient, end the check.
    #[tokio::test]
    async fn failures_beyond_the_tolerance_abort() {
        let stalled = |_| async { Err(model::Error::transient("stalled")) };
        assert!(check_each(policy(1), &hashes(4), 3, stalled).await.is_err());
        assert!(check_each(policy(1), &hashes(4), 4, stalled).await.is_ok());
        let fatal = |_| async { Err(model::Error::fatal("broken")) };
        assert!(check_each(policy(1), &hashes(4), 4, fatal).await.is_err());
    }
}
