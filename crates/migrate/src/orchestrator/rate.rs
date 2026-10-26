/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    num::NonZeroU32,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

pub(crate) struct RateLimiter {
    per_op: Option<Duration>,
    next: Mutex<Instant>,
}

impl RateLimiter {
    pub(crate) fn new(max_ops_per_sec: Option<NonZeroU32>) -> Self {
        RateLimiter {
            per_op: max_ops_per_sec.map(|rate| Duration::from_secs(1) / rate.get()),
            next: Mutex::new(Instant::now()),
        }
    }

    pub(crate) async fn acquire(&self, ops: usize) {
        let Some(per_op) = self.per_op else {
            return;
        };
        let wait = {
            let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            let start = (*next).max(now);
            let ops = u32::try_from(ops).unwrap_or(u32::MAX);
            *next = start + per_op.saturating_mul(ops);
            start - now
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_does_not_wait() {
        let limiter = RateLimiter::new(None);
        let started = Instant::now();
        limiter.acquire(1_000_000).await;
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn limited_spaces_requests() {
        let limiter = RateLimiter::new(NonZeroU32::new(1000));
        let started = Instant::now();
        limiter.acquire(50).await;
        limiter.acquire(50).await;
        limiter.acquire(1).await;
        assert!(started.elapsed() >= Duration::from_millis(100));
    }
}
