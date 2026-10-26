/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    future::Future,
    hash::{BuildHasher, RandomState},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub budget: Duration,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 10,
            budget: Duration::from_secs(300),
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
        }
    }
}

pub(crate) struct Backoff {
    policy: RetryPolicy,
    attempts: u32,
    started: Instant,
}

impl Backoff {
    pub(crate) fn new(policy: RetryPolicy) -> Self {
        Backoff {
            policy,
            attempts: 1,
            started: Instant::now(),
        }
    }

    pub(crate) fn next_delay(&mut self, err: &model::Error) -> Option<Duration> {
        if !err.is_transient()
            || self.attempts >= self.policy.max_attempts
            || self.started.elapsed() >= self.policy.budget
        {
            return None;
        }
        let exponent = self.attempts.saturating_sub(1).min(16);
        self.attempts += 1;
        let ceiling = self
            .policy
            .base_delay
            .saturating_mul(1 << exponent)
            .min(self.policy.max_delay);
        Some(jitter(ceiling))
    }

    pub(crate) async fn wait(&mut self, err: &model::Error) -> bool {
        match self.next_delay(err) {
            Some(delay) => {
                tracing::debug!(error = %err, delay_ms = delay.as_millis() as u64, "retrying after transient error");
                tokio::time::sleep(delay).await;
                true
            }
            None => false,
        }
    }
}

fn jitter(ceiling: Duration) -> Duration {
    const SCALE: u64 = 1024;
    let random = RandomState::new().hash_one(Instant::now()) % SCALE;
    ceiling / 2 + ceiling.mul_f64(random as f64 / (2 * SCALE) as f64)
}

pub(crate) async fn retry<R, F, Fut>(policy: RetryPolicy, mut op: F) -> model::Result<R>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = model::Result<R>>,
{
    let mut backoff = Backoff::new(policy);
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if !backoff.wait(&err).await {
                    return Err(err);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            budget: Duration::from_secs(60),
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        }
    }

    #[test]
    fn only_transient_errors_are_retried() {
        let mut backoff = Backoff::new(policy(3));
        assert!(backoff.next_delay(&model::Error::fatal("x")).is_none());
        assert!(backoff.next_delay(&model::Error::too_large("x")).is_none());
        assert!(backoff.next_delay(&model::Error::transient("x")).is_some());
        assert!(backoff.next_delay(&model::Error::transient("x")).is_some());
        assert!(backoff.next_delay(&model::Error::transient("x")).is_none());
    }

    #[test]
    fn delays_are_bounded() {
        let mut backoff = Backoff::new(policy(40));
        for _ in 0..30 {
            let delay = backoff
                .next_delay(&model::Error::transient("x"))
                .expect("retry allowed");
            assert!(delay <= Duration::from_millis(4));
            assert!(delay >= Duration::from_micros(500));
        }
    }

    #[tokio::test]
    async fn retry_gives_up_after_budget() {
        let mut calls = 0;
        let result: model::Result<()> = retry(policy(4), || {
            calls += 1;
            async { Err(model::Error::transient("busy")) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls, 4);

        let mut calls = 0;
        let result = retry(policy(4), || {
            calls += 1;
            let attempt = calls;
            async move {
                if attempt < 3 {
                    Err(model::Error::transient("busy"))
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;
        assert_eq!(result, Ok(3));
    }
}
