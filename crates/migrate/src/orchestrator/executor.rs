/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinError, JoinSet},
};

use super::error::RunError;
use crate::shutdown::Shutdown;

pub(crate) async fn for_each_bounded<I, F, Fut>(
    items: I,
    limit: usize,
    shutdown: &Shutdown,
    mut task: F,
) -> Result<(), RunError>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: Future<Output = Result<(), RunError>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut items = items.into_iter().peekable();
    let mut failure: Option<RunError> = None;
    let mut interrupted = false;

    loop {
        while failure.is_none() && tasks.len() < limit.max(1) && items.peek().is_some() {
            if shutdown.is_requested() {
                interrupted = true;
                break;
            }
            if let Some(item) = items.next() {
                tasks.spawn(task(item));
            }
        }

        let Some(joined) = tasks.join_next().await else {
            break;
        };
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(RunError::Interrupted)) => interrupted = true,
            Ok(Err(err)) => {
                if failure.is_none() {
                    tasks.abort_all();
                    failure = Some(err);
                }
            }
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                if failure.is_none() {
                    tasks.abort_all();
                    failure = Some(RunError::Panic(err.to_string().into_boxed_str()));
                }
            }
        }
    }

    match failure {
        Some(err) => Err(err),
        None if interrupted => Err(RunError::Interrupted),
        None => Ok(()),
    }
}

fn joined_failure(joined: Result<Result<(), RunError>, JoinError>) -> Option<RunError> {
    match joined {
        Ok(Ok(())) => None,
        Ok(Err(err)) => Some(err),
        Err(err) if err.is_cancelled() => None,
        Err(err) => Some(RunError::Panic(err.to_string().into_boxed_str())),
    }
}

enum Step<P, J> {
    Permit(P),
    Joined(J),
}

pub(crate) async fn for_each_with_slots<I, F, Fut>(
    items: I,
    slots: &Arc<Semaphore>,
    shutdown: &Shutdown,
    mut task: F,
) -> Result<(), RunError>
where
    I: IntoIterator,
    F: FnMut(I::Item, OwnedSemaphorePermit) -> Fut,
    Fut: Future<Output = Result<(), RunError>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut items = items.into_iter().peekable();
    let mut failure: Option<RunError> = None;
    let mut interrupted = false;
    let mut acquire = None;
    let mut ready = None;

    loop {
        let wants_more = failure.is_none() && !interrupted && items.peek().is_some();
        if wants_more && shutdown.is_requested() {
            interrupted = true;
            continue;
        }
        let joined = if wants_more {
            let step = match ready.take() {
                Some(permit) => Step::Permit(Ok(permit)),
                None => {
                    let pending =
                        acquire.get_or_insert_with(|| Box::pin(slots.clone().acquire_owned()));
                    tokio::select! {
                        biased;
                        permit = pending.as_mut() => Step::Permit(permit),
                        Some(joined) = tasks.join_next(), if !tasks.is_empty() => Step::Joined(joined),
                    }
                }
            };
            match step {
                Step::Permit(permit) => {
                    acquire = None;
                    let Ok(permit) = permit else {
                        interrupted = true;
                        continue;
                    };
                    if let Some(item) = items.next() {
                        if items.peek().is_some() {
                            let mut next = Box::pin(slots.clone().acquire_owned());
                            match Pin::as_mut(&mut next)
                                .poll(&mut Context::from_waker(Waker::noop()))
                            {
                                Poll::Ready(Ok(permit)) => ready = Some(permit),
                                Poll::Ready(Err(_)) => {}
                                Poll::Pending => acquire = Some(next),
                            }
                        }
                        tasks.spawn(task(item, permit));
                    }
                    continue;
                }
                Step::Joined(joined) => joined,
            }
        } else {
            acquire = None;
            ready = None;
            match tasks.join_next().await {
                Some(joined) => joined,
                None => break,
            }
        };
        match joined_failure(joined) {
            None => {}
            Some(RunError::Interrupted) => interrupted = true,
            Some(err) if failure.is_none() => {
                tasks.abort_all();
                failure = Some(err);
            }
            Some(_) => {}
        }
    }

    match failure {
        Some(err) => Err(err),
        None if interrupted => Err(RunError::Interrupted),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;

    #[tokio::test]
    async fn respects_concurrency_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let shutdown = Shutdown::default();
        for_each_bounded(0..20, 3, &shutdown, |_| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .expect("all tasks succeed");
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn stops_on_first_failure() {
        let started = Arc::new(AtomicUsize::new(0));
        let shutdown = Shutdown::default();
        let result = for_each_bounded(0..100, 2, &shutdown, |item| {
            let started = started.clone();
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                if item == 3 {
                    Err(RunError::preflight("boom"))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(result, Err(RunError::preflight("boom")));
        assert!(started.load(Ordering::SeqCst) < 100);
    }

    // A queued account gets the next released slot; a running account's try_acquire never takes it first.
    #[tokio::test]
    async fn waiting_items_win_over_extra_slots() {
        let slots = Arc::new(Semaphore::new(2));
        let shutdown = Shutdown::default();
        let third_started = Arc::new(AtomicUsize::new(0));
        let stolen = Arc::new(AtomicUsize::new(0));
        let extras = slots.clone();
        for_each_with_slots(1..=3u32, &slots, &shutdown, |item, permit| {
            let third_started = third_started.clone();
            let stolen = stolen.clone();
            let extras = extras.clone();
            async move {
                let _permit = permit;
                match item {
                    1 => {
                        let started = std::time::Instant::now();
                        while third_started.load(Ordering::SeqCst) < 2
                            && started.elapsed() < Duration::from_secs(5)
                        {
                            if let Ok(extra) = extras.clone().try_acquire_owned() {
                                if third_started.load(Ordering::SeqCst) == 0 {
                                    stolen.fetch_add(1, Ordering::SeqCst);
                                }
                                drop(extra);
                            }
                            tokio::task::yield_now().await;
                        }
                    }
                    2 => tokio::time::sleep(Duration::from_millis(5)).await,
                    _ => {
                        third_started.store(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        third_started.store(2, Ordering::SeqCst);
                    }
                }
                Ok(())
            }
        })
        .await
        .expect("all tasks succeed");
        assert_eq!(stolen.load(Ordering::SeqCst), 0);
        assert_eq!(third_started.load(Ordering::SeqCst), 2);
    }

    // Running accounts polling for extra slots never take a permit while accounts are still queued, on a multi-threaded runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queued_items_are_never_robbed_by_extra_slots() {
        const SMALL: usize = 2000;
        let slots = Arc::new(Semaphore::new(2));
        let shutdown = Shutdown::default();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let steals = Arc::new(AtomicUsize::new(0));
        let extras = slots.clone();
        for_each_with_slots(0..=SMALL, &slots, &shutdown, |item, permit| {
            dispatched.fetch_add(1, Ordering::SeqCst);
            let dispatched = dispatched.clone();
            let finished = finished.clone();
            let steals = steals.clone();
            let extras = extras.clone();
            async move {
                let _permit = permit;
                if item == 0 {
                    while finished.load(Ordering::SeqCst) < SMALL {
                        if let Ok(extra) = extras.clone().try_acquire_owned() {
                            if dispatched.load(Ordering::SeqCst) <= SMALL {
                                steals.fetch_add(1, Ordering::SeqCst);
                            }
                            drop(extra);
                        }
                        tokio::task::yield_now().await;
                    }
                } else {
                    tokio::task::yield_now().await;
                    finished.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            }
        })
        .await
        .expect("all tasks succeed");
        assert_eq!(steals.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn shutdown_stops_spawning() {
        let shutdown = Shutdown::default();
        let started = Arc::new(AtomicUsize::new(0));
        let trigger = shutdown.clone();
        let result = for_each_bounded(0..100, 1, &shutdown, |item| {
            let started = started.clone();
            let trigger = trigger.clone();
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                if item == 4 {
                    trigger.request();
                }
                Ok(())
            }
        })
        .await;
        assert_eq!(result, Err(RunError::Interrupted));
        assert_eq!(started.load(Ordering::SeqCst), 5);
    }
}
