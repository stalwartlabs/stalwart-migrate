/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::{
    signal::unix::{SignalKind, signal},
    sync::Notify,
};

use crate::terminal::TerminalMode;

pub const EXIT_SIGNAL: i32 = 130;

#[derive(Clone, Default)]
pub struct Shutdown(Arc<Inner>);

#[derive(Default)]
struct Inner {
    requested: AtomicBool,
    immediate: AtomicBool,
    notify: Notify,
}

pub struct ImmediateExit(Shutdown);

impl Drop for ImmediateExit {
    fn drop(&mut self) {
        self.0.0.immediate.store(false, Ordering::SeqCst);
    }
}

impl Shutdown {
    pub fn request(&self) {
        self.0.requested.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn exit_on_signal(&self) -> ImmediateExit {
        self.0.immediate.store(true, Ordering::SeqCst);
        ImmediateExit(self.clone())
    }

    fn exits_immediately(&self) -> bool {
        self.0.immediate.load(Ordering::SeqCst)
    }

    pub fn is_requested(&self) -> bool {
        self.0.requested.load(Ordering::SeqCst)
    }

    pub async fn wait(&self) {
        let notified = self.0.notify.notified();
        if !self.is_requested() {
            notified.await;
        }
    }

    pub fn listen_for_signals(&self) -> std::io::Result<()> {
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let shutdown = self.clone();
        let terminal = TerminalMode::capture();
        tokio::spawn(async move {
            let mut received = 0u32;
            loop {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = interrupt.recv() => {}
                }
                received += 1;
                if received == 1 && !shutdown.exits_immediately() {
                    tracing::warn!(
                        "shutdown requested: finishing in-flight batches and flushing state; signal again to exit immediately"
                    );
                    shutdown.request();
                } else {
                    if let Some(terminal) = &terminal {
                        terminal.restore();
                    }
                    tracing::error!("signal received: exiting immediately");
                    std::process::exit(EXIT_SIGNAL);
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signals exit immediately only while the guard is held.
    #[test]
    fn immediate_exit_is_scoped_to_the_guard() {
        let shutdown = Shutdown::default();
        assert!(!shutdown.exits_immediately());
        let guard = shutdown.exit_on_signal();
        assert!(shutdown.clone().exits_immediately());
        drop(guard);
        assert!(!shutdown.exits_immediately());
    }
}
