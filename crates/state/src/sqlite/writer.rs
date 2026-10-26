/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::mpsc;

use rusqlite::Connection;
use tokio::sync::oneshot;

use crate::error::{Error, Result};

const MAX_GROUP: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Access {
    ReadWrite,
    ReadOnly,
}

pub(super) trait Job: Send {
    fn run(&mut self, conn: &Connection) -> bool;

    fn fail(&mut self, err: Error);

    fn finish(self: Box<Self>, commit: Result<()>);
}

pub(super) struct Task<F, R> {
    work: Option<F>,
    result: Option<Result<R>>,
    reply: oneshot::Sender<Result<R>>,
}

impl<F, R> Task<F, R> {
    pub(super) fn new(work: F, reply: oneshot::Sender<Result<R>>) -> Self {
        Task {
            work: Some(work),
            result: None,
            reply,
        }
    }
}

impl<F, R> Job for Task<F, R>
where
    F: FnOnce(&Connection) -> Result<R> + Send,
    R: Send,
{
    fn run(&mut self, conn: &Connection) -> bool {
        let Some(work) = self.work.take() else {
            return false;
        };
        let result = work(conn);
        let ok = result.is_ok();
        self.result = Some(result);
        ok
    }

    fn fail(&mut self, err: Error) {
        self.work = None;
        self.result = Some(Err(err));
    }

    fn finish(self: Box<Self>, commit: Result<()>) {
        let Task { result, reply, .. } = *self;
        let outcome = match (commit, result) {
            (Ok(()), Some(result)) => result,
            (Ok(()), None) => Err(Error::Closed),
            (Err(err), _) => Err(err),
        };
        let _ = reply.send(outcome);
    }
}

pub(super) fn run(conn: Connection, jobs: mpsc::Receiver<Box<dyn Job>>, access: Access) {
    let mut group: Vec<Box<dyn Job>> = Vec::with_capacity(MAX_GROUP);
    while let Ok(first) = jobs.recv() {
        group.push(first);
        while group.len() < MAX_GROUP {
            match jobs.try_recv() {
                Ok(job) => group.push(job),
                Err(_) => break,
            }
        }
        let outcome = match access {
            Access::ReadWrite => run_group(&conn, &mut group),
            Access::ReadOnly => {
                for job in group.iter_mut() {
                    job.run(&conn);
                }
                Ok(())
            }
        };
        for job in group.drain(..) {
            job.finish(outcome.clone());
        }
    }
}

fn run_group(conn: &Connection, group: &mut [Box<dyn Job>]) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    for job in group.iter_mut() {
        if let Err(err) = run_isolated(conn, job.as_mut()) {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(err);
        }
    }
    match conn.execute_batch("COMMIT") {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err.into())
        }
    }
}

fn run_isolated(conn: &Connection, job: &mut dyn Job) -> Result<()> {
    if let Err(err) = conn.execute_batch("SAVEPOINT job") {
        let err = Error::from(err);
        job.fail(err.clone());
        return Err(err);
    }
    let end = if job.run(conn) {
        "RELEASE job"
    } else {
        "ROLLBACK TO job; RELEASE job"
    };
    conn.execute_batch(end).map_err(Error::from)
}
