/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(feature = "failpoints")]
mod points {
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    const SPEC_VAR: &str = "STALWART_MIGRATE_FAILPOINT";
    const TRACE_VAR: &str = "STALWART_MIGRATE_FAILPOINT_TRACE";

    struct Spec {
        name: Box<str>,
        tag: Option<Box<str>>,
        hit: u64,
        pause: Option<Duration>,
        seen: AtomicU64,
    }

    struct Failpoints {
        specs: Vec<Spec>,
        trace: Option<File>,
    }

    static FAILPOINTS: OnceLock<Failpoints> = OnceLock::new();

    impl Failpoints {
        fn from_env() -> Self {
            let specs = std::env::var(SPEC_VAR)
                .unwrap_or_default()
                .split(',')
                .filter_map(|spec| {
                    let (point, hit) = spec.trim().rsplit_once('@')?;
                    let (hit, pause) = match hit.split_once('~') {
                        Some((hit, millis)) => {
                            (hit, Some(Duration::from_millis(millis.parse().ok()?)))
                        }
                        None => (hit, None),
                    };
                    let hit = hit.parse().ok().filter(|hit| *hit > 0)?;
                    let (name, tag) = match point.split_once(':') {
                        Some((name, tag)) => (name, Some(tag.into())),
                        None => (point, None),
                    };
                    Some(Spec {
                        name: name.into(),
                        tag,
                        hit,
                        pause,
                        seen: AtomicU64::new(0),
                    })
                })
                .collect();
            let trace = std::env::var_os(TRACE_VAR)
                .and_then(|path| OpenOptions::new().create(true).append(true).open(path).ok());
            Failpoints { specs, trace }
        }

        fn record(&self, line: &str) {
            if let Some(mut trace) = self.trace.as_ref() {
                let _ = trace.write_all(line.as_bytes());
            }
        }
    }

    pub(crate) fn hit(name: &str, tag: &str) {
        let points = FAILPOINTS.get_or_init(Failpoints::from_env);
        points.record(&format!("hit {name} {tag}\n"));
        for spec in &points.specs {
            if *spec.name == *name
                && spec.tag.as_deref().is_none_or(|wanted| wanted == tag)
                && spec.seen.fetch_add(1, Ordering::SeqCst) + 1 == spec.hit
            {
                let action = if spec.pause.is_some() {
                    "pause"
                } else {
                    "abort"
                };
                points.record(&format!("{action} {name} {tag} {}\n", spec.hit));
                if let Some(trace) = &points.trace {
                    let _ = trace.sync_all();
                }
                if let Some(pause) = spec.pause {
                    std::thread::sleep(pause);
                    continue;
                }
                eprintln!("failpoint {name} {tag} reached hit {}: aborting", spec.hit);
                std::process::abort();
            }
        }
    }
}

#[cfg(feature = "failpoints")]
pub(crate) use points::hit;

macro_rules! failpoint {
    ($name:literal) => {
        $crate::failpoint::failpoint!($name, "")
    };
    ($name:literal, $tag:expr) => {{
        #[cfg(feature = "failpoints")]
        {
            $crate::failpoint::hit($name, $tag);
        }
    }};
}

pub(crate) use failpoint;
