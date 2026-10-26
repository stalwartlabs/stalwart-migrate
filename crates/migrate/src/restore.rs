/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{RegistryKey, RegistryRecord};
use rustc_hash::FxHashSet;
use serde_json::Value;

pub(crate) type Candidate<'r> = (&'r RegistryRecord, Vec<RegistryKey>);

pub(crate) struct RestoredRecord<'r> {
    pub(crate) record: &'r RegistryRecord,
    pub(crate) json: Value,
    pub(crate) deferred: bool,
}

pub(crate) struct RestorePlan<'r> {
    pub(crate) restored: Vec<RestoredRecord<'r>>,
    pub(crate) blocked: Vec<Candidate<'r>>,
    pub(crate) restored_keys: FxHashSet<RegistryKey>,
}

pub(crate) fn plan_restore<'r>(
    mut pending: Vec<Candidate<'r>>,
    missing: impl Fn(&RegistryKey, &FxHashSet<RegistryKey>) -> bool,
    mut split_cycle: impl FnMut(&[&'r RegistryRecord]) -> Option<Vec<RestoredRecord<'r>>>,
) -> RestorePlan<'r> {
    let mut restored = Vec::new();
    let mut restored_keys: FxHashSet<RegistryKey> = FxHashSet::default();
    let mut unsplittable: FxHashSet<RegistryKey> = FxHashSet::default();
    loop {
        loop {
            let before = pending.len();
            let mut blocked = Vec::with_capacity(before);
            for (record, references) in pending {
                if references
                    .iter()
                    .any(|key| *key != record.key && missing(key, &restored_keys))
                {
                    blocked.push((record, references));
                    continue;
                }
                restored_keys.insert(record.key.clone());
                restored.push(RestoredRecord {
                    record,
                    json: record.json.clone(),
                    deferred: false,
                });
            }
            pending = blocked;
            if pending.len() == before {
                break;
            }
        }
        let mut progress = false;
        for component in sink_components(&pending, &missing, &restored_keys) {
            if component
                .iter()
                .any(|record| unsplittable.contains(&record.key))
            {
                continue;
            }
            match split_cycle(&component) {
                Some(group) => {
                    for entry in group {
                        restored_keys.insert(entry.record.key.clone());
                        restored.push(entry);
                    }
                    progress = true;
                }
                None => {
                    unsplittable.extend(component.iter().map(|record| record.key.clone()));
                }
            }
        }
        if !progress {
            break;
        }
        pending.retain(|(record, _)| !restored_keys.contains(&record.key));
    }
    RestorePlan {
        restored,
        blocked: pending,
        restored_keys,
    }
}

fn reachable(edges: &[Vec<usize>], start: usize) -> Vec<bool> {
    let mut seen = vec![false; edges.len()];
    let mut stack = vec![start];
    while let Some(node) = stack.pop() {
        for &next in edges.get(node).into_iter().flatten() {
            if let Some(flag) = seen.get_mut(next)
                && !*flag
            {
                *flag = true;
                stack.push(next);
            }
        }
    }
    seen
}

fn sink_components<'r>(
    pending: &[Candidate<'r>],
    missing: &impl Fn(&RegistryKey, &FxHashSet<RegistryKey>) -> bool,
    restored_keys: &FxHashSet<RegistryKey>,
) -> Vec<Vec<&'r RegistryRecord>> {
    let edges: Vec<Vec<usize>> = pending
        .iter()
        .map(|(record, references)| {
            references
                .iter()
                .filter(|key| **key != record.key)
                .filter_map(|key| pending.iter().position(|(other, _)| other.key == *key))
                .collect()
        })
        .collect();
    let reach: Vec<Vec<bool>> = (0..pending.len())
        .map(|start| reachable(&edges, start))
        .collect();
    let reaches = |from: usize, to: usize| {
        reach
            .get(from)
            .and_then(|row| row.get(to))
            .copied()
            .unwrap_or(false)
    };
    let mut assigned = vec![false; pending.len()];
    let mut components = Vec::new();
    for start in 0..pending.len() {
        if assigned.get(start).copied().unwrap_or(true) || !reaches(start, start) {
            continue;
        }
        let mut members: Vec<&'r RegistryRecord> = Vec::new();
        for (other, (record, _)) in pending.iter().enumerate() {
            if reaches(start, other) && reaches(other, start) {
                if let Some(flag) = assigned.get_mut(other) {
                    *flag = true;
                }
                members.push(*record);
            }
        }
        let is_sink = pending
            .iter()
            .filter(|(record, _)| members.iter().any(|member| member.key == record.key))
            .all(|(record, references)| {
                references.iter().all(|key| {
                    *key == record.key
                        || members.iter().any(|member| member.key == *key)
                        || !missing(key, restored_keys)
                })
            });
        if is_sink {
            components.push(members);
        }
    }
    components
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn record(object: &str, id: u64) -> RegistryRecord {
        RegistryRecord {
            key: RegistryKey::new(object, id),
            json: json!({}),
        }
    }

    // An unsplittable cycle does not stop another cycle in the same pass from being restored.
    #[test]
    fn unsplittable_cycle_does_not_block_other_cycles() {
        let [a, b, c, d] = [
            record("A", 1),
            record("B", 2),
            record("C", 3),
            record("D", 4),
        ];
        let pending: Vec<Candidate<'_>> = vec![
            (&c, vec![d.key.clone()]),
            (&d, vec![c.key.clone()]),
            (&a, vec![b.key.clone()]),
            (&b, vec![a.key.clone()]),
        ];
        let lost: FxHashSet<RegistryKey> = [&a, &b, &c, &d]
            .into_iter()
            .map(|record| record.key.clone())
            .collect();
        let plan = plan_restore(
            pending,
            |key, restored| lost.contains(key) && !restored.contains(key),
            |members| {
                if members.iter().any(|record| &*record.key.object == "C") {
                    return None;
                }
                Some(
                    members
                        .iter()
                        .map(|record| RestoredRecord {
                            record,
                            json: record.json.clone(),
                            deferred: false,
                        })
                        .collect(),
                )
            },
        );
        let mut restored: Vec<&str> = plan
            .restored
            .iter()
            .map(|entry| &*entry.record.key.object)
            .collect();
        restored.sort_unstable();
        assert_eq!(restored, ["A", "B"]);
        let blocked: Vec<&str> = plan
            .blocked
            .iter()
            .map(|(record, _)| &*record.key.object)
            .collect();
        assert_eq!(blocked, ["C", "D"]);
    }
}
