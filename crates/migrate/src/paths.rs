/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    cmp::Reverse,
    fmt,
    io::{self, ErrorKind},
    os::unix::fs::{MetadataExt, chown, lchown},
    path::{Path, PathBuf},
    str::FromStr,
};

const LOST_FOUND: &str = "lost+found";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMapping {
    from: Box<str>,
    to: Box<str>,
}

impl FromStr for PathMapping {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (from, to) = value
            .split_once('=')
            .ok_or_else(|| format!("expected <from>=<to>, got {value:?}"))?;
        if !from.starts_with('/') || !to.starts_with('/') {
            return Err(format!(
                "path map entries must be absolute paths: {value:?}"
            ));
        }
        let from = from.trim_end_matches('/');
        let to = to.trim_end_matches('/');
        Ok(PathMapping {
            from: if from.is_empty() { "/" } else { from }.into(),
            to: if to.is_empty() { "/" } else { to }.into(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathMap {
    entries: Vec<PathMapping>,
}

impl PathMap {
    pub fn new(mut entries: Vec<PathMapping>) -> Self {
        entries.sort_unstable_by_key(|entry| Reverse(entry.from.len()));
        PathMap { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn apply<'x>(&self, path: &'x str) -> Cow<'x, str> {
        for entry in &self.entries {
            if let Some(rest) = strip_component_prefix(path, &entry.from) {
                let mut mapped = String::with_capacity(entry.to.len() + rest.len());
                mapped.push_str(&entry.to);
                if !rest.is_empty() {
                    if !mapped.ends_with('/') {
                        mapped.push('/');
                    }
                    mapped.push_str(rest);
                }
                return Cow::Owned(mapped);
            }
        }
        Cow::Borrowed(path)
    }
}

fn strip_component_prefix<'x>(path: &'x str, prefix: &str) -> Option<&'x str> {
    if prefix == "/" {
        return path.strip_prefix('/');
    }
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        Some(rest)
    } else {
        rest.strip_prefix('/')
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

impl FromStr for Owner {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (uid, gid) = value
            .split_once(':')
            .ok_or_else(|| format!("expected <uid>:<gid>, got {value:?}"))?;
        let uid = uid
            .parse()
            .map_err(|_| format!("invalid uid in {value:?}"))?;
        let gid = gid
            .parse()
            .map_err(|_| format!("invalid gid in {value:?}"))?;
        Ok(Owner { uid, gid })
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.uid, self.gid)
    }
}

impl Owner {
    pub fn apply(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        self.apply_inner(path.as_ref())
    }

    fn apply_inner(&self, root: &Path) -> std::io::Result<()> {
        let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                lchown(&path, Some(self.uid), Some(self.gid))?;
                continue;
            }
            chown(&path, Some(self.uid), Some(self.gid))?;
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&path)? {
                    pending.push(entry?.path());
                }
            }
        }
        Ok(())
    }

    fn adopt_created_by(&self, root: &Path, creator: u32) -> io::Result<()> {
        let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let Some(metadata) = ignore_missing(std::fs::symlink_metadata(&path))? else {
                continue;
            };
            if metadata.uid() == creator {
                ignore_missing(lchown(&path, Some(self.uid), Some(self.gid)))?;
            }
            if metadata.is_dir() {
                let Some(entries) = ignore_missing(std::fs::read_dir(&path))? else {
                    continue;
                };
                for entry in entries {
                    let entry = entry?;
                    if entry.file_name() != LOST_FOUND {
                        pending.push(entry.path());
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn apply_owner<'x>(
    paths: impl IntoIterator<Item = &'x Path>,
    owner: Option<Owner>,
) -> std::io::Result<()> {
    let Some(owner) = owner else {
        return Ok(());
    };
    for path in paths {
        if path.exists() {
            owner.apply(path)?;
        }
    }
    Ok(())
}

pub fn adopt_created<'x>(
    paths: impl IntoIterator<Item = &'x Path>,
    owner: Owner,
) -> io::Result<()> {
    let creator = effective_uid();
    if creator == owner.uid {
        return Ok(());
    }
    for path in paths {
        owner.adopt_created_by(path, creator)?;
    }
    Ok(())
}

pub fn running_as_root() -> bool {
    effective_uid() == 0
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn ignore_missing<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[&str]) -> PathMap {
        PathMap::new(
            entries
                .iter()
                .map(|entry| entry.parse().expect("valid mapping"))
                .collect(),
        )
    }

    #[test]
    fn longest_prefix_on_component_boundary() {
        let map = map(&[
            "/var/lib/stalwart=/srv/data",
            "/var/lib/stalwart/blobs=/mnt/blobs/",
            "/etc/stalwart=/home/op/etc",
        ]);
        assert_eq!(map.apply("/var/lib/stalwart/db"), "/srv/data/db");
        assert_eq!(map.apply("/var/lib/stalwart"), "/srv/data");
        assert_eq!(map.apply("/var/lib/stalwart/blobs/a/b"), "/mnt/blobs/a/b");
        assert_eq!(
            map.apply("/var/lib/stalwart-other/db"),
            "/var/lib/stalwart-other/db"
        );
        assert_eq!(
            map.apply("/etc/stalwart/fdb.cluster"),
            "/home/op/etc/fdb.cluster"
        );
        assert!(matches!(map.apply("/opt/x"), Cow::Borrowed("/opt/x")));
    }

    #[test]
    fn root_mapping_and_invalid_entries() {
        let map = map(&["/=/mnt/root"]);
        assert_eq!(map.apply("/var/x"), "/mnt/root/var/x");
        assert!("relative=/x".parse::<PathMapping>().is_err());
        assert!("/x".parse::<PathMapping>().is_err());
    }

    #[test]
    fn owner_is_applied_recursively() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).expect("dirs");
        std::fs::write(nested.join("file"), b"x").expect("file");
        let metadata = std::fs::metadata(dir.path()).expect("metadata");
        let owner = Owner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        apply_owner([dir.path(), Path::new("/nonexistent/path")], Some(owner)).expect("chown");
        apply_owner([dir.path()], None).expect("no owner");
        assert_eq!(
            std::fs::metadata(nested.join("file"))
                .expect("metadata")
                .uid(),
            owner.uid
        );
    }

    fn other_group(gid: u32) -> Option<u32> {
        let mut groups = [0 as libc::gid_t; 64];
        let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
        let count = usize::try_from(count).ok()?;
        groups
            .get(..count)?
            .iter()
            .copied()
            .find(|group| *group != gid)
    }

    // Only entries owned by the creating user are handed to the owner; the walk skips vanished paths.
    #[test]
    fn adopt_created_changes_only_entries_of_the_creator() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("53/54");
        std::fs::create_dir_all(&nested).expect("dirs");
        std::fs::write(nested.join("blob"), b"x").expect("file");
        let metadata = std::fs::metadata(dir.path()).expect("metadata");
        let Some(gid) = other_group(metadata.gid()) else {
            return;
        };
        let owner = Owner {
            uid: metadata.uid(),
            gid,
        };
        let gid_of = |path: &Path| std::fs::metadata(path).expect("metadata").gid();

        owner
            .adopt_created_by(dir.path(), metadata.uid().wrapping_add(1))
            .expect("foreign creator");
        assert_eq!(gid_of(&nested.join("blob")), metadata.gid());

        owner
            .adopt_created_by(dir.path(), metadata.uid())
            .expect("own creator");
        owner
            .adopt_created_by(Path::new("/nonexistent/path"), metadata.uid())
            .expect("missing root");
        for path in [dir.path(), nested.as_path(), &nested.join("blob")] {
            assert_eq!(gid_of(path), gid, "{}", path.display());
        }
    }

    #[test]
    fn owner_parsing() {
        assert_eq!(
            "2000:2000".parse::<Owner>(),
            Ok(Owner {
                uid: 2000,
                gid: 2000
            })
        );
        assert!("2000".parse::<Owner>().is_err());
        assert!("a:b".parse::<Owner>().is_err());
    }
}
