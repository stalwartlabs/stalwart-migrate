/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    cmp::Reverse,
    fmt,
    os::unix::fs::{chown, lchown},
    path::{Path, PathBuf},
    str::FromStr,
};

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

pub fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
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
