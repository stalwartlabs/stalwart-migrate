/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{CategorySet, Collection, Explanation, RegistryKey, Severity};
use xxhash_rust::xxh3::xxh3_128;

pub type RunId = i64;

macro_rules! text_enum {
    ($name:ident { $($variant:ident => $text:literal),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $($variant,)*
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant,)*];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)*
                }
            }

            pub fn parse(value: &str) -> Option<Self> {
                hashify::map!(value.as_bytes(), $name, $($text => $name::$variant,)*).copied()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

text_enum!(RunMode {
    Incremental => "incremental",
    Final => "final",
    Rollback => "rollback",
    Verify => "verify",
});

text_enum!(RunStatus {
    Running => "running",
    Ok => "ok",
    Failed => "failed",
    Interrupted => "interrupted",
});

text_enum!(AccountPhase {
    Pending => "pending",
    Containers => "containers",
    Full => "full",
    Delta => "delta",
    Done => "done",
    Wiped => "wiped",
    Error => "error",
});

text_enum!(CursorMode {
    Full => "full",
    Pending => "pending",
    Checkpoint => "checkpoint",
    Log => "log",
    Share => "share",
    Finalized => "finalized",
    Started => "started",
});

impl CursorMode {
    pub const fn survives_completion(self) -> bool {
        matches!(
            self,
            CursorMode::Checkpoint | CursorMode::Log | CursorMode::Share
        )
    }
}

text_enum!(RegistryStatus {
    Ok => "ok",
    Dropped => "dropped",
    Error => "error",
});

text_enum!(MetaKey {
    ToolVersion => "tool_version",
    Edition => "edition",
    SourceDefHash => "source_def_hash",
    TargetDefHash => "target_def_hash",
    TargetSchemaVersion => "target_schema_version",
    AnswersHash => "answers_hash",
    Categories => "categories",
    CreatedAt => "created_at",
    FinalDone => "final_done",
    AcceptedErrors => "accepted_errors",
    FinalGeneration => "final_generation",
    SourceStore => "source_store",
    TargetClaim => "target_claim",
    ClaimGeneration => "claim_generation",
    ClaimGenerationPending => "claim_generation_pending",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(pub [u8; 16]);

impl ContentHash {
    pub fn of(bytes: &[u8]) -> Self {
        ContentHash(xxh3_128(bytes).to_be_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(ContentHash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub id: RunId,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub mode: RunMode,
    pub status: RunStatus,
    pub stats: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunStart {
    pub run_id: RunId,
    pub interrupted: Vec<RunId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    pub account_id: u32,
    pub phase: AccountPhase,
    pub checkpoint: Option<u64>,
    pub full_target: Option<u64>,
    pub attempts: u32,
    pub last_error: Option<Box<str>>,
    pub updated_at: i64,
    pub synced: CategorySet,
    pub full_run: Option<RunId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountUpdate {
    StartFull {
        account_id: u32,
        full_target: u64,
        run_id: RunId,
    },
    SetPhase {
        account_id: u32,
        phase: AccountPhase,
    },
    Complete {
        account_id: u32,
        checkpoint: u64,
        synced: CategorySet,
    },
    Fail {
        account_id: u32,
        error: Box<str>,
    },
    Wiped {
        account_id: u32,
        run_id: RunId,
    },
    Remove {
        account_id: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorRow {
    pub collection: u8,
    pub mode: CursorMode,
    pub last_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryState {
    pub key: RegistryKey,
    pub source_hash: ContentHash,
    pub target_hash: Option<ContentHash>,
    pub stored_hash: Option<ContentHash>,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryUpdate {
    pub key: RegistryKey,
    pub source_hash: ContentHash,
    pub target_hash: Option<ContentHash>,
    pub stored_hash: Option<ContentHash>,
    pub source_json: Vec<u8>,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRow {
    pub id: Option<i64>,
    pub run_id: RunId,
    pub severity: Severity,
    pub category: Box<str>,
    pub account_id: Option<u32>,
    pub object: Option<Box<str>>,
    pub object_id: Option<u64>,
    pub message: Box<str>,
    pub explains: Option<Explanation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailedDocument {
    pub account_id: u32,
    pub collection: Collection,
    pub document_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReportScope {
    #[default]
    All,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReportFilter {
    pub run_id: Option<RunId>,
    pub severity: Option<Severity>,
    pub category: Option<Box<str>>,
    pub account_id: Option<u32>,
    pub scope: ReportScope,
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportsAdded {
    pub rows: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportCount {
    pub severity: Severity,
    pub category: Box<str>,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseCount {
    pub phase: AccountPhase,
    pub count: u64,
}
