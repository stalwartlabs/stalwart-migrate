/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY};
use model::{
    Explanation, Issue, IssueKind, RegistryKey, SampleReservoir, Severity, SharedDeletes,
    SpamClassifierModel, SpamModelChange, SpamModelKind, SpamModelRecord, SpamOptimizer, Subject,
    WriteOutcome,
};
use store::{Serialize, rkyv, write::Archiver};

use crate::{error::trc_error, target::V016Target};

const SPAM_MODEL_ID: u64 = 0;
const FINAL_STEP_ONLY: &str =
    "the spam model is written only by the final step, after verification passes";
const SHARED_BLOB_STORE: &str = "the v0.16 blob store is external and may be shared with v1; the spam model was left in the v1 format, which v0.16 cannot load: delete the spamClassifier and spamTrainer keys so v0.16 retrains, or rerun with --allow-shared-deletes to write v0.16's model back";

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct FhClassifier {
    parameters: Vec<f32>,
    bias: f32,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct CcfhClassifier {
    parameters: Vec<f32>,
    indicators: Vec<f32>,
    bias: f32,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
enum SpamClassifier {
    FhClassifier {
        classifier: FhClassifier,
        last_trained_at: u64,
    },
    CcfhClassifier {
        classifier: CcfhClassifier,
        last_trained_at: u64,
    },
    Disabled,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct Zn {
    z: f32,
    n: f64,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct Ftrl {
    alpha: f64,
    beta: f64,
    l1_ratio: f64,
    l2_ratio: f64,
    zn: Vec<Zn>,
    zn_bias: Zn,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct FhTrainer {
    optimizer: Ftrl,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct CcfhTrainer {
    w_optimizer: Ftrl,
    i_optimizer: Ftrl,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
enum SpamTrainerClass {
    FtrlFh(Box<FhTrainer>),
    FtrlCfh(Box<CcfhTrainer>),
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct TrainingSample {
    hash: [u8; 32],
    account_id: u32,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct SampleReservoirClass {
    buffer: Vec<TrainingSample>,
    total_seen: u64,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct Reservoir {
    spam: SampleReservoirClass,
    ham: SampleReservoirClass,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct SpamTrainer {
    trainer: SpamTrainerClass,
    reservoir: Reservoir,
    last_id: u64,
}

fn ftrl(ftrl: &model::Ftrl) -> Ftrl {
    let zn = |weight: &model::FtrlWeight| Zn {
        z: weight.z,
        n: weight.n,
    };
    Ftrl {
        alpha: ftrl.alpha,
        beta: ftrl.beta,
        l1_ratio: ftrl.l1_ratio,
        l2_ratio: ftrl.l2_ratio,
        zn: ftrl.zn.iter().map(zn).collect(),
        zn_bias: zn(&ftrl.zn_bias),
    }
}

fn reservoir(reservoir: &SampleReservoir) -> SampleReservoirClass {
    SampleReservoirClass {
        buffer: reservoir
            .samples
            .iter()
            .map(|sample| TrainingSample {
                hash: sample.blob_hash.0,
                account_id: sample.account_id,
            })
            .collect(),
        total_seen: reservoir.total_seen,
    }
}

fn encode(record: &SpamModelRecord) -> trc::Result<Vec<u8>> {
    match record {
        SpamModelRecord::Classifier(model) => Archiver::new(match model {
            SpamClassifierModel::Fh {
                parameters,
                bias,
                last_trained_at,
            } => SpamClassifier::FhClassifier {
                classifier: FhClassifier {
                    parameters: parameters.clone(),
                    bias: *bias,
                },
                last_trained_at: *last_trained_at,
            },
            SpamClassifierModel::Ccfh {
                parameters,
                indicators,
                bias,
                last_trained_at,
            } => SpamClassifier::CcfhClassifier {
                classifier: CcfhClassifier {
                    parameters: parameters.clone(),
                    indicators: indicators.clone(),
                    bias: *bias,
                },
                last_trained_at: *last_trained_at,
            },
            SpamClassifierModel::Disabled => SpamClassifier::Disabled,
        })
        .serialize(),
        SpamModelRecord::Trainer(model) => Archiver::new(SpamTrainer {
            trainer: match &model.optimizer {
                SpamOptimizer::Fh(optimizer) => SpamTrainerClass::FtrlFh(Box::new(FhTrainer {
                    optimizer: ftrl(optimizer),
                })),
                SpamOptimizer::Ccfh {
                    weights,
                    indicators,
                } => SpamTrainerClass::FtrlCfh(Box::new(CcfhTrainer {
                    w_optimizer: ftrl(weights),
                    i_optimizer: ftrl(indicators),
                })),
            },
            reservoir: Reservoir {
                spam: reservoir(&model.spam),
                ham: reservoir(&model.ham),
            },
            last_id: model.last_id,
        })
        .serialize(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SpamBlob {
    Classifier,
    Trainer,
}

impl SpamBlob {
    const ALL: [SpamBlob; 2] = [SpamBlob::Trainer, SpamBlob::Classifier];

    const fn of(kind: SpamModelKind) -> SpamBlob {
        match kind {
            SpamModelKind::Classifier => SpamBlob::Classifier,
            SpamModelKind::Trainer => SpamBlob::Trainer,
        }
    }

    const fn key(self) -> &'static [u8] {
        match self {
            SpamBlob::Classifier => SPAM_CLASSIFIER_KEY,
            SpamBlob::Trainer => SPAM_TRAINER_KEY,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            SpamBlob::Classifier => "spamClassifier",
            SpamBlob::Trainer => "spamTrainer",
        }
    }
}

fn skipped(blob: SpamBlob, message: impl Into<Box<str>>) -> Issue {
    Issue::new(
        Severity::Warning,
        IssueKind::Skipped,
        Subject::Registry(RegistryKey::new(blob.as_str(), SPAM_MODEL_ID)),
        message,
    )
    .explaining(Explanation::Missing)
}

fn shared_change(blob: SpamBlob, backend: &str, change: SharedChange) -> Issue {
    let key = blob.as_str();
    Issue::new(
        Severity::Info,
        IssueKind::Changed,
        Subject::Registry(RegistryKey::new(key, SPAM_MODEL_ID)),
        match change {
            SharedChange::Overwritten => format!(
                "the {key} key in the external {backend} blob store was overwritten in the v0.16 format; v1 sharing this store cannot load it"
            ),
            SharedChange::Deleted => format!(
                "the {key} key in the external {backend} blob store was deleted; v0.16 and v1 sharing this store retrain it"
            ),
        },
    )
}

#[derive(Clone, Copy)]
enum SharedChange {
    Overwritten,
    Deleted,
}

impl V016Target {
    pub(crate) fn defer_spam_model(records: &[SpamModelRecord]) -> Vec<Issue> {
        records
            .iter()
            .map(|record| skipped(SpamBlob::of(record.kind()), FINAL_STEP_ONLY))
            .collect()
    }

    pub(crate) async fn apply_spam_model(
        &self,
        changes: &[SpamModelChange],
    ) -> model::Result<WriteOutcome> {
        if changes.is_empty() {
            return Ok(WriteOutcome::ok());
        }
        let backend = self.external_blob_store().await?;
        if backend.is_some() && self.shared_deletes == SharedDeletes::Forbid {
            return Ok(WriteOutcome {
                issues: SpamBlob::ALL
                    .into_iter()
                    .filter(|blob| {
                        changes
                            .iter()
                            .any(|change| SpamBlob::of(change.kind()) == *blob)
                    })
                    .map(|blob| skipped(blob, SHARED_BLOB_STORE))
                    .collect(),
            });
        }
        let server = self.server()?;
        let blob_store = server.blob_store();
        let mut issues = Vec::new();
        for change in changes {
            let blob = SpamBlob::of(change.kind());
            let encoded = match change {
                SpamModelChange::Write(record) => match encode(record) {
                    Ok(data) => Some(data),
                    Err(err) => {
                        issues.push(skipped(
                            blob,
                            format!("cannot encode the v0.16 spam model, v0.16 retrains it: {err}"),
                        ));
                        None
                    }
                },
                SpamModelChange::Delete(_) => None,
            };
            match (encoded, backend) {
                (Some(data), _) => {
                    blob_store
                        .delete_blob(blob.key())
                        .await
                        .map_err(trc_error)?;
                    blob_store
                        .put_blob(blob.key(), &data, server.core.email.compression)
                        .await
                        .map_err(trc_error)?;
                    if let Some(backend) = backend {
                        issues.push(shared_change(blob, backend, SharedChange::Overwritten));
                    }
                }
                (None, None) => {
                    blob_store
                        .delete_blob(blob.key())
                        .await
                        .map_err(trc_error)?;
                }
                (None, Some(backend)) => {
                    if blob_store
                        .get_blob(blob.key(), 0..usize::MAX)
                        .await
                        .map_err(trc_error)?
                        .is_some()
                    {
                        blob_store
                            .delete_blob(blob.key())
                            .await
                            .map_err(trc_error)?;
                        issues.push(shared_change(blob, backend, SharedChange::Deleted));
                    }
                }
            }
        }
        Ok(WriteOutcome { issues })
    }
}
