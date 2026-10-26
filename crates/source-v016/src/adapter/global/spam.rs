/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY};
use model::{
    BlobHash, GlobalBatch, GlobalPage, Issue, IssueKind, RegistryKey, SampleReservoir, Severity,
    SpamClassifierModel, SpamModelRecord, SpamOptimizer, SpamTrainerModel, Subject, TrainingSample,
};
use store::{
    BlobStore, Deserialize,
    rkyv::{self, Archive},
    write::{AlignedBytes, Archive as StoreArchive},
};

use crate::adapter::error::trc_error;

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct FhClassifier {
    parameters: Vec<f32>,
    bias: f32,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct CcfhClassifier {
    parameters: Vec<f32>,
    indicators: Vec<f32>,
    bias: f32,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) enum SpamClassifier {
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

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct Zn {
    z: f32,
    n: f64,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct Ftrl {
    alpha: f64,
    beta: f64,
    l1_ratio: f64,
    l2_ratio: f64,
    zn: Vec<Zn>,
    zn_bias: Zn,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct FhTrainer {
    optimizer: Ftrl,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct CcfhTrainer {
    w_optimizer: Ftrl,
    i_optimizer: Ftrl,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) enum SpamTrainerClass {
    FtrlFh(Box<FhTrainer>),
    FtrlCfh(Box<CcfhTrainer>),
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct TrainingSampleArchive {
    hash: [u8; 32],
    account_id: u32,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct SampleReservoirClass {
    buffer: Vec<TrainingSampleArchive>,
    total_seen: u64,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct SampleReservoirArchive {
    spam: SampleReservoirClass,
    ham: SampleReservoirClass,
}

#[derive(Archive, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub(crate) struct SpamTrainer {
    trainer: SpamTrainerClass,
    reservoir: SampleReservoirArchive,
    last_id: u64,
}

fn floats(values: &[rkyv::Archived<f32>]) -> Vec<f32> {
    values.iter().map(|value| value.to_native()).collect()
}

fn ftrl(ftrl: &ArchivedFtrl) -> model::Ftrl {
    let weight = |zn: &ArchivedZn| model::FtrlWeight {
        z: zn.z.to_native(),
        n: zn.n.to_native(),
    };
    model::Ftrl {
        alpha: ftrl.alpha.to_native(),
        beta: ftrl.beta.to_native(),
        l1_ratio: ftrl.l1_ratio.to_native(),
        l2_ratio: ftrl.l2_ratio.to_native(),
        zn: ftrl.zn.iter().map(weight).collect(),
        zn_bias: weight(&ftrl.zn_bias),
    }
}

fn reservoir(class: &ArchivedSampleReservoirClass) -> SampleReservoir {
    SampleReservoir {
        samples: class
            .buffer
            .iter()
            .map(|sample| TrainingSample {
                blob_hash: BlobHash(sample.hash),
                account_id: sample.account_id.to_native(),
            })
            .collect(),
        total_seen: class.total_seen.to_native(),
    }
}

pub(crate) fn classifier(archived: &ArchivedSpamClassifier) -> SpamClassifierModel {
    match archived {
        ArchivedSpamClassifier::FhClassifier {
            classifier,
            last_trained_at,
        } => SpamClassifierModel::Fh {
            parameters: floats(&classifier.parameters),
            bias: classifier.bias.to_native(),
            last_trained_at: last_trained_at.to_native(),
        },
        ArchivedSpamClassifier::CcfhClassifier {
            classifier,
            last_trained_at,
        } => SpamClassifierModel::Ccfh {
            parameters: floats(&classifier.parameters),
            indicators: floats(&classifier.indicators),
            bias: classifier.bias.to_native(),
            last_trained_at: last_trained_at.to_native(),
        },
        ArchivedSpamClassifier::Disabled => SpamClassifierModel::Disabled,
    }
}

pub(crate) fn trainer(archived: &ArchivedSpamTrainer) -> SpamTrainerModel {
    SpamTrainerModel {
        optimizer: match &archived.trainer {
            ArchivedSpamTrainerClass::FtrlFh(trainer) => {
                SpamOptimizer::Fh(ftrl(&trainer.optimizer))
            }
            ArchivedSpamTrainerClass::FtrlCfh(trainer) => SpamOptimizer::Ccfh {
                weights: ftrl(&trainer.w_optimizer),
                indicators: ftrl(&trainer.i_optimizer),
            },
        },
        spam: reservoir(&archived.reservoir.spam),
        ham: reservoir(&archived.reservoir.ham),
        last_id: archived.last_id.to_native(),
    }
}

pub(crate) fn decode_classifier(data: &[u8]) -> trc::Result<SpamModelRecord> {
    let archive = <StoreArchive<AlignedBytes> as Deserialize>::deserialize(data)?;
    archive
        .unarchive_untrusted::<SpamClassifier>()
        .map(|archived| SpamModelRecord::Classifier(classifier(archived)))
}

pub(crate) fn decode_trainer(data: &[u8]) -> trc::Result<SpamModelRecord> {
    let archive = <StoreArchive<AlignedBytes> as Deserialize>::deserialize(data)?;
    archive
        .unarchive_untrusted::<SpamTrainer>()
        .map(|archived| SpamModelRecord::Trainer(Box::new(trainer(archived))))
}

type Decoder = fn(&[u8]) -> trc::Result<SpamModelRecord>;

const BLOBS: [(&[u8], &str, Decoder); 2] = [
    (SPAM_TRAINER_KEY, "spamTrainer", decode_trainer),
    (SPAM_CLASSIFIER_KEY, "spamClassifier", decode_classifier),
];

pub(super) async fn page(blob: &BlobStore) -> model::Result<GlobalPage> {
    let mut records = Vec::with_capacity(BLOBS.len());
    let mut issues = Vec::new();
    for (key, name, decode) in BLOBS {
        let Some(data) = blob.get_blob(key, 0..usize::MAX).await.map_err(trc_error)? else {
            continue;
        };
        match decode(&data) {
            Ok(record) => records.push(record),
            Err(err) => issues.push(Issue::new(
                Severity::Warning,
                IssueKind::Skipped,
                Subject::Registry(RegistryKey::new(name, 0)),
                format!("undecodable v0.16 spam model, v1 retrains it: {err}"),
            )),
        }
    }
    Ok(GlobalPage {
        batch: GlobalBatch::SpamModel(records),
        issues,
        next: None,
        resume: None,
    })
}
