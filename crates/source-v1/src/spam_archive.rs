/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY};
use model::{
    BlobHash, FtrlWeight, SampleReservoir, SpamClassifierModel, SpamModelRecord, SpamOptimizer,
    SpamTrainerModel, TrainingSample,
};
use store::{
    Deserialize, Serialize,
    rkyv::{self, Archive},
    write::{Archive as StoreArchive, ArchiveBytes, ArchiveCompression, Archiver},
};

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct FhClassifier {
    parameters: Vec<f32>,
    bias: f32,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct CcfhClassifier {
    parameters: Vec<f32>,
    indicators: Vec<f32>,
    bias: f32,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
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

impl ArchiveCompression for SpamClassifier {}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy)]
#[rkyv(crate = rkyv)]
struct Zn {
    z: f32,
    n: f64,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct Ftrl {
    alpha: f64,
    beta: f64,
    l1_ratio: f64,
    l2_ratio: f64,
    zn: Vec<Zn>,
    zn_bias: Zn,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct FhTrainer {
    optimizer: Ftrl,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct CcfhTrainer {
    w_optimizer: Ftrl,
    i_optimizer: Ftrl,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
enum SpamTrainerClass {
    FtrlFh(Box<FhTrainer>),
    FtrlCfh(Box<CcfhTrainer>),
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct Sample {
    hash: [u8; 32],
    account_id: u32,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct ReservoirClass {
    buffer: Vec<Sample>,
    total_seen: u64,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct Reservoir {
    spam: ReservoirClass,
    ham: ReservoirClass,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
struct SpamTrainer {
    trainer: SpamTrainerClass,
    reservoir: Reservoir,
    last_id: u64,
}

impl ArchiveCompression for SpamTrainer {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamBlob {
    Trainer,
    Classifier,
}

impl SpamBlob {
    pub const ALL: [SpamBlob; 2] = [SpamBlob::Trainer, SpamBlob::Classifier];

    pub const fn key(self) -> &'static [u8] {
        match self {
            SpamBlob::Trainer => SPAM_TRAINER_KEY,
            SpamBlob::Classifier => SPAM_CLASSIFIER_KEY,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            SpamBlob::Trainer => "spamTrainer",
            SpamBlob::Classifier => "spamClassifier",
        }
    }

    pub const fn of(record: &SpamModelRecord) -> SpamBlob {
        match record {
            SpamModelRecord::Trainer(_) => SpamBlob::Trainer,
            SpamModelRecord::Classifier(_) => SpamBlob::Classifier,
        }
    }
}

fn floats(values: &[rkyv::Archived<f32>]) -> Vec<f32> {
    values.iter().map(|value| value.to_native()).collect()
}

fn weight(zn: &ArchivedZn) -> FtrlWeight {
    FtrlWeight {
        z: zn.z.to_native(),
        n: zn.n.to_native(),
    }
}

fn ftrl(ftrl: &ArchivedFtrl) -> model::Ftrl {
    model::Ftrl {
        alpha: ftrl.alpha.to_native(),
        beta: ftrl.beta.to_native(),
        l1_ratio: ftrl.l1_ratio.to_native(),
        l2_ratio: ftrl.l2_ratio.to_native(),
        zn: ftrl.zn.iter().map(weight).collect(),
        zn_bias: weight(&ftrl.zn_bias),
    }
}

fn reservoir(class: &ArchivedReservoirClass) -> SampleReservoir {
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

fn classifier(archived: &ArchivedSpamClassifier) -> SpamClassifierModel {
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

fn trainer(archived: &ArchivedSpamTrainer) -> SpamTrainerModel {
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

pub fn decode(blob: SpamBlob, data: &[u8]) -> trc::Result<SpamModelRecord> {
    let archive = <StoreArchive<ArchiveBytes> as Deserialize>::deserialize(data)?;
    match blob {
        SpamBlob::Trainer => archive
            .unarchive_untrusted::<SpamTrainer>()
            .map(|archived| SpamModelRecord::Trainer(Box::new(trainer(archived)))),
        SpamBlob::Classifier => archive
            .unarchive_untrusted::<SpamClassifier>()
            .map(|archived| SpamModelRecord::Classifier(classifier(archived))),
    }
}

fn to_ftrl(ftrl: &model::Ftrl) -> Ftrl {
    let zn = |weight: &FtrlWeight| Zn {
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

fn to_reservoir(reservoir: &SampleReservoir) -> ReservoirClass {
    ReservoirClass {
        buffer: reservoir
            .samples
            .iter()
            .map(|sample| Sample {
                hash: sample.blob_hash.0,
                account_id: sample.account_id,
            })
            .collect(),
        total_seen: reservoir.total_seen,
    }
}

pub fn encode(record: &SpamModelRecord) -> trc::Result<Vec<u8>> {
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
                SpamOptimizer::Fh(ftrl) => SpamTrainerClass::FtrlFh(Box::new(FhTrainer {
                    optimizer: to_ftrl(ftrl),
                })),
                SpamOptimizer::Ccfh {
                    weights,
                    indicators,
                } => SpamTrainerClass::FtrlCfh(Box::new(CcfhTrainer {
                    w_optimizer: to_ftrl(weights),
                    i_optimizer: to_ftrl(indicators),
                })),
            },
            reservoir: Reservoir {
                spam: to_reservoir(&model.spam),
                ham: to_reservoir(&model.ham),
            },
            last_id: model.last_id,
        })
        .serialize(),
    }
}
