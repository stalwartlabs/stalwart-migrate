/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ids::BlobHash;

#[derive(Debug, Clone, PartialEq)]
pub enum SpamModelRecord {
    Classifier(SpamClassifierModel),
    Trainer(Box<SpamTrainerModel>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpamModelKind {
    Classifier,
    Trainer,
}

impl SpamModelKind {
    pub const ALL: [SpamModelKind; 2] = [SpamModelKind::Classifier, SpamModelKind::Trainer];

    pub const fn as_str(self) -> &'static str {
        match self {
            SpamModelKind::Classifier => "spamClassifier",
            SpamModelKind::Trainer => "spamTrainer",
        }
    }

    pub fn from_object(object: &str) -> Option<Self> {
        SpamModelKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == object)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpamModelChange {
    Write(SpamModelRecord),
    Delete(SpamModelKind),
}

impl SpamModelChange {
    pub const fn kind(&self) -> SpamModelKind {
        match self {
            SpamModelChange::Write(record) => record.kind(),
            SpamModelChange::Delete(kind) => *kind,
        }
    }
}

impl SpamModelRecord {
    pub const fn kind(&self) -> SpamModelKind {
        match self {
            SpamModelRecord::Classifier(_) => SpamModelKind::Classifier,
            SpamModelRecord::Trainer(_) => SpamModelKind::Trainer,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        self.kind().as_str()
    }

    pub fn bit_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SpamModelRecord::Classifier(a), SpamModelRecord::Classifier(b)) => a.bit_eq(b),
            (SpamModelRecord::Trainer(a), SpamModelRecord::Trainer(b)) => a.bit_eq(b),
            _ => false,
        }
    }
}

fn f32_eq(a: f32, b: f32) -> bool {
    a.to_bits() == b.to_bits()
}

fn f64_eq(a: f64, b: f64) -> bool {
    a.to_bits() == b.to_bits()
}

fn f32s_eq(a: &[f32], b: &[f32]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| f32_eq(*a, *b))
}

impl SpamClassifierModel {
    fn bit_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                SpamClassifierModel::Fh {
                    parameters,
                    bias,
                    last_trained_at,
                },
                SpamClassifierModel::Fh {
                    parameters: other_parameters,
                    bias: other_bias,
                    last_trained_at: other_trained,
                },
            ) => {
                f32s_eq(parameters, other_parameters)
                    && f32_eq(*bias, *other_bias)
                    && last_trained_at == other_trained
            }
            (
                SpamClassifierModel::Ccfh {
                    parameters,
                    indicators,
                    bias,
                    last_trained_at,
                },
                SpamClassifierModel::Ccfh {
                    parameters: other_parameters,
                    indicators: other_indicators,
                    bias: other_bias,
                    last_trained_at: other_trained,
                },
            ) => {
                f32s_eq(parameters, other_parameters)
                    && f32s_eq(indicators, other_indicators)
                    && f32_eq(*bias, *other_bias)
                    && last_trained_at == other_trained
            }
            (SpamClassifierModel::Disabled, SpamClassifierModel::Disabled) => true,
            _ => false,
        }
    }
}

impl SpamTrainerModel {
    fn bit_eq(&self, other: &Self) -> bool {
        self.optimizer.bit_eq(&other.optimizer)
            && self.spam == other.spam
            && self.ham == other.ham
            && self.last_id == other.last_id
    }
}

impl SpamOptimizer {
    fn bit_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SpamOptimizer::Fh(a), SpamOptimizer::Fh(b)) => a.bit_eq(b),
            (
                SpamOptimizer::Ccfh {
                    weights,
                    indicators,
                },
                SpamOptimizer::Ccfh {
                    weights: other_weights,
                    indicators: other_indicators,
                },
            ) => weights.bit_eq(other_weights) && indicators.bit_eq(other_indicators),
            _ => false,
        }
    }
}

impl Ftrl {
    fn bit_eq(&self, other: &Self) -> bool {
        f64_eq(self.alpha, other.alpha)
            && f64_eq(self.beta, other.beta)
            && f64_eq(self.l1_ratio, other.l1_ratio)
            && f64_eq(self.l2_ratio, other.l2_ratio)
            && self.zn_bias.bit_eq(&other.zn_bias)
            && self.zn.len() == other.zn.len()
            && self.zn.iter().zip(&other.zn).all(|(a, b)| a.bit_eq(b))
    }
}

impl FtrlWeight {
    fn bit_eq(&self, other: &Self) -> bool {
        f32_eq(self.z, other.z) && f64_eq(self.n, other.n)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpamClassifierModel {
    Fh {
        parameters: Vec<f32>,
        bias: f32,
        last_trained_at: u64,
    },
    Ccfh {
        parameters: Vec<f32>,
        indicators: Vec<f32>,
        bias: f32,
        last_trained_at: u64,
    },
    Disabled,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpamTrainerModel {
    pub optimizer: SpamOptimizer,
    pub spam: SampleReservoir,
    pub ham: SampleReservoir,
    pub last_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpamOptimizer {
    Fh(Ftrl),
    Ccfh { weights: Ftrl, indicators: Ftrl },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ftrl {
    pub alpha: f64,
    pub beta: f64,
    pub l1_ratio: f64,
    pub l2_ratio: f64,
    pub zn: Vec<FtrlWeight>,
    pub zn_bias: FtrlWeight,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FtrlWeight {
    pub z: f32,
    pub n: f64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SampleReservoir {
    pub samples: Vec<TrainingSample>,
    pub total_seen: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrainingSample {
    pub blob_hash: BlobHash,
    pub account_id: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan_weights_compare_by_bits() {
        let model = |bias: f32| {
            SpamModelRecord::Classifier(SpamClassifierModel::Fh {
                parameters: vec![f32::NAN, 1.0],
                bias,
                last_trained_at: 7,
            })
        };
        assert!(model(f32::NAN).bit_eq(&model(f32::NAN)));
        assert!(!model(0.0).bit_eq(&model(-0.0)));
        assert!(!model(1.0).bit_eq(&model(2.0)));
    }
}
