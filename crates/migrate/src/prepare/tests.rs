/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::{self, BufRead, Write};

use mapping::{
    Answers, Instance, Mapping, ObjectKey, Options, Outcome, SourceObject, TargetObject,
};
use serde_json::json;

use super::{Confirmation, Prepare, Prepared, Terminal, load_answers, summary, write_outputs};

struct Scripted<'x> {
    input: &'x [u8],
    output: Vec<u8>,
    secrets: usize,
}

impl Terminal for Scripted<'_> {
    fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
        self.input.read_line(buf)
    }

    fn read_secret(&mut self, buf: &mut String) -> io::Result<usize> {
        self.secrets += 1;
        self.input.read_line(buf)
    }

    fn output(&mut self) -> &mut dyn Write {
        &mut self.output
    }
}

fn objects() -> Vec<SourceObject> {
    vec![
        SourceObject {
            key: ObjectKey::singleton("x:Http"),
            value: json!({"useXForwarded": true}),
        },
        SourceObject {
            key: ObjectKey::with_id("x:Domain", 1),
            value: json!({"name": "example.org"}),
        },
    ]
}

fn script() -> Vec<u8> {
    std::iter::repeat_n(b'\n', 200).collect()
}

#[test]
fn interactive_prepare_answers_every_question() {
    let mapping = Mapping::embedded().expect("mapping");
    let prepare = Prepare {
        mapping: &mapping,
        options: Options::default(),
        objects: objects(),
    };
    let mut answers = Answers::default();
    assert!(!prepare.validate(&answers).is_complete());

    let input = script();
    let mut terminal = Scripted {
        input: &input,
        output: Vec::new(),
        secrets: 0,
    };
    let (prepared, confirmation) = prepare
        .interactive(&mut answers, &mut terminal)
        .expect("prepare");
    let output = String::from_utf8(terminal.output).expect("utf8");
    assert_eq!(confirmation, Confirmation::Write, "{output}");
    assert!(prepared.is_complete(), "{:?}\n{output}", prepared.problems);
    assert!(prepared.answered >= 2);
    assert!(!output.contains("Target data store"));
    assert!(!output.contains("v1 edition"));
    assert!(!output.contains("Blob store"));
    assert!(!output.contains("Per setting overrides"));
    assert!(prepare.validate(&answers).is_complete());

    let dir = tempfile::tempdir().expect("tempdir");
    write_outputs(dir.path(), &mapping, &answers, &prepared).expect("write");
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(dir.path().join(super::ANSWERS_FILE))
            .expect("metadata")
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
    let loaded = load_answers(dir.path()).expect("load");
    assert!(prepare.validate(&loaded).is_complete());
    let report = std::fs::read_to_string(dir.path().join(super::REPORT_FILE)).expect("report");
    assert!(report.contains("objects to write"));
}

#[test]
fn closed_input_is_an_error() {
    let mapping = Mapping::embedded().expect("mapping");
    let prepare = Prepare {
        mapping: &mapping,
        options: Options::default(),
        objects: objects(),
    };
    let mut terminal = Scripted {
        input: b"",
        output: Vec::new(),
        secrets: 0,
    };
    let err = prepare
        .interactive(&mut Answers::default(), &mut terminal)
        .expect_err("eof");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn missing_answers_file_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(load_answers(dir.path()).expect("load"), Answers::default());
}

// The plan names the spam model overwrite only when the v1 blob store is external.
#[test]
fn external_blob_store_announces_the_spam_model_overwrite() {
    let prepared = |backend: &str| Prepared {
        outcome: Outcome {
            objects: vec![TargetObject {
                source: ObjectKey::new("BlobStore", Instance::Singleton),
                key: ObjectKey::new("x:BlobStore", Instance::Singleton),
                value: json!({"@type": backend}),
            }],
            ..Default::default()
        },
        problems: Vec::new(),
        answered: 0,
    };
    let text = summary(&prepared("S3"));
    assert!(
        text.contains("overwrites the spam classifier and trainer models under their fixed keys in the external S3 blob store"),
        "{text}"
    );
    assert!(
        text.contains("a later rollback into this blob store refuses to start unless it is told to write the v0.16 model back (--allow-shared-deletes) or to keep the v1 model (--keep-v1-spam-model)"),
        "{text}"
    );
    assert!(!summary(&prepared("Default")).contains("spam"));
}
