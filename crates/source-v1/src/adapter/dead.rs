/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write as _;

use common::storage::dav::DISPLAY_NAME_PROPERTY;
use model::{DeadPropertyRecord, DeadPropertyTag};
use store::{
    Store, ValueKey,
    write::{ValueClass, metadata::MetadataBuf, metadata::MetadataClass},
};
use types::{
    collection::Collection,
    metadata::{MetadataKinds, XmlAttribute, XmlName, XmlNode},
};

use super::{error::corrupt, keys::get};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DisplayName {
    Separate,
    DeadProperty,
}

#[derive(Debug, Default)]
pub(super) struct DavMetadata {
    pub(super) dead: DeadPropertyRecord,
    pub(super) display_name: Option<String>,
}

fn attributes(
    namespace: Option<&str>,
    lang: Option<&str>,
    attributes: &[XmlAttribute<'_>],
) -> Option<Box<str>> {
    let mut out = String::new();
    let mut push = |key: &str, value: &str| {
        if !out.is_empty() {
            out.push(' ');
        }
        let _ = write!(out, "{key}=\"{value}\"");
    };
    if let Some(namespace) = namespace {
        push("xmlns", namespace);
    }
    if let Some(lang) = lang {
        push("xml:lang", lang);
    }
    for attribute in attributes {
        push(&attribute.name.name, &attribute.value);
    }
    (!out.is_empty()).then(|| out.into_boxed_str())
}

fn push_children(tags: &mut Vec<DeadPropertyTag>, children: &[XmlNode<'_>]) {
    for child in children {
        match child {
            XmlNode::Text(text) => tags.push(DeadPropertyTag::Text(text.as_ref().into())),
            XmlNode::Element(element) => {
                tags.push(DeadPropertyTag::ElementStart {
                    name: element.name.name.as_ref().into(),
                    attrs: attributes(element.name.namespace.as_deref(), None, &element.attributes),
                });
                push_children(tags, &element.children);
                tags.push(DeadPropertyTag::ElementEnd);
            }
        }
    }
}

pub(super) async fn read(
    store: &Store,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    kinds: MetadataKinds,
    display_name: DisplayName,
) -> model::Result<DavMetadata> {
    let mut metadata = DavMetadata::default();
    if !kinds.intersects(MetadataKinds::DAV) {
        return Ok(metadata);
    }
    let Some(container) = get::<MetadataBuf>(
        store,
        ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            class: ValueClass::Metadata(MetadataClass::Shared),
        },
    )
    .await?
    else {
        return Ok(metadata);
    };
    let view = container.view();
    let tags = &mut metadata.dead.0;
    for (name, value) in view.dav() {
        if display_name == DisplayName::Separate && name == DISPLAY_NAME_PROPERTY {
            metadata.display_name = value.text().map(|text| text.into_owned());
            continue;
        }
        let value = value.to_value().ok_or_else(|| {
            corrupt(format!(
                "dead property {} of document {document_id}",
                label(&name)
            ))
        })?;
        tags.push(DeadPropertyTag::ElementStart {
            name: name.name.as_ref().into(),
            attrs: attributes(
                name.namespace.as_deref(),
                value.lang.as_deref(),
                &value.attributes,
            ),
        });
        push_children(tags, &value.children);
        tags.push(DeadPropertyTag::ElementEnd);
    }
    Ok(metadata)
}

fn label(name: &XmlName<'_>) -> String {
    format!(
        "{{{}}}{}",
        name.namespace.as_deref().unwrap_or_default(),
        name.name
    )
}
