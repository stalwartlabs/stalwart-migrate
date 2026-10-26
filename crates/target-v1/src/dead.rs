/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, mem};

use common::{
    Server,
    storage::{
        dav::{DISPLAY_NAME_PROPERTY, FilePresence},
        metadata::{ContainerChange, MetadataLog, MetadataWrite},
    },
};
use model::{DeadPropertyRecord, DeadPropertyTag, Explanation, IssueKind, Severity, WriteOutcome};
use store::write::{BatchBuilder, PendingId};
use types::{
    collection::Collection,
    metadata::{
        MetadataBuilder, MetadataKinds, MetadataScope, XmlAttribute, XmlElement, XmlName, XmlNode,
        XmlValue,
    },
};

use crate::{error::trc_error, mail::issue, target::V1Target};

const XMLNS: &str = "xmlns";
const XML_LANG: &str = "xml:lang";
const XML_PREFIX: &str = "xml";
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const LANG: &str = "lang";

pub(crate) struct DeadWrite {
    write: Option<MetadataWrite>,
    pub(crate) kinds: MetadataKinds,
    pub(crate) file_presence: FilePresence,
}

impl DeadWrite {
    pub(crate) fn build(self, document_id: u32, batch: &mut BatchBuilder) -> model::Result<()> {
        if let Some(write) = self.write {
            write
                .build(PendingId::Assigned(document_id), batch)
                .map_err(trc_error)?;
        }
        Ok(())
    }
}

struct Attributes {
    namespace: Option<String>,
    lang: Option<String>,
    attributes: Vec<XmlAttribute<'static>>,
}

fn xml_attribute(name: &str, value: String) -> XmlAttribute<'static> {
    XmlAttribute {
        name: XmlName::owned(Some(XML_NAMESPACE.to_string()), name.to_string()),
        value: Cow::Owned(value),
    }
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some((before, after)) = rest.split_once('&') {
        out.push_str(before);
        let decoded = after.split_once(';').and_then(|(entity, tail)| {
            let ch = hashify::map!(entity.as_bytes(), char,
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
            )
            .copied()
            .or_else(|| {
                entity
                    .strip_prefix("#x")
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                    .and_then(char::from_u32)
            })?;
            Some((ch, tail))
        });
        match decoded {
            Some((ch, tail)) => {
                out.push(ch);
                rest = tail;
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_attributes(attrs: Option<&str>, unbound: &mut Vec<String>) -> Attributes {
    let mut result = Attributes {
        namespace: None,
        lang: None,
        attributes: Vec::new(),
    };
    let mut rest = attrs.unwrap_or_default().trim_start();
    while let Some((key, after)) = rest.split_once("=\"") {
        let Some((value, tail)) = split_value(after) else {
            break;
        };
        let value = unescape(value);
        match key.trim() {
            XMLNS => result.namespace = (!value.is_empty()).then_some(value),
            XML_LANG => result.lang = Some(value),
            key => match key.split_once(':') {
                None => result.attributes.push(XmlAttribute {
                    name: XmlName::owned(None, key.to_string()),
                    value: Cow::Owned(value),
                }),
                Some((XML_PREFIX, local)) => result.attributes.push(xml_attribute(local, value)),
                Some(_) => unbound.push(key.to_string()),
            },
        }
        rest = tail.trim_start();
    }
    result
}

fn split_value(after: &str) -> Option<(&str, &str)> {
    after.match_indices('"').find_map(|(pos, _)| {
        let tail = after.get(pos + 1..)?;
        if is_value_end(tail) {
            Some((after.get(..pos)?, tail))
        } else {
            None
        }
    })
}

fn is_value_end(tail: &str) -> bool {
    match tail.strip_prefix(' ') {
        Some(next) => {
            let key_len = next.bytes().take_while(|byte| is_name_byte(*byte)).count();
            key_len > 0
                && next
                    .get(key_len..)
                    .is_some_and(|rest| rest.starts_with("=\""))
        }
        None => tail.trim_end().is_empty(),
    }
}

fn is_name_byte(byte: u8) -> bool {
    !byte.is_ascii_whitespace() && !matches!(byte, b'"' | b'\'' | b'=' | b'<' | b'>' | b'&')
}

fn dead_label(name: &XmlName<'_>) -> String {
    format!(
        "{{{}}}{}",
        name.namespace.as_deref().unwrap_or_default(),
        name.name
    )
}

enum Frame {
    Property {
        name: XmlName<'static>,
        value: XmlValue<'static>,
    },
    Element(XmlElement<'static>),
}

fn push_node(stack: &mut [Frame], node: XmlNode<'static>) {
    match stack.last_mut() {
        Some(Frame::Property { value, .. }) => value.children.push(node),
        Some(Frame::Element(element)) => element.children.push(node),
        None => {}
    }
}

type Property = (XmlName<'static>, XmlValue<'static>, Vec<String>);

fn properties(record: &DeadPropertyRecord) -> Vec<Property> {
    let mut properties = Vec::new();
    let mut unbound = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    for tag in &record.0 {
        match tag {
            DeadPropertyTag::ElementStart { name, attrs } => {
                let mut attributes = parse_attributes(attrs.as_deref(), &mut unbound);
                let xml_name = XmlName::owned(attributes.namespace, name.to_string());
                if stack.is_empty() {
                    stack.push(Frame::Property {
                        name: xml_name,
                        value: XmlValue {
                            lang: attributes.lang.map(Cow::Owned),
                            attributes: attributes.attributes,
                            children: Vec::new(),
                        },
                    });
                } else {
                    if let Some(lang) = attributes.lang.take() {
                        attributes.attributes.push(xml_attribute(LANG, lang));
                    }
                    stack.push(Frame::Element(XmlElement {
                        name: xml_name,
                        prefix: None,
                        attributes: attributes.attributes,
                        children: Vec::new(),
                    }));
                }
            }
            DeadPropertyTag::Text(text) => {
                push_node(&mut stack, XmlNode::Text(Cow::Owned(text.to_string())));
            }
            DeadPropertyTag::ElementEnd => match stack.pop() {
                Some(Frame::Property { name, value }) => {
                    properties.push((name, value, mem::take(&mut unbound)))
                }
                Some(Frame::Element(element)) => push_node(&mut stack, XmlNode::Element(element)),
                None => {}
            },
        }
    }
    properties
}

impl V1Target {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn dead_write(
        &self,
        server: &Server,
        account_id: u32,
        collection: Collection,
        model_collection: model::Collection,
        document_id: u32,
        record: &DeadPropertyRecord,
        display_name: Option<&str>,
        load_current: bool,
        outcome: &mut WriteOutcome,
    ) -> model::Result<Option<DeadWrite>> {
        let current = if load_current {
            server
                .metadata_container(account_id, collection, document_id)
                .await
                .map_err(trc_error)?
        } else {
            None
        };
        if record.is_empty() && display_name.is_none() && current.is_none() {
            return Ok(None);
        }
        let limits = server.core.metadata.limits();
        let mut builder = MetadataBuilder::new();
        for (name, value, unbound) in properties(record) {
            for attribute in unbound {
                outcome.issues.push(issue(
                    Severity::Warning,
                    IssueKind::Dropped,
                    model_collection,
                    document_id,
                    format!(
                        "dead property {}: attribute {attribute} was dropped, v0.16 did not store the namespace of its prefix",
                        dead_label(&name)
                    ),
                )
                .explaining(Explanation::DeadAttribute(
                    dead_label(&name).into(),
                    attribute.into(),
                )));
            }
            match builder.set_dav(name.clone(), &value) {
                Ok(size) if limits.check_entry_size(size).is_ok() => {}
                Ok(size) => {
                    builder.remove_dav(&name);
                    outcome.issues.push(issue(
                        Severity::Warning,
                        IssueKind::Dropped,
                        model_collection,
                        document_id,
                        format!(
                            "dead property {} has {size} bytes, above the v1 limit (raise Metadata.maxEntrySize to keep it)",
                            dead_label(&name)
                        ),
                    )
                    .explaining(Explanation::DeadProperty(dead_label(&name).into())));
                }
                Err(err) => outcome.issues.push(
                    issue(
                        Severity::Warning,
                        IssueKind::Dropped,
                        model_collection,
                        document_id,
                        format!(
                            "dead property {} is not valid v1 metadata: {err}",
                            dead_label(&name)
                        ),
                    )
                    .explaining(Explanation::DeadProperty(dead_label(&name).into())),
                ),
            }
        }
        if let Some(display_name) = display_name {
            let value = XmlValue {
                children: vec![XmlNode::Text(Cow::Owned(display_name.to_string()))],
                ..Default::default()
            };
            if let Err(err) = builder.set_dav(DISPLAY_NAME_PROPERTY, &value) {
                outcome.issues.push(
                    issue(
                        Severity::Warning,
                        IssueKind::Dropped,
                        model_collection,
                        document_id,
                        format!("display name is not valid v1 metadata: {err}"),
                    )
                    .explaining(Explanation::DisplayName),
                );
            }
        }
        let mut next = builder.encode();
        if let Some(encoded) = &next
            && let Err(err) = limits.check_edit(MetadataScope::Shared, 0, 0, encoded)
        {
            outcome.issues.push(issue(
                Severity::Warning,
                IssueKind::Dropped,
                model_collection,
                document_id,
                format!(
                    "dead properties exceed the v1 container limits and were dropped (raise the Metadata limits to keep them): {err:?}"
                ),
            )
            .explaining(Explanation::DeadProperties));
            next = None;
        }
        let kinds = next
            .as_ref()
            .map_or(MetadataKinds::NONE, |encoded| encoded.kinds());
        let file_presence = next.as_ref().map_or(FilePresence::NONE, |encoded| {
            FilePresence::from_view(&encoded.view())
        });
        let edit = builder.edit();
        drop(builder);
        let write = match ContainerChange::new(current.as_ref(), next, edit) {
            Some(change) => {
                let owner = server.account(account_id).await.map_err(trc_error)?;
                Some(change.into_write(&owner, collection, MetadataLog::None))
            }
            None => None,
        };
        Ok(Some(DeadWrite {
            write,
            kinds,
            file_presence,
        }))
    }
}
