/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Write as _};

use model::{
    AclRecord, AddressBookRecord, CalendarEventRecord, CalendarRecord, Collection, ContactRecord,
    DavNameRecord, DeadPropertyRecord, DeadPropertyTag, EmailRecord, EventNotificationRecord,
    EventPreferencesRecord, Explanation, FileNodeRecord, IdentityRecord, LogChanges, LogEntry,
    MailboxRecord, Record, RecordBatch, SieveRecord, SubmissionRecord, TimeZoneRecord,
    VanishedRecord,
};
use rustc_hash::FxHashMap;
use source_v1::{same_icalendar, same_vcard};
use types::keyword::Keyword;

use super::explain::Explanations;

const MAX_RECEIVED_AT: u64 = u32::MAX as u64;
const MAX_LISTED_KEYWORDS: usize = 5;
const MAX_KEYWORD_CHARS: usize = 64;

pub(super) type Fields = Vec<&'static str>;

pub(super) trait Compare: Record + Clone {
    fn compare(&self, target: &Self, fields: &mut Fields);

    fn explain(&mut self, _target: &Self, _explanation: &Explanation) {}

    fn describe(&self, _target: &Self, _detail: &mut String) {}
}

fn check(fields: &mut Fields, name: &'static str, equal: bool) {
    if !equal {
        fields.push(name);
    }
}

fn sorted<T: Ord + Clone>(items: &[T]) -> Vec<T> {
    let mut items = items.to_vec();
    items.sort_unstable();
    items
}

fn same_set<T: Ord + Clone>(left: &[T], right: &[T]) -> bool {
    left == right || (left.len() == right.len() && sorted(left) == sorted(right))
}

fn keyword_set(keywords: &[Box<str>]) -> Vec<Box<str>> {
    let mut keywords: Vec<Box<str>> = keywords
        .iter()
        .map(|keyword| Keyword::parse(keyword))
        .filter(|keyword| !matches!(keyword, Keyword::HasAttachment | Keyword::HasNoAttachment))
        .map(|keyword| Box::from(keyword.as_str()))
        .collect();
    keywords.sort_unstable();
    keywords.dedup();
    keywords
}

fn describe_keywords(source: &[Box<str>], target: &[Box<str>], detail: &mut String) {
    let source = keyword_set(source);
    let target = keyword_set(target);
    if source == target {
        return;
    }
    detail.push_str(" (keywords only in the source: ");
    list_keywords(
        detail,
        source
            .iter()
            .filter(|keyword| target.binary_search(keyword).is_err()),
    );
    detail.push_str("; only in the target: ");
    list_keywords(
        detail,
        target
            .iter()
            .filter(|keyword| source.binary_search(keyword).is_err()),
    );
    detail.push(')');
}

fn list_keywords<'x>(detail: &mut String, mut keywords: impl Iterator<Item = &'x Box<str>>) {
    let mut listed = 0;
    while let Some(keyword) = keywords.next() {
        if listed == MAX_LISTED_KEYWORDS {
            let _ = write!(detail, " and {} more", keywords.count() + 1);
            return;
        }
        if listed > 0 {
            detail.push_str(", ");
        }
        listed += 1;
        let (shown, ellipsis) = match keyword.char_indices().nth(MAX_KEYWORD_CHARS) {
            Some((end, _)) => (keyword.get(..end).unwrap_or_default(), "..."),
            None => (&**keyword, ""),
        };
        let _ = write!(detail, "\"{}{ellipsis}\"", shown.escape_debug());
    }
    if listed == 0 {
        detail.push_str("none");
    }
}

fn same_acls(left: &[AclRecord], right: &[AclRecord]) -> bool {
    if left == right {
        return true;
    }
    let key = |acl: &AclRecord| (acl.account_id, acl.grants);
    let mut left: Vec<_> = left.iter().map(key).collect();
    let mut right: Vec<_> = right.iter().map(key).collect();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

fn same_names(left: &[DavNameRecord], right: &[DavNameRecord]) -> bool {
    if left == right {
        return true;
    }
    let key = |name: &DavNameRecord| (name.parent_id, name.name.clone());
    let mut left: Vec<_> = left.iter().map(key).collect();
    let mut right: Vec<_> = right.iter().map(key).collect();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

#[derive(Debug, PartialEq, Eq)]
enum DeadTag<'x> {
    Start {
        name: &'x str,
        namespace: Cow<'x, str>,
        attributes: Vec<(&'x str, Cow<'x, str>)>,
    },
    End,
    Text(&'x str),
}

const XMLNS: &str = "xmlns";
const XML_PREFIX: &str = "xml:";

fn unescape(value: &str) -> Cow<'_, str> {
    if !value.contains('&') {
        return Cow::Borrowed(value);
    }
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
    Cow::Owned(out)
}

fn dead_attributes(attrs: Option<&str>) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = attrs.unwrap_or_default().trim_start();
    while let Some((key, after)) = rest.split_once("=\"") {
        let Some((value, tail)) = after.split_once('"') else {
            break;
        };
        out.push((key.trim(), value));
        rest = tail.trim_start();
    }
    out.sort_unstable();
    out
}

fn dead_tags(record: &DeadPropertyRecord) -> Vec<DeadTag<'_>> {
    let mut namespaces: Vec<Cow<'_, str>> = Vec::new();
    let mut tags = Vec::with_capacity(record.0.len());
    for tag in &record.0 {
        match tag {
            DeadPropertyTag::ElementStart { name, attrs } => {
                let mut namespace = namespaces.last().cloned().unwrap_or_default();
                let mut attributes = Vec::new();
                for (key, value) in dead_attributes(attrs.as_deref()) {
                    if key == XMLNS {
                        namespace = unescape(value);
                    } else {
                        attributes
                            .push((key.strip_prefix(XML_PREFIX).unwrap_or(key), unescape(value)));
                    }
                }
                attributes.sort_unstable();
                namespaces.push(namespace.clone());
                tags.push(DeadTag::Start {
                    name,
                    namespace,
                    attributes,
                });
            }
            DeadPropertyTag::ElementEnd => {
                namespaces.pop();
                tags.push(DeadTag::End);
            }
            DeadPropertyTag::Text(text) if text.trim().is_empty() => {}
            DeadPropertyTag::Text(text) => tags.push(DeadTag::Text(text)),
        }
    }
    tags
}

fn dead_property_key<'x>(tags: &'x [DeadTag<'x>]) -> Option<(&'x str, &'x str)> {
    match tags.first() {
        Some(DeadTag::Start {
            name, namespace, ..
        }) => Some((namespace.as_ref(), name)),
        _ => None,
    }
}

fn dead_properties<'x>(tags: &'x [DeadTag<'x>]) -> Vec<&'x [DeadTag<'x>]> {
    let mut depth = 0usize;
    let mut properties: Vec<&[DeadTag<'_>]> = tags
        .split_inclusive(|tag| {
            match tag {
                DeadTag::Start { .. } => depth += 1,
                DeadTag::End => depth = depth.saturating_sub(1),
                DeadTag::Text(_) => {}
            }
            depth == 0
        })
        .collect();
    properties.sort_by(|left, right| dead_property_key(left).cmp(&dead_property_key(right)));
    properties
}

fn same_dead(left: &DeadPropertyRecord, right: &DeadPropertyRecord) -> bool {
    if left.0 == right.0 {
        return true;
    }
    let (left, right) = (dead_tags(left), dead_tags(right));
    left == right || dead_properties(&left) == dead_properties(&right)
}

fn dead_label_matches(name: &str, attrs: Option<&str>, label: &str) -> bool {
    let namespace = dead_attributes(attrs)
        .into_iter()
        .find_map(|(key, value)| (key == XMLNS).then(|| unescape(value)))
        .unwrap_or_default();
    label
        .strip_prefix('{')
        .and_then(|rest| rest.strip_prefix(namespace.as_ref()))
        .and_then(|rest| rest.strip_prefix('}'))
        == Some(name)
}

fn remove_dead(record: &mut DeadPropertyRecord, label: &str) {
    let mut depth = 0usize;
    let mut removing = false;
    record.0.retain(|tag| match tag {
        DeadPropertyTag::ElementStart { name, attrs } => {
            if depth == 0 {
                removing = dead_label_matches(name, attrs.as_deref(), label);
            }
            depth += 1;
            !removing
        }
        DeadPropertyTag::ElementEnd => {
            depth = depth.saturating_sub(1);
            let keep = !removing;
            if depth == 0 {
                removing = false;
            }
            keep
        }
        DeadPropertyTag::Text(_) => !removing,
    });
}

fn remove_dead_attribute(record: &mut DeadPropertyRecord, label: &str, attribute: &str) {
    let mut depth = 0usize;
    let mut inside = false;
    for tag in &mut record.0 {
        match tag {
            DeadPropertyTag::ElementStart { name, attrs } => {
                if depth == 0 {
                    inside = dead_label_matches(name, attrs.as_deref(), label);
                }
                depth += 1;
                if inside && let Some(current) = attrs {
                    let pairs = dead_attributes(Some(current));
                    if pairs.iter().any(|(key, _)| *key == attribute) {
                        let mut kept = String::with_capacity(current.len());
                        for (key, value) in pairs.into_iter().filter(|(key, _)| *key != attribute) {
                            if !kept.is_empty() {
                                kept.push(' ');
                            }
                            let _ = write!(kept, "{key}=\"{value}\"");
                        }
                        *attrs = (!kept.is_empty()).then(|| kept.into());
                    }
                }
            }
            DeadPropertyTag::ElementEnd => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    inside = false;
                }
            }
            DeadPropertyTag::Text(_) => {}
        }
    }
}

fn explain_dead(source: &mut DeadPropertyRecord, explanation: &Explanation) {
    match explanation {
        Explanation::DeadProperty(label) => remove_dead(source, label),
        Explanation::DeadAttribute(label, attribute) => {
            remove_dead_attribute(source, label, attribute)
        }
        Explanation::DeadProperties => source.0.clear(),
        _ => {}
    }
}

fn truncated<T: Ord + Clone>(source: &mut Vec<T>, target: &[T], limit: u32) {
    if usize::try_from(limit).is_ok_and(|limit| limit == target.len())
        && target.len() < source.len()
        && target.iter().all(|item| source.contains(item))
    {
        *source = target.to_vec();
    }
}

fn default_alert_accounts(preferences: &[EventPreferencesRecord]) -> Vec<u32> {
    let mut accounts: Vec<u32> = preferences
        .iter()
        .filter(|preferences| preferences.flags & EventPreferencesRecord::USE_DEFAULT_ALERTS != 0)
        .map(|preferences| preferences.account_id)
        .collect();
    accounts.sort_unstable();
    accounts.dedup();
    accounts
}

const EVENT_FLAGS: u16 = CalendarEventRecord::INVITE_SELF
    | CalendarEventRecord::INVITE_OTHERS
    | CalendarEventRecord::HIDE_ATTENDEES
    | CalendarEventRecord::DRAFT;
const NOTIFICATION_FLAGS: u16 =
    EventNotificationRecord::IS_DRAFT | EventNotificationRecord::IS_CHANGE;

impl Compare for MailboxRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "name", self.name == target.name);
        check(fields, "parent", self.parent_id == target.parent_id);
        check(fields, "role", self.role == target.role);
        check(fields, "sortOrder", self.sort_order == target.sort_order);
        check(
            fields,
            "uidValidity",
            self.uid_validity == target.uid_validity,
        );
        check(
            fields,
            "subscribers",
            same_set(&self.subscribers, &target.subscribers),
        );
        check(fields, "acls", same_acls(&self.acls, &target.acls));
    }

    fn explain(&mut self, target: &Self, explanation: &Explanation) {
        if *explanation == Explanation::MailboxRole && target.role.is_none() {
            self.role = None;
        }
    }
}

impl Compare for EmailRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "threadId", self.thread_id == target.thread_id);
        check(fields, "changeId", self.change_id == target.change_id);
        check(fields, "receivedAt", self.received_at == target.received_at);
        check(
            fields,
            "keywords",
            keyword_set(&self.keywords) == keyword_set(&target.keywords),
        );
        check(
            fields,
            "mailboxes",
            same_set(&self.mailboxes, &target.mailboxes),
        );
        check(fields, "blobHash", self.blob_hash == target.blob_hash);
        check(
            fields,
            "headers",
            self.body_offset == target.body_offset && self.extra_headers == target.extra_headers,
        );
        check(fields, "size", self.size == target.size);
    }

    fn explain(&mut self, target: &Self, explanation: &Explanation) {
        match explanation {
            Explanation::Keyword(keyword) => self
                .keywords
                .retain(|item| !item.eq_ignore_ascii_case(keyword)),
            Explanation::Keywords(limit) => {
                let mut keywords = keyword_set(&self.keywords);
                truncated(&mut keywords, &keyword_set(&target.keywords), *limit);
                self.keywords = keywords;
            }
            Explanation::Mailboxes(limit) => {
                truncated(&mut self.mailboxes, &target.mailboxes, *limit)
            }
            Explanation::ExtraHeaders if target.extra_headers.is_empty() => {
                let removed = u32::try_from(self.extra_headers.len()).unwrap_or(u32::MAX);
                self.size = self.size.saturating_sub(removed);
                self.extra_headers = Default::default();
            }
            Explanation::ReceivedAt => self.received_at = self.received_at.min(MAX_RECEIVED_AT),
            _ => {}
        }
    }

    fn describe(&self, target: &Self, detail: &mut String) {
        describe_keywords(&self.keywords, &target.keywords, detail);
    }
}

impl Compare for IdentityRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "identity", self == target);
    }
}

impl Compare for SubmissionRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "submission", self == target);
    }
}

impl Compare for SieveRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "name", self.name == target.name);
        check(fields, "vacation", self.vacation == target.vacation);
    }
}

impl Compare for CalendarRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "name", self.name == target.name);
        check(
            fields,
            "preferences",
            self.preferences == target.preferences,
        );
        check(fields, "acls", same_acls(&self.acls, &target.acls));
        check(
            fields,
            "supportedComponents",
            self.supported_components == target.supported_components,
        );
        check(
            fields,
            "deadProperties",
            same_dead(&self.dead_properties, &target.dead_properties),
        );
        check(
            fields,
            "timestamps",
            self.created == target.created && self.modified == target.modified,
        );
    }

    fn explain(&mut self, _target: &Self, explanation: &Explanation) {
        match explanation {
            Explanation::TimeZone(account_id) => {
                for preferences in &mut self.preferences {
                    if preferences.account_id == *account_id {
                        preferences.time_zone = TimeZoneRecord::Default;
                    }
                }
            }
            Explanation::DefaultAlert(account_id, id) => {
                for preferences in &mut self.preferences {
                    if preferences.account_id == *account_id {
                        preferences
                            .default_alerts
                            .retain(|alert| alert.id.as_str() != &**id);
                    }
                }
            }
            _ => explain_dead(&mut self.dead_properties, explanation),
        }
    }
}

impl Compare for AddressBookRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "name", self.name == target.name);
        check(
            fields,
            "preferences",
            self.preferences == target.preferences,
        );
        check(
            fields,
            "subscribers",
            same_set(&self.subscribers, &target.subscribers),
        );
        check(fields, "acls", same_acls(&self.acls, &target.acls));
        check(
            fields,
            "deadProperties",
            same_dead(&self.dead_properties, &target.dead_properties),
        );
        check(
            fields,
            "timestamps",
            self.created == target.created && self.modified == target.modified,
        );
    }

    fn explain(&mut self, _target: &Self, explanation: &Explanation) {
        explain_dead(&mut self.dead_properties, explanation);
    }
}

impl Compare for FileNodeRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "parent", self.parent_id == target.parent_id);
        check(fields, "name", self.name == target.name);
        check(
            fields,
            "displayName",
            self.display_name == target.display_name,
        );
        check(fields, "file", self.file == target.file);
        check(
            fields,
            "timestamps",
            self.created == target.created && self.modified == target.modified,
        );
        check(
            fields,
            "deadProperties",
            same_dead(&self.dead_properties, &target.dead_properties),
        );
        check(fields, "acls", same_acls(&self.acls, &target.acls));
    }

    fn explain(&mut self, _target: &Self, explanation: &Explanation) {
        match explanation {
            Explanation::DisplayName | Explanation::DeadProperties => self.display_name = None,
            _ => {}
        }
        explain_dead(&mut self.dead_properties, explanation);
    }
}

impl Compare for CalendarEventRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "hrefs", same_names(&self.names, &target.names));
        check(
            fields,
            "displayName",
            self.display_name == target.display_name,
        );
        check(
            fields,
            "icalendar",
            same_icalendar(&self.icalendar, &target.icalendar),
        );
        check(
            fields,
            "preferences",
            default_alert_accounts(&self.preferences)
                == default_alert_accounts(&target.preferences),
        );
        check(
            fields,
            "flags",
            self.flags & EVENT_FLAGS == target.flags & EVENT_FLAGS,
        );
        check(
            fields,
            "deadProperties",
            same_dead(&self.dead_properties, &target.dead_properties),
        );
        check(
            fields,
            "timestamps",
            self.created == target.created && self.modified == target.modified,
        );
        check(
            fields,
            "scheduleTag",
            self.schedule_tag == target.schedule_tag,
        );
    }

    fn explain(&mut self, _target: &Self, explanation: &Explanation) {
        explain_dead(&mut self.dead_properties, explanation);
    }
}

impl Compare for EventNotificationRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(
            fields,
            "icalendar",
            same_icalendar(&self.icalendar, &target.icalendar),
        );
        check(fields, "eventId", self.event_id == target.event_id);
        check(fields, "changedBy", self.changed_by == target.changed_by);
        check(
            fields,
            "flags",
            self.flags & NOTIFICATION_FLAGS == target.flags & NOTIFICATION_FLAGS,
        );
        check(
            fields,
            "timestamps",
            self.created == target.created && self.modified == target.modified,
        );
    }
}

impl Compare for ContactRecord {
    fn compare(&self, target: &Self, fields: &mut Fields) {
        check(fields, "hrefs", same_names(&self.names, &target.names));
        check(
            fields,
            "displayName",
            self.display_name == target.display_name,
        );
        check(fields, "vcard", same_vcard(&self.vcard, &target.vcard));
        check(
            fields,
            "deadProperties",
            same_dead(&self.dead_properties, &target.dead_properties),
        );
        check(
            fields,
            "timestamps",
            self.created == target.created && self.modified == target.modified,
        );
    }

    fn explain(&mut self, _target: &Self, explanation: &Explanation) {
        explain_dead(&mut self.dead_properties, explanation);
    }
}

pub(super) enum Outcome {
    Missing,
    Differs { fields: Fields, detail: String },
}

fn with_explanations<'x, R: Compare>(
    source: &'x R,
    target: &R,
    explanations: &[Explanation],
) -> Cow<'x, R> {
    if explanations.is_empty() {
        return Cow::Borrowed(source);
    }
    let mut source = source.clone();
    for explanation in explanations {
        source.explain(target, explanation);
    }
    Cow::Owned(source)
}

fn same<R: Compare>(source: &R, target: &R) -> bool {
    let mut fields = Fields::new();
    source.compare(target, &mut fields);
    fields.is_empty()
}

fn pair<R: Compare>(
    source: &[R],
    target: &[R],
    explanations: &Explanations,
    collection: Collection,
    mut each: impl FnMut(u32, Outcome, bool),
) {
    let by_id: FxHashMap<u32, &R> = target
        .iter()
        .map(|record| (record.document_id(), record))
        .collect();
    let mut fields = Fields::new();
    for record in source {
        let document_id = record.document_id();
        let known = explanations.get(collection, document_id);
        match by_id.get(&document_id) {
            None => each(
                document_id,
                Outcome::Missing,
                known.contains(&Explanation::Missing),
            ),
            Some(target) => {
                record.compare(target, &mut fields);
                if !fields.is_empty() {
                    let source = with_explanations(record, target, known);
                    let explained = !known.is_empty() && same(&*source, target);
                    let mut detail = String::new();
                    source.describe(target, &mut detail);
                    each(
                        document_id,
                        Outcome::Differs {
                            fields: std::mem::take(&mut fields),
                            detail,
                        },
                        explained,
                    );
                }
            }
        }
    }
}

pub(super) fn compare_batches(
    source: &RecordBatch,
    target: &RecordBatch,
    explanations: &Explanations,
    each: impl FnMut(u32, Outcome, bool),
) {
    let collection = source.collection();
    match (source, target) {
        (RecordBatch::Mailbox(s), RecordBatch::Mailbox(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::Calendar(s), RecordBatch::Calendar(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::AddressBook(s), RecordBatch::AddressBook(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::FileNode(s), RecordBatch::FileNode(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::Identity(s), RecordBatch::Identity(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::SieveScript(s), RecordBatch::SieveScript(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::Email(s), RecordBatch::Email(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::EmailSubmission(s), RecordBatch::EmailSubmission(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::CalendarEvent(s), RecordBatch::CalendarEvent(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::CalendarEventNotification(s), RecordBatch::CalendarEventNotification(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (RecordBatch::ContactCard(s), RecordBatch::ContactCard(t)) => {
            pair(s, t, explanations, collection, each)
        }
        (source, _) => {
            let mut ids = Vec::new();
            source.collect_ids(&mut ids);
            let mut each = each;
            for document_id in ids {
                let explained = explanations
                    .get(collection, document_id)
                    .contains(&Explanation::Missing);
                each(document_id, Outcome::Missing, explained);
            }
        }
    }
}

fn normalized(list: &[u64]) -> Vec<u64> {
    let mut list = list.to_vec();
    list.sort_unstable();
    list.dedup();
    list
}

fn collapse(changes: &LogChanges, items: bool) -> [Vec<u64>; 4] {
    let (inserts, updates, properties, deletes) = if items {
        (
            &changes.inserted_items,
            &changes.updated_items,
            &[][..],
            &changes.deleted_items,
        )
    } else {
        (
            &changes.inserted_containers,
            &changes.updated_containers,
            &changes.updated_container_properties[..],
            &changes.deleted_containers,
        )
    };
    let inserts = normalized(inserts);
    let deletes = normalized(deletes);
    let contains = |list: &[u64], id: &u64| list.binary_search(id).is_ok();
    let kept_inserts = inserts
        .iter()
        .copied()
        .filter(|id| !contains(&deletes, id))
        .collect::<Vec<_>>();
    let kept_deletes = deletes
        .iter()
        .copied()
        .filter(|id| !contains(&inserts, id))
        .collect::<Vec<_>>();
    let touched = |id: &u64| contains(&inserts, id) || contains(&deletes, id);
    let updates = normalized(updates);
    let kept_updates = updates
        .iter()
        .copied()
        .filter(|id| !touched(id))
        .collect::<Vec<_>>();
    let kept_properties = normalized(properties)
        .into_iter()
        .filter(|id| !touched(id) && !contains(&updates, id))
        .collect::<Vec<_>>();
    [kept_inserts, kept_updates, kept_properties, kept_deletes]
}

pub(super) fn same_log_entry(source: &LogEntry, target: &LogEntry) -> bool {
    match (source, target) {
        (LogEntry::Changes(source), LogEntry::Changes(target)) => {
            collapse(source, true) == collapse(target, true)
                && collapse(source, false) == collapse(target, false)
        }
        (
            LogEntry::Vanished(VanishedRecord::Email(source)),
            LogEntry::Vanished(VanishedRecord::Email(target)),
        ) => same_set(source, target),
        (
            LogEntry::Vanished(VanishedRecord::Paths(source)),
            LogEntry::Vanished(VanishedRecord::Paths(target)),
        ) => same_set(source, target),
        (LogEntry::Truncated, _) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explained<R: Compare>(source: &R, target: &R, explanations: &[Explanation]) -> bool {
        same(&*with_explanations(source, target, explanations), target)
    }

    #[test]
    fn dead_properties_ignore_attribute_order_and_blank_text() {
        let tag = |attrs: &str| DeadPropertyTag::ElementStart {
            name: "color".into(),
            attrs: Some(attrs.into()),
        };
        let left = DeadPropertyRecord(vec![
            tag("xmlns=\"urn:a\" x=\"1\""),
            DeadPropertyTag::Text("\n ".into()),
            DeadPropertyTag::Text("red".into()),
            DeadPropertyTag::ElementEnd,
        ]);
        let right = DeadPropertyRecord(vec![
            tag("x=\"1\" xmlns=\"urn:a\""),
            DeadPropertyTag::Text("red".into()),
            DeadPropertyTag::ElementEnd,
        ]);
        assert!(same_dead(&left, &right));
        let other = DeadPropertyRecord(vec![
            tag("xmlns=\"urn:b\""),
            DeadPropertyTag::Text("red".into()),
            DeadPropertyTag::ElementEnd,
        ]);
        assert!(!same_dead(&left, &other));
    }

    // Top-level properties compare as a set keyed by namespace and name; v1 stores them sorted.
    #[test]
    fn dead_properties_ignore_property_order() {
        let property = |namespace: &str, name: &str, text: &str| {
            [
                DeadPropertyTag::ElementStart {
                    name: name.into(),
                    attrs: Some(format!("xmlns=\"{namespace}\"").into()),
                },
                DeadPropertyTag::Text(text.into()),
                DeadPropertyTag::ElementEnd,
            ]
        };
        let b = property("urn:b", "x", "1");
        let a = property("urn:a", "y", "2");
        let left = DeadPropertyRecord(b.iter().chain(&a).cloned().collect());
        let right = DeadPropertyRecord(a.iter().chain(&b).cloned().collect());
        assert!(same_dead(&left, &right));
        let changed = DeadPropertyRecord(
            a.iter()
                .chain(&property("urn:b", "x", "3"))
                .cloned()
                .collect(),
        );
        assert!(!same_dead(&left, &changed));
        let first = property("urn:a", "x", "1");
        let second = property("urn:b", "x", "2");
        let ordered = DeadPropertyRecord(first.iter().chain(&second).cloned().collect());
        let reversed = DeadPropertyRecord(second.iter().chain(&first).cloned().collect());
        assert!(same_dead(&ordered, &reversed));
        let swapped = DeadPropertyRecord(
            property("urn:a", "x", "2")
                .iter()
                .chain(&property("urn:b", "x", "1"))
                .cloned()
                .collect(),
        );
        assert!(!same_dead(&ordered, &swapped));
        let nested = DeadPropertyRecord(
            property("urn:b", "x", "1")
                .into_iter()
                .take(1)
                .chain(a.iter().cloned())
                .chain([DeadPropertyTag::ElementEnd])
                .collect(),
        );
        assert!(!same_dead(&left, &nested));
    }

    // v1 returns attribute values unescaped, xml: attributes without prefix and namespaces per element.
    #[test]
    fn dead_properties_normalize_escaping_and_namespaces() {
        let start = |name: &str, attrs: &str| DeadPropertyTag::ElementStart {
            name: name.into(),
            attrs: (!attrs.is_empty()).then(|| attrs.into()),
        };
        let source = DeadPropertyRecord(vec![
            start(
                "calendar-color",
                "xmlns=\"http://apple.com/ns/ical/\" xml:lang=\"en\" note=\"a &amp; b\"",
            ),
            DeadPropertyTag::Text("#FF0000".into()),
            start("inner", "xml:lang=\"de\""),
            DeadPropertyTag::ElementEnd,
            DeadPropertyTag::ElementEnd,
        ]);
        let target = DeadPropertyRecord(vec![
            start(
                "calendar-color",
                "xmlns=\"http://apple.com/ns/ical/\" xml:lang=\"en\" note=\"a & b\"",
            ),
            DeadPropertyTag::Text("#FF0000".into()),
            start("inner", "xmlns=\"http://apple.com/ns/ical/\" lang=\"de\""),
            DeadPropertyTag::ElementEnd,
            DeadPropertyTag::ElementEnd,
        ]);
        assert!(same_dead(&source, &target));
        let other = DeadPropertyRecord(vec![
            start("calendar-color", "xmlns=\"urn:other\" note=\"a & b\""),
            DeadPropertyTag::Text("#FF0000".into()),
            DeadPropertyTag::ElementEnd,
        ]);
        assert!(!same_dead(&source, &other));
    }

    // A named dead property drop removes only that property before comparing.
    #[test]
    fn dead_property_explanation_removes_only_the_named_property() {
        let start = |name: &str, attrs: &str| DeadPropertyTag::ElementStart {
            name: name.into(),
            attrs: (!attrs.is_empty()).then(|| attrs.into()),
        };
        let property = |name: &str, text: &str| {
            vec![
                start(name, "xmlns=\"urn:x\""),
                DeadPropertyTag::Text(text.into()),
                DeadPropertyTag::ElementEnd,
            ]
        };
        let source = CalendarRecord {
            dead_properties: DeadPropertyRecord([property("a", "1"), property("b", "2")].concat()),
            ..Default::default()
        };
        let mut lost_a = source.clone();
        lost_a.dead_properties = DeadPropertyRecord(property("b", "2"));
        assert!(explained(
            &source,
            &lost_a,
            &[Explanation::DeadProperty("{urn:x}a".into())]
        ));
        let mut lost_both = source.clone();
        lost_both.dead_properties = DeadPropertyRecord(Vec::new());
        assert!(!explained(
            &source,
            &lost_both,
            &[Explanation::DeadProperty("{urn:x}a".into())]
        ));
        assert!(explained(
            &source,
            &lost_both,
            &[Explanation::DeadProperties]
        ));
        let mut renamed = lost_a.clone();
        renamed.name = "other".into();
        assert!(!explained(
            &source,
            &renamed,
            &[Explanation::DeadProperty("{urn:x}a".into())]
        ));
    }

    // A dropped attribute explains only that attribute; a dropped property requires the target to lack it.
    #[test]
    fn dead_attribute_explanation_strips_only_the_attribute() {
        let start = |name: &str, attrs: &str| DeadPropertyTag::ElementStart {
            name: name.into(),
            attrs: (!attrs.is_empty()).then(|| attrs.into()),
        };
        let record = |attrs: &str, text: &str| CalendarRecord {
            dead_properties: DeadPropertyRecord(vec![
                start("a", "xmlns=\"urn:x\""),
                start("inner", attrs),
                DeadPropertyTag::Text(text.into()),
                DeadPropertyTag::ElementEnd,
                DeadPropertyTag::ElementEnd,
            ]),
            ..Default::default()
        };
        let source = record("p:q=\"1\" keep=\"2\"", "v");
        let attribute = [Explanation::DeadAttribute("{urn:x}a".into(), "p:q".into())];
        assert!(explained(&source, &record("keep=\"2\"", "v"), &attribute));
        assert!(!explained(&source, &record("keep=\"2\"", "w"), &attribute));
        assert!(!explained(&source, &record("", "v"), &attribute));
        let unrelated = [Explanation::DeadAttribute("{urn:y}a".into(), "p:q".into())];
        assert!(!explained(&source, &record("keep=\"2\"", "v"), &unrelated));
        let property = [Explanation::DeadProperty("{urn:x}a".into())];
        assert!(!explained(&source, &record("keep=\"2\"", "v"), &property));
        let lost = CalendarRecord::default();
        assert!(explained(&source, &lost, &property));
    }

    // Truncations explain only a target that keeps exactly the limit, as a subset of the source.
    #[test]
    fn truncation_explanations_are_exact() {
        let source = EmailRecord {
            keywords: vec!["a".into(), "b".into(), "c".into()],
            ..Default::default()
        };
        let kept = EmailRecord {
            keywords: vec!["a".into(), "c".into()],
            ..Default::default()
        };
        assert!(explained(&source, &kept, &[Explanation::Keywords(2)]));
        assert!(!explained(&source, &kept, &[Explanation::Keywords(1)]));
        let foreign = EmailRecord {
            keywords: vec!["a".into(), "z".into()],
            ..Default::default()
        };
        assert!(!explained(&source, &foreign, &[Explanation::Keywords(2)]));
        let headers = EmailRecord {
            size: 100,
            extra_headers: b"X: y\r\n".as_slice().into(),
            ..Default::default()
        };
        let dropped = EmailRecord {
            size: 94,
            ..Default::default()
        };
        assert!(explained(&headers, &dropped, &[Explanation::ExtraHeaders]));
        let wrong_size = EmailRecord {
            size: 90,
            ..Default::default()
        };
        assert!(!explained(
            &headers,
            &wrong_size,
            &[Explanation::ExtraHeaders]
        ));
    }

    #[test]
    fn log_rows_compare_after_collapsing() {
        let source = LogEntry::Changes(LogChanges {
            inserted_items: vec![5, 3, 3],
            updated_items: vec![3, 9],
            deleted_items: vec![7],
            updated_containers: vec![1],
            updated_container_properties: vec![1, 2],
            ..Default::default()
        });
        let target = LogEntry::Changes(LogChanges {
            inserted_items: vec![3, 5],
            updated_items: vec![9],
            deleted_items: vec![7],
            updated_containers: vec![1],
            updated_container_properties: vec![2],
            ..Default::default()
        });
        assert!(same_log_entry(&source, &target));
        let moved = LogEntry::Changes(LogChanges {
            inserted_items: vec![3, 5],
            deleted_items: vec![9],
            ..Default::default()
        });
        assert!(!same_log_entry(&source, &moved));
    }

    #[test]
    fn email_ignores_keyword_order() {
        let email = EmailRecord {
            keywords: vec!["$seen".into(), "a".into()],
            ..Default::default()
        };
        let target = EmailRecord {
            keywords: vec!["a".into(), "$seen".into()],
            ..Default::default()
        };
        let mut fields = Fields::new();
        email.compare(&target, &mut fields);
        assert!(fields.is_empty());
        let target = EmailRecord {
            extra_headers: b"X: y\r\n".as_slice().into(),
            ..target
        };
        email.compare(&target, &mut fields);
        assert_eq!(fields, ["headers"]);
    }

    // v1 derives $hasattachment and $hasnoattachment from the message, so stored values are not compared.
    #[test]
    fn email_ignores_server_set_keywords() {
        let email = EmailRecord {
            keywords: vec![
                "$seen".into(),
                "$HasAttachment".into(),
                "$hasnoattachment".into(),
            ],
            ..Default::default()
        };
        let target = EmailRecord {
            keywords: vec!["$seen".into()],
            ..Default::default()
        };
        let mut fields = Fields::new();
        email.compare(&target, &mut fields);
        assert!(fields.is_empty());
        let target = EmailRecord {
            keywords: vec!["$hasattachment".into()],
            ..Default::default()
        };
        email.compare(&target, &mut fields);
        assert_eq!(fields, ["keywords"]);
    }

    fn keyword_detail(source: &[&str], target: &[&str], explanations: &[Explanation]) -> String {
        let record = |keywords: &[&str]| EmailRecord {
            keywords: keywords.iter().map(|keyword| (*keyword).into()).collect(),
            ..Default::default()
        };
        let (source, target) = (record(source), record(target));
        let mut detail = String::new();
        with_explanations(&source, &target, explanations).describe(&target, &mut detail);
        detail
    }

    // A keyword mismatch lists the keywords each side holds alone, ignoring case and attachment keywords.
    #[test]
    fn keyword_mismatch_lists_the_differing_keywords() {
        assert_eq!(
            keyword_detail(
                &["$Seen", "$label1", "foo", "$hasattachment"],
                &["$seen", "bar"],
                &[]
            ),
            " (keywords only in the source: \"$label1\", \"foo\"; only in the target: \"bar\")"
        );
        assert_eq!(
            keyword_detail(&["$seen", "a"], &["$seen"], &[]),
            " (keywords only in the source: \"a\"; only in the target: none)"
        );
        assert_eq!(
            keyword_detail(&["$Seen"], &["$seen", "$hasnoattachment"], &[]),
            ""
        );
    }

    // A backslash system flag matches its dollar keyword, as the v1 writer stores it.
    #[test]
    fn keyword_backslash_system_flags_match_dollar_keywords() {
        let mut fields = Fields::new();
        let source = EmailRecord {
            keywords: vec!["$seen".into(), "\\seen".into(), "\\Flagged".into()],
            ..Default::default()
        };
        let target = EmailRecord {
            keywords: vec!["$seen".into(), "$flagged".into()],
            ..Default::default()
        };
        source.compare(&target, &mut fields);
        assert!(fields.is_empty());
        assert_eq!(
            keyword_detail(
                &["$seen", "\\seen", "\\Flagged"],
                &["$seen", "$flagged"],
                &[]
            ),
            ""
        );
        assert_eq!(
            keyword_detail(&["\\foo"], &["$foo"], &[]),
            " (keywords only in the source: \"\\\\foo\"; only in the target: \"$foo\")"
        );
    }

    // Keywords removed by an explanation are not listed.
    #[test]
    fn keyword_mismatch_skips_explained_keywords() {
        assert_eq!(
            keyword_detail(
                &["a", "b", "c"],
                &["a"],
                &[Explanation::Keyword("b".into())]
            ),
            " (keywords only in the source: \"c\"; only in the target: none)"
        );
    }

    // Long lists are capped and hostile names are escaped and shortened.
    #[test]
    fn keyword_mismatch_is_capped_and_escaped() {
        let many = ["k1", "k2", "k3", "k4", "k5", "k6", "k7"];
        assert_eq!(
            keyword_detail(&many, &[], &[]),
            " (keywords only in the source: \"k1\", \"k2\", \"k3\", \"k4\", \"k5\" and 2 more; only in the target: none)"
        );
        let long = "x".repeat(300);
        let hostile = format!("a,b\n{long}");
        let detail = keyword_detail(&[hostile.as_str()], &[], &[]);
        let shown = format!("a,b\\n{}", "x".repeat(MAX_KEYWORD_CHARS - 4));
        assert_eq!(
            detail,
            format!(" (keywords only in the source: \"{shown}...\"; only in the target: none)")
        );
    }
}
