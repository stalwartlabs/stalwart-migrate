use rustc_hash::FxHashSet;
use serde_json::{Map, Value};

use super::string;
use crate::{
    engine::{Direction, Flow, Move, SourceObject, TYPE_KEY, Walker},
    ids::{Instance, ObjectKey},
    prompts::PromptId,
    report::DropReason,
    schema::TypeDef,
    transform::Transform,
};

const ENCRYPTION_AT_REST: &str = "encryptionAtRest";
const ENCRYPT_ON_APPEND: &str = "encryptOnAppend";
const PUBLIC_KEY: &str = "publicKey";
const HEADER_PROTECTION: &str = "headerProtection";
const AUTHENTICATED_ENCRYPTION: &str = "authenticatedEncryption";
const STRICT_KEY_WRAP_ENCODING: &str = "strictKeyWrapEncoding";
const KEY: &str = "key";
const ENABLED: &str = "Enabled";
const DISABLED: &str = "Disabled";
const EMAIL_OBJECT: &str = "x:Email";
const PUBLIC_KEY_OBJECT: &str = "x:PublicKey";
const HEADER_PROTECTION_NONE: &str = "none";
const DEFAULT_HEADER_PROTECTION: &str = "noConfidentiality";
const V016_CIPHER: &str = "Aes256";
const V016_AEAD_CIPHER: &str = "Aes256Gcm";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Aes128,
    Aes256,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Cipher {
    fn parse(name: &str) -> Option<Self> {
        hashify::map!(name.as_bytes(), Cipher,
            "Aes128" => Cipher::Aes128,
            "Aes256" => Cipher::Aes256,
            "Aes256Gcm" => Cipher::Aes256Gcm,
            "ChaCha20Poly1305" => Cipher::ChaCha20Poly1305,
        )
        .copied()
    }

    fn is_aead(self) -> bool {
        matches!(self, Cipher::Aes256Gcm | Cipher::ChaCha20Poly1305)
    }

    fn label(self) -> &'static str {
        match self {
            Cipher::Aes128 => "AES-128",
            Cipher::Aes256 => "AES-256",
            Cipher::Aes256Gcm => "AES-256-GCM",
            Cipher::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    OpenPgp,
    Smime,
    Unknown,
}

impl KeyKind {
    fn of(text: &str) -> Self {
        let text = text.trim_start();
        let Some(label) = text
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.split_once("-----"))
            .map(|(label, _)| label)
        else {
            return KeyKind::Unknown;
        };
        if label.starts_with("PGP ") {
            KeyKind::OpenPgp
        } else if label.contains("CERTIFICATE") {
            KeyKind::Smime
        } else {
            KeyKind::Unknown
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct EncryptionFacts {
    email_encrypt_on_append: bool,
    authenticated_keys: FxHashSet<Instance>,
    append_account: Option<ObjectKey>,
    encrypted_accounts: u64,
}

impl EncryptionFacts {
    pub(crate) fn scan(direction: Direction, inputs: &[SourceObject]) -> Self {
        let mut facts = EncryptionFacts::default();
        let mut smime_keys = FxHashSet::default();
        let mut key_flags = Vec::new();
        for input in inputs {
            let object = &*input.key.object;
            if object == EMAIL_OBJECT {
                facts.email_encrypt_on_append = input
                    .value
                    .get(ENCRYPT_ON_APPEND)
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            } else if object == PUBLIC_KEY_OBJECT {
                if input
                    .value
                    .get(KEY)
                    .and_then(Value::as_str)
                    .map(KeyKind::of)
                    == Some(KeyKind::Smime)
                {
                    smime_keys.insert(input.key.instance.clone());
                }
                if input
                    .value
                    .get(AUTHENTICATED_ENCRYPTION)
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    key_flags.push(input.key.instance.clone());
                }
            }
            let Some(settings) = input.value.get(ENCRYPTION_AT_REST) else {
                continue;
            };
            let Some(variant) = settings.get(TYPE_KEY).and_then(Value::as_str) else {
                continue;
            };
            if variant == DISABLED {
                continue;
            }
            facts.encrypted_accounts += 1;
            match direction {
                Direction::Forward => {
                    if Cipher::parse(variant).is_some_and(Cipher::is_aead)
                        && let Some(key) = settings
                            .get(PUBLIC_KEY)
                            .and_then(Value::as_str)
                            .and_then(Instance::parse_reference)
                    {
                        key_flags.push(key);
                    }
                }
                Direction::Reverse => {
                    if settings.get(ENCRYPT_ON_APPEND).and_then(Value::as_bool) == Some(true)
                        && facts.append_account.as_ref().is_none_or(|k| input.key < *k)
                    {
                        facts.append_account = Some(input.key.clone());
                    }
                }
            }
        }
        facts.authenticated_keys = key_flags
            .into_iter()
            .filter(|key| smime_keys.contains(key))
            .collect();
        facts
    }
}

pub(super) fn encryption_at_rest_forward(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let Some(mut value) = src.remove(ENCRYPTION_AT_REST) else {
        return Flow::Keep;
    };
    let cipher = value
        .get(TYPE_KEY)
        .and_then(Value::as_str)
        .and_then(Cipher::parse);
    if let (Some(cipher), Value::Object(settings)) = (cipher, &mut value) {
        let context = vec![(
            "accountsWithEncryption".into(),
            Value::from(w.facts.encryption.encrypted_accounts),
        )];
        let defaults = w.prompt_defaults(PromptId::EncryptionAtRest);
        let answer = w.session.answer(
            w.report,
            PromptId::EncryptionAtRest,
            None,
            defaults,
            context,
        );
        let header_protection = answer
            .str("header_protection")
            .unwrap_or(DEFAULT_HEADER_PROTECTION);
        settings.insert(TYPE_KEY.into(), string(ENABLED));
        settings.insert(HEADER_PROTECTION.into(), string(header_protection));
        let mut detail = format!(
            "{} became Enabled (header protection {header_protection}); v1 selects the cipher from the public key",
            cipher.label()
        );
        if cipher.is_aead() {
            let authenticated = settings
                .get(PUBLIC_KEY)
                .and_then(Value::as_str)
                .and_then(Instance::parse_reference)
                .is_some_and(|key| w.facts.encryption.authenticated_keys.contains(&key));
            detail.push_str(if authenticated {
                ", with authenticated encryption on its S/MIME certificate"
            } else {
                "; the key is not an S/MIME certificate, so v1 has no authenticated encryption setting for it"
            });
        }
        if !w.facts.encryption.email_encrypt_on_append
            && settings.get(ENCRYPT_ON_APPEND).and_then(Value::as_bool) == Some(true)
        {
            settings.insert(ENCRYPT_ON_APPEND.into(), Value::Bool(false));
            detail.push_str(
                "; encryptOnAppend turned off because Email.encryptOnAppend was off in v0.16",
            );
        }
        w.transformed(Transform::EncryptionAtRest, ENCRYPTION_AT_REST, detail);
    }
    out.insert(ENCRYPTION_AT_REST.into(), value);
    Flow::Keep
}

pub(super) fn encryption_at_rest_reverse(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let Some(mut value) = src.remove(ENCRYPTION_AT_REST) else {
        return Flow::Keep;
    };
    if let Value::Object(settings) = &mut value
        && settings.get(TYPE_KEY).and_then(Value::as_str) == Some(ENABLED)
    {
        let authenticated = settings
            .get(PUBLIC_KEY)
            .and_then(Value::as_str)
            .and_then(Instance::parse_reference)
            .is_some_and(|key| w.facts.encryption.authenticated_keys.contains(&key));
        let cipher = if authenticated {
            V016_AEAD_CIPHER
        } else {
            V016_CIPHER
        };
        settings.insert(TYPE_KEY.into(), string(cipher));
        if let Some(protection) = settings.remove(HEADER_PROTECTION)
            && protection.as_str() != Some(HEADER_PROTECTION_NONE)
        {
            w.path.push(ENCRYPTION_AT_REST);
            w.dropped(
                HEADER_PROTECTION,
                DropReason::NoEquivalent,
                Some(&protection),
            );
            w.path.pop();
        }
        if w.facts.encryption.append_account.as_ref() == Some(w.key) {
            w.moves.push(Move {
                source: w.key.clone(),
                object: EMAIL_OBJECT.into(),
                property: ENCRYPT_ON_APPEND.into(),
                value: Value::Bool(true),
            });
        }
        w.transformed(
            Transform::EncryptionAtRest,
            ENCRYPTION_AT_REST,
            format!("Enabled became {cipher}"),
        );
    }
    out.insert(ENCRYPTION_AT_REST.into(), value);
    Flow::Keep
}

pub(super) fn email_encrypt_on_append(
    w: &mut Walker,
    _name: &str,
    _ty: &TypeDef,
    value: Value,
    _out: &mut Map<String, Value>,
) -> Flow {
    let detail = if value.as_bool() == Some(true) {
        "applied to the encryptOnAppend setting of each account"
    } else {
        "encryptOnAppend turned off for every account with encryption at rest"
    };
    w.transformed(Transform::EmailEncryptOnAppend, "", detail);
    Flow::Keep
}

pub(super) fn public_key_forward(
    w: &mut Walker,
    _src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    if w.facts
        .encryption
        .authenticated_keys
        .contains(&w.key.instance)
    {
        out.insert(AUTHENTICATED_ENCRYPTION.into(), Value::Bool(true));
        w.transformed(
            Transform::PublicKeyEncryption,
            AUTHENTICATED_ENCRYPTION,
            "set for an account that used AES-256-GCM or ChaCha20-Poly1305",
        );
    }
    Flow::Keep
}

pub(super) fn public_key_reverse(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    _out: &mut Map<String, Value>,
) -> Flow {
    if let Some(value) = src
        .remove(STRICT_KEY_WRAP_ENCODING)
        .filter(|v| v.as_bool() == Some(true))
    {
        w.dropped(
            STRICT_KEY_WRAP_ENCODING,
            DropReason::NoEquivalent,
            Some(&value),
        );
    }
    if let Some(value) = src
        .remove(AUTHENTICATED_ENCRYPTION)
        .filter(|v| v.as_bool() == Some(true))
    {
        if w.facts
            .encryption
            .authenticated_keys
            .contains(&w.key.instance)
        {
            w.transformed(
                Transform::PublicKeyEncryption,
                AUTHENTICATED_ENCRYPTION,
                "accounts using this key select AES-256-GCM",
            );
        } else {
            w.dropped(
                AUTHENTICATED_ENCRYPTION,
                DropReason::NoEquivalent,
                Some(&value),
            );
        }
    }
    Flow::Keep
}

#[cfg(test)]
mod tests {
    use super::*;

    // PEM labels tell OpenPGP keys from S/MIME certificates, as v0.16 parsed them.
    #[test]
    fn key_kind_follows_the_pem_label() {
        for (text, kind) in [
            (
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n",
                KeyKind::OpenPgp,
            ),
            ("\n  -----BEGIN CERTIFICATE-----\nx\n", KeyKind::Smime),
            ("-----BEGIN X509 CERTIFICATE-----\nx\n", KeyKind::Smime),
            ("-----BEGIN PUBLIC KEY-----\nx\n", KeyKind::Unknown),
            ("mQINBGTGHwkBEADRB5EEtfsn", KeyKind::Unknown),
            ("-----BEGIN PGP", KeyKind::Unknown),
        ] {
            assert_eq!(KeyKind::of(text), kind, "{text:?}");
        }
    }

    // Only the authenticated ciphers of v0.16 select authenticated encryption in v1.
    #[test]
    fn aead_ciphers_are_recognized() {
        let aead: Vec<bool> = ["Aes128", "Aes256", "Aes256Gcm", "ChaCha20Poly1305"]
            .into_iter()
            .filter_map(Cipher::parse)
            .map(Cipher::is_aead)
            .collect();
        assert_eq!(aead, [false, false, true, true]);
        assert!(Cipher::parse("Enabled").is_none());
    }

    // Accounts referencing an S/MIME key with an authenticated cipher mark that key; OpenPGP keys and other ciphers do not.
    #[test]
    fn forward_scan_marks_only_smime_keys_of_aead_accounts() {
        let input = |key: &str, value: Value| SourceObject {
            key: ObjectKey::parse(key).expect("key"),
            value,
        };
        let smime = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";
        let pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n";
        let facts = EncryptionFacts::scan(
            Direction::Forward,
            &[
                input("x:PublicKey/b", serde_json::json!({"key": smime})),
                input("x:PublicKey/c", serde_json::json!({"key": pgp})),
                input("x:PublicKey/d", serde_json::json!({"key": smime})),
                input(
                    "x:Account/e",
                    serde_json::json!({"encryptionAtRest": {"@type": "Aes256Gcm", "publicKey": "b"}}),
                ),
                input(
                    "x:Account/f",
                    serde_json::json!({"encryptionAtRest": {"@type": "ChaCha20Poly1305", "publicKey": "c"}}),
                ),
                input(
                    "x:Account/g",
                    serde_json::json!({"encryptionAtRest": {"@type": "Aes256", "publicKey": "d"}}),
                ),
                input("x:Email", serde_json::json!({"encryptOnAppend": true})),
            ],
        );
        assert_eq!(facts.authenticated_keys.len(), 1);
        assert!(facts.authenticated_keys.contains(&Instance::Id(1)));
        assert_eq!(facts.encrypted_accounts, 3);
        assert!(facts.email_encrypt_on_append);
    }
}
