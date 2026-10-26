use std::{borrow::Cow, fmt};

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz792013";
const INVALID: u8 = u8::MAX;
const OBJECT_PREFIX: &str = "x:";
const MAX_ID_DIGITS: usize = 13;

const INVERSE: [u8; 256] = {
    let mut table = [INVALID; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JmapId(pub u64);

impl JmapId {
    pub fn parse(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > MAX_ID_DIGITS {
            return None;
        }
        value
            .bytes()
            .try_fold(0u64, |id, ch| {
                let digit = INVERSE[ch as usize];
                (digit != INVALID && id >> (u64::BITS - 5) == 0)
                    .then(|| (id << 5) | u64::from(digit))
            })
            .map(JmapId)
    }
}

impl fmt::Display for JmapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; MAX_ID_DIGITS];
        let mut pos = buf.len();
        let mut n = self.0;
        loop {
            pos -= 1;
            buf[pos] = ALPHABET[(n & 31) as usize];
            n >>= 5;
            if n == 0 {
                break;
            }
        }
        let digits = buf.get(pos..).unwrap_or_default();
        f.write_str(std::str::from_utf8(digits).map_err(|_| fmt::Error)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Instance {
    Singleton,
    Id(u64),
    Client(Box<str>),
    Label(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectKey {
    pub object: Box<str>,
    pub instance: Instance,
}

impl ObjectKey {
    pub fn new(object: &str, instance: Instance) -> Self {
        ObjectKey {
            object: canonical_object(object).into(),
            instance,
        }
    }

    pub fn singleton(object: &str) -> Self {
        Self::new(object, Instance::Singleton)
    }

    pub fn with_id(object: &str, id: u64) -> Self {
        Self::new(object, Instance::Id(id))
    }

    pub fn parse(value: &str) -> Option<Self> {
        let Some((object, instance)) = value.split_once('/') else {
            return (!value.is_empty()).then(|| Self::singleton(value));
        };
        let instance = if let Some(client) = instance.strip_prefix('#') {
            Instance::Client(client.into())
        } else if let Some(label) = instance.strip_prefix('=') {
            Instance::Label(label.into())
        } else {
            Instance::Id(JmapId::parse(instance)?.0)
        };
        (!object.is_empty()).then(|| Self::new(object, instance))
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.instance {
            Instance::Singleton => f.write_str(&self.object),
            Instance::Id(id) => write!(f, "{}/{}", self.object, JmapId(*id)),
            Instance::Client(client) => write!(f, "{}/#{client}", self.object),
            Instance::Label(label) => write!(f, "{}/={label}", self.object),
        }
    }
}

pub fn canonical_object(name: &str) -> Cow<'_, str> {
    if name.starts_with(OBJECT_PREFIX) {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("{OBJECT_PREFIX}{name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmap_id_round_trip() {
        // Matches the Crockford-style encoding of types::id::Id in both Stalwart versions.
        assert_eq!(JmapId(0).to_string(), "a");
        assert_eq!(JmapId(1).to_string(), "b");
        assert_eq!(JmapId(32).to_string(), "ba");
        for n in [
            0,
            1,
            31,
            32,
            1023,
            20080258862541,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let text = JmapId(n).to_string();
            assert_eq!(JmapId::parse(&text), Some(JmapId(n)), "{n} {text}");
        }
        assert_eq!(JmapId::parse(""), None);
        assert_eq!(JmapId::parse("A"), None);
    }

    #[test]
    fn object_key_round_trip() {
        for text in [
            "x:Http",
            "x:Directory/b",
            "x:Directory/#oidc",
            "x:Domain/=example.com",
        ] {
            assert_eq!(
                ObjectKey::parse(text).map(|k| k.to_string()).as_deref(),
                Some(text)
            );
        }
        assert_eq!(
            ObjectKey::parse("Http").map(|k| k.object),
            Some("x:Http".into())
        );
    }
}
