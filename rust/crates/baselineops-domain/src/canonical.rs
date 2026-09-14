use std::{fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::DomainResult;

mod hex;

/// Lowercase, 32-byte SHA-256 digest used to bind profiles, plans, and evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
#[schemars(with = "String")]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps the output bytes of an already-completed SHA-256 calculation.
    #[must_use]
    pub const fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Calculates the SHA-256 digest for the supplied bytes.
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the canonical lowercase hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err("SHA-256 digests must be exactly 64 lowercase hexadecimal characters");
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex::nibble(pair[0]).ok_or("SHA-256 digest is not hexadecimal")?;
            let low = hex::nibble(pair[1]).ok_or("SHA-256 digest is not hexadecimal")?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Serializes any value to a recursively key-sorted, whitespace-free JSON value.
///
/// # Errors
///
/// Returns an error if `value` cannot be serialized as JSON.
pub fn canonical_json_value<T: Serialize>(value: &T) -> DomainResult<Value> {
    Ok(serde_json::to_value(value)?)
}

/// Serializes any value to a recursively key-sorted, whitespace-free UTF-8 JSON byte sequence.
///
/// # Errors
///
/// Returns an error if `value` cannot be serialized as JSON.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> DomainResult<Vec<u8>> {
    let value = canonical_json_value(value)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

/// Calculates SHA-256 over the canonical JSON representation of a value.
///
/// # Errors
///
/// Returns an error if `value` cannot be serialized as JSON.
pub fn canonical_json_digest<T: Serialize>(value: &T) -> DomainResult<Sha256Digest> {
    let value = canonical_json_value(value)?;
    let mut output = DigestSink::default();
    write_canonical_value(&value, &mut output)?;
    Ok(output.finish())
}

trait CanonicalSink {
    fn write(&mut self, bytes: &[u8]);

    fn write_byte(&mut self, byte: u8) {
        self.write(&[byte]);
    }
}

impl CanonicalSink for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

#[derive(Default)]
struct DigestSink(Sha256);

impl DigestSink {
    fn finish(self) -> Sha256Digest {
        Sha256Digest::from_digest_bytes(self.0.finalize().into())
    }
}

impl CanonicalSink for DigestSink {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

fn write_canonical_value<S: CanonicalSink>(
    value: &serde_json::Value,
    output: &mut S,
) -> DomainResult<()> {
    match value {
        Value::Null => output.write(b"null"),
        Value::Bool(value) => write_canonical_boolean(*value, output),
        Value::Number(number) => output.write(number.to_string().as_bytes()),
        Value::String(string) => write_canonical_string(string, output)?,
        Value::Array(values) => write_canonical_array(values, output)?,
        Value::Object(values) => write_canonical_object(values, output)?,
    }
    Ok(())
}

fn write_canonical_boolean<S: CanonicalSink>(value: bool, output: &mut S) {
    output.write(if value { b"true" } else { b"false" });
}

fn write_canonical_string<S: CanonicalSink>(value: &str, output: &mut S) -> DomainResult<()> {
    serde_json::to_writer(SinkWriter(output), value)?;
    Ok(())
}

struct SinkWriter<'a, S>(&'a mut S);

impl<S: CanonicalSink> std::io::Write for SinkWriter<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_canonical_array<S: CanonicalSink>(values: &[Value], output: &mut S) -> DomainResult<()> {
    output.write_byte(b'[');
    for (index, item) in values.iter().enumerate() {
        if index != 0 {
            output.write_byte(b',');
        }
        write_canonical_value(item, output)?;
    }
    output.write_byte(b']');
    Ok(())
}

fn write_canonical_object<S: CanonicalSink>(
    values: &serde_json::Map<String, Value>,
    output: &mut S,
) -> DomainResult<()> {
    output.write_byte(b'{');
    let mut members = values.iter().collect::<Vec<_>>();
    members.sort_unstable_by_key(|(key, _)| *key);
    for (index, (key, item)) in members.into_iter().enumerate() {
        if index != 0 {
            output.write_byte(b',');
        }
        write_canonical_string(key, output)?;
        output.write_byte(b':');
        write_canonical_value(item, output)?;
    }
    output.write_byte(b'}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::ser::Error as _;
    use serde::{Serialize, Serializer};
    use serde_json::json;

    use super::{Sha256Digest, canonical_json_bytes, canonical_json_digest};

    #[test]
    fn streamed_digest_matches_public_canonical_bytes() {
        let value = json!({
            "z": [null, true, "escaped\nvalue"],
            "a": {"beta": 2, "alpha": 1},
        });

        let bytes = canonical_json_bytes(&value).expect("canonical bytes");
        let digest = canonical_json_digest(&value).expect("canonical digest");

        assert_eq!(digest, Sha256Digest::of_bytes(bytes));
    }

    #[test]
    fn byte_and_digest_apis_preserve_serialization_errors() {
        struct FailingValue;

        impl Serialize for FailingValue {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                Err(S::Error::custom("expected failure"))
            }
        }

        let bytes_error = canonical_json_bytes(&FailingValue)
            .expect_err("byte serialization must fail")
            .to_string();
        let digest_error = canonical_json_digest(&FailingValue)
            .expect_err("digest serialization must fail")
            .to_string();

        assert_eq!(digest_error, bytes_error);
    }
}
