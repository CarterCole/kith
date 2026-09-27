//! Canonical JSON (a strict subset of RFC 8785 / JCS).
//!
//! Objects have their keys sorted by UTF-16 code units, there is no insignificant
//! whitespace, and numbers must be integers. Floats are rejected so every
//! implementation (Rust, JS, Python) produces byte-identical output.

use serde_json::Value;

use crate::{Error, Result};

pub fn to_canonical(value: &Value) -> Result<String> {
    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out)
}

pub fn canonical_of<T: serde::Serialize>(value: &T) -> Result<String> {
    to_canonical(&serde_json::to_value(value)?)
}

fn write(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(Error::Encoding("canonical JSON forbids non-integer numbers".into()));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s)?),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k)?);
                out.push(':');
                write(&map[k.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({"b": 1, "a": [true, null, "x"], "c": {"z": 1, "y": 2}});
        assert_eq!(to_canonical(&v).unwrap(), r#"{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":1}}"#);
    }

    #[test]
    fn rejects_floats() {
        assert!(to_canonical(&json!({"a": 1.5})).is_err());
    }
}
