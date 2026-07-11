use thiserror::Error;
use url::{Origin, Url};

#[derive(Debug, Clone)]
pub struct OriginPolicy {
    allowed: Origin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OriginError {
    #[error("origin is missing")]
    Missing,
    #[error("multiple origins are not allowed")]
    Multiple,
    #[error("origin is malformed")]
    Malformed,
    #[error("origin is not allowed")]
    Disallowed,
}

impl OriginPolicy {
    pub fn new(value: &str) -> Result<Self, OriginError> {
        let url = parse_origin(value)?;
        Ok(Self {
            allowed: url.origin(),
        })
    }

    pub fn validate(&self, value: &str) -> Result<(), OriginError> {
        let url = parse_origin(value)?;
        if url.origin() == self.allowed {
            Ok(())
        } else {
            Err(OriginError::Disallowed)
        }
    }

    pub fn validate_header_values(&self, values: &[&[u8]]) -> Result<(), OriginError> {
        match values {
            [] => Err(OriginError::Missing),
            [value] => {
                self.validate(std::str::from_utf8(value).map_err(|_| OriginError::Malformed)?)
            }
            _ => Err(OriginError::Multiple),
        }
    }
}

fn parse_origin(value: &str) -> Result<Url, OriginError> {
    let url = Url::parse(value).map_err(|_| OriginError::Malformed)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OriginError::Malformed);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::{OriginError, OriginPolicy};

    #[test]
    fn exact_origin_is_allowed_and_confusable_origins_are_rejected() {
        let policy = OriginPolicy::new("https://ttygate.local:7681").unwrap();
        assert_eq!(policy.validate("https://ttygate.local:7681"), Ok(()));
        for value in [
            "",
            "null",
            "not a url",
            "http://ttygate.local:7681",
            "https://ttygate.local",
            "https://ttygate.local:7682",
            "https://ttygate.local.attacker.test:7681",
            "https://attacker.test",
            "https://user@ttygate.local:7681",
            "https://ttygate.local:7681/path",
            "https://ttygate.local:7681?query",
            "https://ttygate.local:7681#fragment",
        ] {
            assert_ne!(
                policy.validate(value),
                Ok(()),
                "unexpectedly allowed {value}"
            );
        }
    }

    #[test]
    fn request_header_validation_rejects_missing_duplicate_and_invalid_bytes() {
        let policy = OriginPolicy::new("https://ttygate.local").unwrap();
        assert_eq!(
            policy.validate_header_values(&[]),
            Err(OriginError::Missing)
        );
        assert_eq!(
            policy.validate_header_values(&[b"https://ttygate.local", b"https://ttygate.local"]),
            Err(OriginError::Multiple)
        );
        assert_eq!(
            policy.validate_header_values(&[b"\xff"]),
            Err(OriginError::Malformed)
        );
    }
}
