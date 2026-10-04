use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use ts_rs::TS;

macro_rules! error_codes {
    ($($variant:ident => $wire:literal,)*) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $($variant,)*
            Other(String),
        }

        impl ErrorCode {
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $wire,)*
                    Self::Other(code) => code,
                }
            }

            fn parse(code: &str) -> Self {
                match code {
                    $($wire => Self::$variant,)*
                    other => Self::Other(other.to_owned()),
                }
            }
        }
    };
}

error_codes! {
    InvalidParams => "invalidParams",
    NotFound => "notFound",
    Internal => "internal",
    Forbidden => "forbidden",
    Unauthorized => "unauthorized",
    Unavailable => "unavailable",
    Conflict => "conflict",
    Locked => "locked",
    Io => "io",
    Storage => "storage",
    Secrets => "secrets",
    InvalidManifest => "invalidManifest",
    InvalidSettings => "invalidSettings",
    DependencyFailed => "dependencyFailed",
    FrontendCommand => "frontendCommand",
    NotRegistered => "notRegistered",
    RateLimited => "rateLimited",
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ErrorCode {
    fn from(code: &str) -> Self {
        Self::parse(code)
    }
}

impl From<String> for ErrorCode {
    fn from(code: String) -> Self {
        Self::parse(&code)
    }
}

impl From<&String> for ErrorCode {
    fn from(code: &String) -> Self {
        Self::parse(code)
    }
}

impl From<ErrorCode> for String {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::Other(code) => code,
            known => known.as_str().to_owned(),
        }
    }
}

impl PartialEq<str> for ErrorCode {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ErrorCode {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(d)?))
    }
}

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[error("{code}: {message}")]
#[ts(export)]
pub struct KernelError {
    #[ts(type = "string")]
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub data: Option<Value>,
}

impl KernelError {
    pub fn new(code: impl Into<ErrorCode>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Io, message)
    }
}

pub type KernelResult<T> = Result<T, KernelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_travel_as_plain_strings() {
        let e = KernelError::new(ErrorCode::InvalidParams, "x");
        assert_eq!(
            serde_json::to_value(&e).unwrap(),
            serde_json::json!({ "code": "invalidParams", "message": "x" })
        );
        let custom = KernelError::new("busy", "y");
        assert_eq!(custom.code, ErrorCode::Other("busy".into()));
        assert_eq!(custom.code, "busy");
        let back: KernelError =
            serde_json::from_value(serde_json::json!({ "code": "notFound", "message": "z" }))
                .unwrap();
        assert_eq!(back.code, ErrorCode::NotFound);
        assert_eq!(KernelError::new("forbidden", "").code, ErrorCode::Forbidden);
    }
}
