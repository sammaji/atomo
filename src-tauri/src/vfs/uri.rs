use std::fmt;
use std::path::{Component, Path, PathBuf, Prefix};

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use super::error::VfsError;

/// RFC 3986 unreserved characters (ALPHA / DIGIT / "-" / "." / "_" / "~") are left
/// unencoded, as is ':' (needed for Windows drive-letter segments like "C:" to
/// round-trip losslessly); everything else in the ASCII range is escaped.
/// Non-ASCII bytes are always escaped by `utf8_percent_encode` regardless of
/// this set.
const SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct VfsUri {
    scheme: String,
    authority: String,
    segments: Vec<String>,
}

fn validate_scheme(raw: &str) -> Result<String, VfsError> {
    if raw.is_empty() {
        return Err(VfsError::InvalidUri("empty scheme".into()));
    }
    let lowered = raw.to_ascii_lowercase();
    let mut chars = lowered.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(VfsError::InvalidUri(format!("invalid scheme: {raw}")));
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+' || c == '-') {
        return Err(VfsError::InvalidUri(format!("invalid scheme: {raw}")));
    }
    Ok(lowered)
}

fn validate_segment(seg: &str) -> Result<(), VfsError> {
    if seg.is_empty() {
        return Err(VfsError::InvalidUri("empty path segment".into()));
    }
    if seg == "." || seg == ".." {
        return Err(VfsError::InvalidUri(format!(
            "path traversal segment not allowed: {seg}"
        )));
    }
    Ok(())
}

fn decode_segment(raw: &str) -> Result<String, VfsError> {
    percent_decode_str(raw)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| VfsError::InvalidUri(format!("invalid percent-encoding in segment: {raw}")))
}

impl VfsUri {
    pub fn parse(s: &str) -> Result<Self, VfsError> {
        let (scheme_raw, rest) = s
            .split_once("://")
            .ok_or_else(|| VfsError::InvalidUri(format!("missing scheme separator: {s}")))?;
        let scheme = validate_scheme(scheme_raw)?;

        let (authority, path_raw) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };

        let mut segments = Vec::new();
        if !path_raw.is_empty() {
            // path_raw starts with '/' (or is empty); strip it before splitting.
            let trimmed = path_raw.trim_end_matches('/');
            let body = trimmed.strip_prefix('/').unwrap_or(trimmed);
            if !body.is_empty() {
                for raw_seg in body.split('/') {
                    validate_segment(raw_seg)?;
                    segments.push(decode_segment(raw_seg)?);
                }
            }
        }

        Ok(VfsUri {
            scheme,
            authority: authority.to_string(),
            segments,
        })
    }

    pub fn from_local_path(p: &Path) -> Result<Self, VfsError> {
        let mut segments = Vec::new();
        for component in p.components() {
            match component {
                Component::Prefix(prefix) => {
                    if let Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) = prefix.kind() {
                        segments.push(format!("{}:", letter as char));
                    }
                }
                Component::RootDir => {}
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(VfsError::InvalidUri("local path contains '..'".to_string()))
                }
                Component::Normal(part) => {
                    let s = part.to_str().ok_or_else(|| {
                        VfsError::InvalidUri("local path is not valid UTF-8".to_string())
                    })?;
                    segments.push(s.to_string());
                }
            }
        }
        Ok(VfsUri {
            scheme: "file".to_string(),
            authority: String::new(),
            segments,
        })
    }

    pub fn to_local_path(&self) -> Result<PathBuf, VfsError> {
        if self.scheme != "file" {
            return Err(VfsError::InvalidUri(format!(
                "cannot convert non-file uri to a local path: {self}"
            )));
        }
        let mut path = PathBuf::new();
        if let Some(first) = self.segments.first() {
            if is_drive_letter(first) {
                path.push(format!("{first}\\"));
                for seg in &self.segments[1..] {
                    path.push(seg);
                }
                return Ok(path);
            }
        }
        path.push("/");
        for seg in &self.segments {
            path.push(seg);
        }
        Ok(path)
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Part of the documented `VfsUri` contract (not yet called by M1 code).
    #[allow(dead_code)]
    pub fn path(&self) -> String {
        format!("/{}", self.segments.join("/"))
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.segments.iter().map(|s| s.as_str())
    }

    pub fn name(&self) -> Option<&str> {
        self.segments.last().map(|s| s.as_str())
    }

    pub fn parent(&self) -> Option<VfsUri> {
        if self.segments.is_empty() {
            return None;
        }
        let mut segments = self.segments.clone();
        segments.pop();
        Some(VfsUri {
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            segments,
        })
    }

    pub fn join(&self, segment: &str) -> Result<VfsUri, VfsError> {
        validate_segment(segment)?;
        if segment.contains('/') {
            return Err(VfsError::InvalidUri(format!(
                "segment may not contain '/': {segment}"
            )));
        }
        let mut segments = self.segments.clone();
        segments.push(segment.to_string());
        Ok(VfsUri {
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            segments,
        })
    }

    /// Part of the documented `VfsUri` contract (not yet called by M1 code).
    #[allow(dead_code)]
    pub fn with_name(&self, name: &str) -> Result<VfsUri, VfsError> {
        match self.parent() {
            Some(parent) => parent.join(name),
            None => {
                validate_segment(name)?;
                if name.contains('/') {
                    return Err(VfsError::InvalidUri(format!(
                        "segment may not contain '/': {name}"
                    )));
                }
                Ok(VfsUri {
                    scheme: self.scheme.clone(),
                    authority: self.authority.clone(),
                    segments: vec![name.to_string()],
                })
            }
        }
    }

    /// Segment-wise ancestry: `file:///a/b` is an ancestor of `file:///a/b/c`
    /// but NOT of `file:///a/bc` (a plain string-prefix check would get this wrong).
    pub fn is_ancestor_of(&self, other: &VfsUri) -> bool {
        if self.scheme != other.scheme || self.authority != other.authority {
            return false;
        }
        if self.segments.len() >= other.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(other.segments.iter())
            .all(|(a, b)| a == b)
    }
}

fn is_drive_letter(seg: &str) -> bool {
    seg.len() == 2 && seg.as_bytes()[1] == b':' && seg.as_bytes()[0].is_ascii_alphabetic()
}

impl fmt::Display for VfsUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}/", self.scheme, self.authority)?;
        let encoded: Vec<String> = self
            .segments
            .iter()
            .map(|s| utf8_percent_encode(s, SEGMENT_ENCODE_SET).to_string())
            .collect();
        write!(f, "{}", encoded.join("/"))
    }
}

impl Serialize for VfsUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VfsUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        VfsUri::parse(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_display_round_trip() {
        let cases = ["file:///Users/x/doc.md", "mem://test/a/b", "file:///"];
        for c in cases {
            let uri = VfsUri::parse(c).unwrap();
            assert_eq!(uri.to_string(), c);
        }
    }

    #[test]
    fn scheme_is_case_folded() {
        let uri = VfsUri::parse("FILE:///a").unwrap();
        assert_eq!(uri.scheme(), "file");
    }

    #[test]
    fn rejects_bad_scheme() {
        assert!(VfsUri::parse("1file:///a").is_err());
        assert!(VfsUri::parse("://a").is_err());
        assert!(VfsUri::parse("fi le:///a").is_err());
    }

    #[test]
    fn percent_encodes_special_and_unicode_segments() {
        let uri = VfsUri::parse("file:///").unwrap().join("a b#c%d").unwrap();
        assert_eq!(uri.to_string(), "file:///a%20b%23c%25d");

        let uri = VfsUri::parse("file:///").unwrap().join("café").unwrap();
        assert_eq!(uri.to_string(), "file:///caf%C3%A9");
        assert_eq!(uri.name(), Some("café"));
    }

    #[test]
    fn rejects_dot_segments_and_empty_segments() {
        assert!(VfsUri::parse("file:///a/../b").is_err());
        assert!(VfsUri::parse("file:///a/./b").is_err());
        assert!(VfsUri::parse("file:///a//b").is_err());
    }

    #[test]
    fn join_rejects_slash_and_dotdot() {
        let root = VfsUri::parse("file:///a").unwrap();
        assert!(root.join("b/c").is_err());
        assert!(root.join("..").is_err());
        assert!(root.join("").is_err());
    }

    #[test]
    fn parent_at_root_is_none() {
        let root = VfsUri::parse("file:///").unwrap();
        assert!(root.parent().is_none());
        let one = VfsUri::parse("file:///a").unwrap();
        assert_eq!(one.parent().unwrap().to_string(), "file:///");
    }

    #[test]
    fn is_ancestor_of_is_segment_wise() {
        let a_b = VfsUri::parse("file:///a/b").unwrap();
        let a_b_c = VfsUri::parse("file:///a/b/c").unwrap();
        let a_bc = VfsUri::parse("file:///a/bc").unwrap();
        assert!(a_b.is_ancestor_of(&a_b_c));
        assert!(!a_b.is_ancestor_of(&a_bc));
        assert!(!a_b.is_ancestor_of(&a_b));
    }

    #[test]
    fn windows_drive_letter_round_trip() {
        let uri = VfsUri::parse("file:///C:/Users/x").unwrap();
        assert_eq!(uri.to_string(), "file:///C:/Users/x");
        assert_eq!(uri.segments().collect::<Vec<_>>(), vec!["C:", "Users", "x"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_local_path_round_trip() {
        let path = std::path::PathBuf::from("C:\\Users\\x\\doc.md");
        let uri = VfsUri::from_local_path(&path).unwrap();
        assert_eq!(uri.to_string(), "file:///C:/Users/x/doc.md");
        assert_eq!(uri.to_local_path().unwrap(), path);
    }

    #[cfg(unix)]
    #[test]
    fn unix_local_path_round_trip() {
        let path = std::path::PathBuf::from("/Users/x/doc.md");
        let uri = VfsUri::from_local_path(&path).unwrap();
        assert_eq!(uri.to_string(), "file:///Users/x/doc.md");
        assert_eq!(uri.to_local_path().unwrap(), path);
    }
}
