use std::collections::HashSet;
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_CONTROL_BYTES: usize = 4_096;
pub const MAX_BINARY_BYTES: usize = 65_536;
pub const MAX_DIMENSION: u16 = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    TerminalInput(Vec<u8>),
    Control(ClientControl),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFrame {
    TerminalOutput(Vec<u8>),
    Control(ServerControl),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientControl {
    Resize(Resize),
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resize {
    pub cols: u16,
    pub rows: u16,
}

impl Resize {
    pub fn new(cols: u16, rows: u16) -> Result<Self, ProtocolError> {
        if !(1..=MAX_DIMENSION).contains(&cols) || !(1..=MAX_DIMENSION).contains(&rows) {
            return Err(ProtocolError::InvalidField);
        }
        Ok(Self { cols, rows })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerControl {
    ExitStatus(ExitStatus),
    Error(ProtocolErrorMessage),
    Close(CloseReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    Code(u8),
    Signal(u8),
    Unavailable,
}

impl ExitStatus {
    pub fn code(code: u16) -> Result<Self, ProtocolError> {
        u8::try_from(code)
            .map(Self::Code)
            .map_err(|_| ProtocolError::InvalidField)
    }

    pub fn signal(signal: u8) -> Result<Self, ProtocolError> {
        if (1..=127).contains(&signal) {
            Ok(Self::Signal(signal))
        } else {
            Err(ProtocolError::InvalidField)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolErrorMessage {
    pub code: String,
    pub message: String,
}

impl ProtocolErrorMessage {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = Self {
            code: code.into(),
            message: message.into(),
        };
        if valid_error_code(&value.code) && valid_error_message(&value.message) {
            Ok(value)
        } else {
            Err(ProtocolError::InvalidField)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloseReason {
    ClientRequest,
    Exited,
    Timeout,
    Policy,
    ProtocolError,
    TransportError,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    BinaryTooLarge,
    ControlTooLarge,
    MalformedText,
    MalformedControl,
    InvalidControl,
    DuplicateField,
    MissingField,
    UnknownField,
    UnknownMessageType,
    UnsupportedVersion,
    InvalidDirection,
    InvalidField,
}

impl ProtocolError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::BinaryTooLarge => "binary-too-large",
            Self::ControlTooLarge => "control-too-large",
            Self::MalformedText => "malformed-text",
            Self::MalformedControl => "malformed-control",
            Self::InvalidControl => "invalid-control",
            Self::DuplicateField => "duplicate-field",
            Self::MissingField => "missing-field",
            Self::UnknownField => "unknown-field",
            Self::UnknownMessageType => "unknown-message-type",
            Self::UnsupportedVersion => "unsupported-version",
            Self::InvalidDirection => "invalid-direction",
            Self::InvalidField => "invalid-field",
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProtocolError {}

pub fn decode_client_binary(bytes: &[u8]) -> Result<ClientFrame, ProtocolError> {
    check_binary_len(bytes)?;
    Ok(ClientFrame::TerminalInput(bytes.to_vec()))
}

pub fn decode_server_binary(bytes: &[u8]) -> Result<ServerFrame, ProtocolError> {
    check_binary_len(bytes)?;
    Ok(ServerFrame::TerminalOutput(bytes.to_vec()))
}

pub fn decode_client_control(bytes: &[u8]) -> Result<ClientControl, ProtocolError> {
    let object = parse_control(bytes)?;
    let message_type = header(&object)?;
    match message_type {
        "resize" => {
            exact_keys(&object, &["version", "type", "cols", "rows"])?;
            let cols = dimension(&object, "cols")?;
            let rows = dimension(&object, "rows")?;
            Ok(ClientControl::Resize(Resize { cols, rows }))
        }
        "close" => {
            if object.contains_key("reason") {
                return Err(ProtocolError::InvalidDirection);
            }
            exact_keys(&object, &["version", "type"])?;
            Ok(ClientControl::Close)
        }
        "exit-status" | "error" => Err(ProtocolError::InvalidDirection),
        _ => Err(ProtocolError::UnknownMessageType),
    }
}

pub fn decode_server_control(bytes: &[u8]) -> Result<ServerControl, ProtocolError> {
    let object = parse_control(bytes)?;
    let message_type = header(&object)?;
    match message_type {
        "exit-status" => {
            exact_keys(&object, &["version", "type", "status"])?;
            Ok(ServerControl::ExitStatus(parse_exit_status(field(
                &object, "status",
            )?)?))
        }
        "error" => {
            exact_keys(&object, &["version", "type", "code", "message"])?;
            let code = string_field(&object, "code")?;
            let message = string_field(&object, "message")?;
            Ok(ServerControl::Error(ProtocolErrorMessage::new(
                code, message,
            )?))
        }
        "close" => {
            if object.len() == 2 && object.contains_key("version") && object.contains_key("type") {
                return Err(ProtocolError::InvalidDirection);
            }
            exact_keys(&object, &["version", "type", "reason"])?;
            Ok(ServerControl::Close(parse_close_reason(string_field(
                &object, "reason",
            )?)?))
        }
        "resize" => Err(ProtocolError::InvalidDirection),
        _ => Err(ProtocolError::UnknownMessageType),
    }
}

pub fn encode_client_control(message: &ClientControl) -> Result<String, ProtocolError> {
    match message {
        ClientControl::Resize(resize) => {
            Resize::new(resize.cols, resize.rows)?;
            serialize(&ClientResizeWire {
                version: PROTOCOL_VERSION,
                message_type: "resize",
                cols: resize.cols,
                rows: resize.rows,
            })
        }
        ClientControl::Close => serialize(&CloseWire {
            version: PROTOCOL_VERSION,
            message_type: "close",
        }),
    }
}

pub fn encode_server_control(message: &ServerControl) -> Result<String, ProtocolError> {
    match message {
        ServerControl::ExitStatus(status) => serialize(&ExitStatusWire {
            version: PROTOCOL_VERSION,
            message_type: "exit-status",
            status: StatusWire::try_from(status)?,
        }),
        ServerControl::Error(error) => {
            let error = ProtocolErrorMessage::new(error.code.clone(), error.message.clone())?;
            serialize(&ErrorWire {
                version: PROTOCOL_VERSION,
                message_type: "error",
                code: &error.code,
                message: &error.message,
            })
        }
        ServerControl::Close(reason) => serialize(&ServerCloseWire {
            version: PROTOCOL_VERSION,
            message_type: "close",
            reason,
        }),
    }
}

fn check_binary_len(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.len() > MAX_BINARY_BYTES {
        Err(ProtocolError::BinaryTooLarge)
    } else {
        Ok(())
    }
}

fn parse_control(bytes: &[u8]) -> Result<Map<String, Value>, ProtocolError> {
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(ProtocolError::ControlTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::MalformedText)?;
    detect_duplicate_fields(text)?;
    let value: Value = serde_json::from_str(text).map_err(classify_json_error)?;
    value
        .as_object()
        .cloned()
        .ok_or(ProtocolError::InvalidControl)
}

fn header(object: &Map<String, Value>) -> Result<&str, ProtocolError> {
    let version = field(object, "version")?;
    let Some(version) = version.as_u64() else {
        return Err(ProtocolError::InvalidField);
    };
    if version != u64::from(PROTOCOL_VERSION) {
        return Err(ProtocolError::UnsupportedVersion);
    }
    string_field(object, "type")
}

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ProtocolError> {
    object.get(key).ok_or(ProtocolError::MissingField)
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ProtocolError> {
    field(object, key)?
        .as_str()
        .ok_or(ProtocolError::InvalidField)
}

fn exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<(), ProtocolError> {
    if expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(ProtocolError::MissingField);
    }
    if object.keys().any(|key| !expected.contains(&key.as_str())) {
        return Err(ProtocolError::UnknownField);
    }
    Ok(())
}

fn dimension(object: &Map<String, Value>, key: &str) -> Result<u16, ProtocolError> {
    let value = field(object, key)?
        .as_u64()
        .ok_or(ProtocolError::InvalidField)?;
    let value = u16::try_from(value).map_err(|_| ProtocolError::InvalidField)?;
    if (1..=MAX_DIMENSION).contains(&value) {
        Ok(value)
    } else {
        Err(ProtocolError::InvalidField)
    }
}

fn parse_exit_status(value: &Value) -> Result<ExitStatus, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError::InvalidField)?;
    match string_field(object, "kind")? {
        "code" => {
            exact_keys(object, &["kind", "code"])?;
            let value = field(object, "code")?
                .as_u64()
                .ok_or(ProtocolError::InvalidField)?;
            ExitStatus::code(u16::try_from(value).map_err(|_| ProtocolError::InvalidField)?)
        }
        "signal" => {
            exact_keys(object, &["kind", "signal"])?;
            let value = field(object, "signal")?
                .as_u64()
                .ok_or(ProtocolError::InvalidField)?;
            ExitStatus::signal(u8::try_from(value).map_err(|_| ProtocolError::InvalidField)?)
        }
        "unavailable" => {
            exact_keys(object, &["kind"])?;
            Ok(ExitStatus::Unavailable)
        }
        _ => Err(ProtocolError::InvalidField),
    }
}

fn parse_close_reason(reason: &str) -> Result<CloseReason, ProtocolError> {
    match reason {
        "client-request" => Ok(CloseReason::ClientRequest),
        "exited" => Ok(CloseReason::Exited),
        "timeout" => Ok(CloseReason::Timeout),
        "policy" => Ok(CloseReason::Policy),
        "protocol-error" => Ok(CloseReason::ProtocolError),
        "transport-error" => Ok(CloseReason::TransportError),
        "internal-error" => Ok(CloseReason::InternalError),
        _ => Err(ProtocolError::InvalidField),
    }
}

fn valid_error_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

fn valid_error_message(message: &str) -> bool {
    let count = message.chars().count();
    (1..=256).contains(&count)
        && !message
            .chars()
            .any(|character| character.is_ascii_control())
}

fn serialize(value: &impl Serialize) -> Result<String, ProtocolError> {
    let encoded = serde_json::to_string(value).map_err(|_| ProtocolError::InvalidField)?;
    if encoded.len() > MAX_CONTROL_BYTES {
        Err(ProtocolError::ControlTooLarge)
    } else {
        Ok(encoded)
    }
}

fn detect_duplicate_fields(text: &str) -> Result<(), ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    DuplicateDetector::deserialize(&mut deserializer)
        .map(|_| ())
        .map_err(|error| {
            let error = error.to_string();
            if error.starts_with("duplicate field") {
                ProtocolError::DuplicateField
            } else if error.contains("surrogate") || error.contains("unexpected end of hex escape")
            {
                ProtocolError::InvalidField
            } else {
                ProtocolError::MalformedControl
            }
        })
}

fn classify_json_error(error: serde_json::Error) -> ProtocolError {
    let error = error.to_string();
    if error.contains("surrogate") || error.contains("unexpected end of hex escape") {
        ProtocolError::InvalidField
    } else {
        ProtocolError::MalformedControl
    }
}

struct DuplicateDetector;

impl<'de> Deserialize<'de> for DuplicateDetector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}

struct DuplicateVisitor;

impl<'de> Visitor<'de> for DuplicateVisitor {
    type Value = DuplicateDetector;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON value")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate field"));
            }
            map.next_value::<DuplicateDetector>()?;
        }
        Ok(DuplicateDetector)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateDetector>()?.is_some() {}
        Ok(DuplicateDetector)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateDetector)
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateDetector::deserialize(deserializer)
    }
}

#[derive(Serialize)]
struct ClientResizeWire<'a> {
    version: u8,
    #[serde(rename = "type")]
    message_type: &'a str,
    cols: u16,
    rows: u16,
}

#[derive(Serialize)]
struct CloseWire<'a> {
    version: u8,
    #[serde(rename = "type")]
    message_type: &'a str,
}

#[derive(Serialize)]
struct ExitStatusWire<'a> {
    version: u8,
    #[serde(rename = "type")]
    message_type: &'a str,
    status: StatusWire,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum StatusWire {
    Code { code: u8 },
    Signal { signal: u8 },
    Unavailable,
}

impl TryFrom<&ExitStatus> for StatusWire {
    type Error = ProtocolError;

    fn try_from(status: &ExitStatus) -> Result<Self, Self::Error> {
        match status {
            ExitStatus::Code(code) => Ok(Self::Code { code: *code }),
            ExitStatus::Signal(signal) if (1..=127).contains(signal) => {
                Ok(Self::Signal { signal: *signal })
            }
            ExitStatus::Signal(_) => Err(ProtocolError::InvalidField),
            ExitStatus::Unavailable => Ok(Self::Unavailable),
        }
    }
}

#[derive(Serialize)]
struct ErrorWire<'a> {
    version: u8,
    #[serde(rename = "type")]
    message_type: &'a str,
    code: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct ServerCloseWire<'a> {
    version: u8,
    #[serde(rename = "type")]
    message_type: &'a str,
    reason: &'a CloseReason,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixtures {
        protocol_version: u8,
        max_control_bytes: usize,
        max_binary_bytes: usize,
        valid: Vec<ValidFixture>,
        invalid: Vec<InvalidFixture>,
    }

    #[derive(Deserialize)]
    struct ValidFixture {
        name: String,
        direction: String,
        wire: String,
    }

    #[derive(Deserialize)]
    struct InvalidFixture {
        name: String,
        direction: String,
        wire: String,
        error: String,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../../../protocol/fixtures.json")).unwrap()
    }

    #[test]
    fn shared_constants_match() {
        let fixtures = fixtures();
        assert_eq!(
            usize::from(fixtures.protocol_version),
            usize::from(PROTOCOL_VERSION)
        );
        assert_eq!(fixtures.max_control_bytes, MAX_CONTROL_BYTES);
        assert_eq!(fixtures.max_binary_bytes, MAX_BINARY_BYTES);
    }

    #[test]
    fn valid_shared_fixtures_round_trip_exactly() {
        for fixture in fixtures().valid {
            let encoded = match fixture.direction.as_str() {
                "client" => {
                    encode_client_control(&decode_client_control(fixture.wire.as_bytes()).unwrap())
                        .unwrap()
                }
                "server" => {
                    encode_server_control(&decode_server_control(fixture.wire.as_bytes()).unwrap())
                        .unwrap()
                }
                other => panic!("unknown fixture direction {other}"),
            };
            assert_eq!(encoded, fixture.wire, "{}", fixture.name);
        }
    }

    #[test]
    fn invalid_shared_fixtures_have_stable_safe_errors() {
        for fixture in fixtures().invalid {
            let hostile = fixture.wire.clone();
            let error = match fixture.direction.as_str() {
                "client" => decode_client_control(fixture.wire.as_bytes()).unwrap_err(),
                "server" => decode_server_control(fixture.wire.as_bytes()).unwrap_err(),
                other => panic!("unknown fixture direction {other}"),
            };
            assert_eq!(error.code(), fixture.error, "{}", fixture.name);
            assert!(
                !error.to_string().contains(&hostile),
                "{} reflected input",
                fixture.name
            );
        }
    }

    #[test]
    fn binary_frames_accept_empty_and_maximum_but_reject_oversize() {
        assert_eq!(
            decode_client_binary(&[]).unwrap(),
            ClientFrame::TerminalInput(vec![])
        );
        assert_eq!(
            decode_server_binary(&vec![7; MAX_BINARY_BYTES]).unwrap(),
            ServerFrame::TerminalOutput(vec![7; MAX_BINARY_BYTES])
        );
        assert_eq!(
            decode_client_binary(&vec![0; MAX_BINARY_BYTES + 1])
                .unwrap_err()
                .code(),
            "binary-too-large"
        );
    }

    #[test]
    fn text_boundary_rejects_invalid_utf8_and_oversize_before_parsing() {
        assert_eq!(
            decode_client_control(&[0xff]).unwrap_err().code(),
            "malformed-text"
        );
        let oversized = vec![b' '; MAX_CONTROL_BYTES + 1];
        assert_eq!(
            decode_client_control(&oversized).unwrap_err().code(),
            "control-too-large"
        );

        let prefix = b"{\"version\":1,\"type\":\"close\",\"padding\":\"";
        let suffix = b"\"}";
        let mut maximum = Vec::from(prefix.as_slice());
        maximum.resize(MAX_CONTROL_BYTES - suffix.len(), b'a');
        maximum.extend_from_slice(suffix);
        assert_eq!(maximum.len(), MAX_CONTROL_BYTES);
        assert_eq!(
            decode_client_control(&maximum).unwrap_err().code(),
            "unknown-field"
        );
    }

    #[test]
    fn constructors_reject_values_that_cannot_be_encoded() {
        assert!(Resize::new(0, 24).is_err());
        assert!(ExitStatus::code(256).is_err());
        assert!(ExitStatus::signal(0).is_err());
        assert!(ProtocolErrorMessage::new("Bad_Code", "safe").is_err());
        assert!(ProtocolErrorMessage::new("safe-code", "bad\nmessage").is_err());
        assert!(ProtocolErrorMessage::new("a".repeat(65), "safe").is_err());
        assert!(ProtocolErrorMessage::new("safe-code", "a".repeat(257)).is_err());
    }
}
