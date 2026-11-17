use super::wire::Wire;
use crate::runtime_wire::fields::uint;
use ciborium::value::Value;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

pub(super) fn invalid<T>() -> RuntimeResult<T> {
    Err(RuntimeError::InvalidInput)
}
fn text(value: &Value) -> RuntimeResult<String> {
    value
        .as_text()
        .map(str::to_owned)
        .ok_or(RuntimeError::InvalidInput)
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> RuntimeResult<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid();
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| RuntimeError::InvalidInput))
        .collect()
}
macro_rules! string_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
        pub struct $name(pub String);
    };
}
string_type!(DomainUuid);
impl Wire for DomainUuid {
    fn encode_value(&self) -> RuntimeResult<Value> {
        let s = &self.0;
        if s.len() != 36 || [8, 13, 18, 23].iter().any(|i| s.as_bytes()[*i] != b'-') {
            return invalid();
        }
        let bytes = unhex(&s.replace('-', ""))?;
        if bytes.len() != 16 || !(1..=8).contains(&(bytes[6] >> 4)) || bytes[8] >> 6 != 2 {
            return invalid();
        }
        Ok(Value::Bytes(bytes))
    }
    fn decode_value(value: &Value) -> RuntimeResult<Self> {
        let b = value
            .as_bytes()
            .filter(|b| b.len() == 16)
            .ok_or(RuntimeError::InvalidInput)?;
        let h = hex(b);
        let out = Self(format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        ));
        out.encode_value()?;
        Ok(out)
    }
}
string_type!(Hash32);
impl Wire for Hash32 {
    fn encode_value(&self) -> RuntimeResult<Value> {
        let s = self
            .0
            .strip_prefix("sha256:")
            .filter(|s| s.len() == 64)
            .ok_or(RuntimeError::InvalidInput)?;
        Ok(Value::Bytes(unhex(s)?))
    }
    fn decode_value(value: &Value) -> RuntimeResult<Self> {
        let b = value
            .as_bytes()
            .filter(|b| b.len() == 32)
            .ok_or(RuntimeError::InvalidInput)?;
        Ok(Self(format!("sha256:{}", hex(b))))
    }
}
string_type!(Identifier);
impl Wire for Identifier {
    fn encode_value(&self) -> RuntimeResult<Value> {
        let b = self.0.as_bytes();
        if b.is_empty()
            || b.len() > 160
            || !b[0].is_ascii_alphanumeric()
            || !b
                .iter()
                .all(|v| v.is_ascii_alphanumeric() || b":._/-".contains(v))
        {
            return invalid();
        }
        Ok(Value::Text(self.0.clone()))
    }
    fn decode_value(value: &Value) -> RuntimeResult<Self> {
        let out = Self(text(value)?);
        out.encode_value()?;
        Ok(out)
    }
}
string_type!(ActionIntent);
impl Wire for ActionIntent {
    fn encode_value(&self) -> RuntimeResult<Value> {
        Identifier(self.0.clone()).encode_value()?;
        let (name, version) = self
            .0
            .strip_prefix("ACT-")
            .and_then(|s| s.rsplit_once("-V"))
            .ok_or(RuntimeError::InvalidInput)?;
        if name.is_empty()
            || !name.as_bytes()[0].is_ascii_uppercase()
            || !name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            || version.is_empty()
            || version.starts_with('0')
            || !version.bytes().all(|b| b.is_ascii_digit())
        {
            return invalid();
        }
        Ok(Value::Text(self.0.clone()))
    }
    fn decode_value(value: &Value) -> RuntimeResult<Self> {
        let out = Self(text(value)?);
        out.encode_value()?;
        Ok(out)
    }
}
macro_rules! decimal {
    ($name:ident, $positive:expr, $multiple:expr) => {
        string_type!($name);
        impl $name {
            pub fn value(&self) -> RuntimeResult<u64> {
                let s = &self.0;
                if s.is_empty()
                    || (s.len() > 1 && s.starts_with('0'))
                    || !s.bytes().all(|b| b.is_ascii_digit())
                {
                    return invalid();
                }
                let n = s.parse::<u64>().map_err(|_| RuntimeError::InvalidInput)?;
                if ($positive && n == 0) || !n.is_multiple_of($multiple) {
                    return invalid();
                }
                Ok(n)
            }
        }
        impl Wire for $name {
            fn encode_value(&self) -> RuntimeResult<Value> {
                Ok(uint(self.value()?))
            }
            fn decode_value(value: &Value) -> RuntimeResult<Self> {
                let n = crate::runtime_wire::fields::number(value)?;
                let out = Self(n.to_string());
                out.value()?;
                Ok(out)
            }
        }
    };
}
decimal!(Unsigned, false, 1);
decimal!(Positive, true, 1);
decimal!(Nanos, false, 1000);
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Flag(pub bool);
impl Wire for Flag {
    fn encode_value(&self) -> RuntimeResult<Value> {
        Ok(uint(u64::from(self.0)))
    }
    fn decode_value(v: &Value) -> RuntimeResult<Self> {
        match crate::runtime_wire::fields::number(v)? {
            0 => Ok(Self(false)),
            1 => Ok(Self(true)),
            _ => invalid(),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Depth(pub u8);
impl Wire for Depth {
    fn encode_value(&self) -> RuntimeResult<Value> {
        if self.0 > 32 {
            return invalid();
        }
        Ok(uint(u64::from(self.0)))
    }
    fn decode_value(v: &Value) -> RuntimeResult<Self> {
        let n = crate::runtime_wire::fields::number(v)?;
        if n > 32 {
            return invalid();
        }
        Ok(Self(n as u8))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FiniteSet<T>(pub Vec<T>);
impl<T: Wire + Ord> Wire for FiniteSet<T> {
    fn encode_value(&self) -> RuntimeResult<Value> {
        if self.0.len() > 256 || self.0.windows(2).any(|v| v[0] >= v[1]) {
            return invalid();
        }
        Ok(Value::Array(
            self.0
                .iter()
                .map(Wire::encode_value)
                .collect::<RuntimeResult<_>>()?,
        ))
    }
    fn decode_value(v: &Value) -> RuntimeResult<Self> {
        let out = Self(
            v.as_array()
                .ok_or(RuntimeError::InvalidInput)?
                .iter()
                .map(T::decode_value)
                .collect::<RuntimeResult<_>>()?,
        );
        out.encode_value()?;
        Ok(out)
    }
}
macro_rules! text_enum {
    ($name:ident, $($variant:ident => $text:literal),+ $(,)?) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename=$text)] $variant),+ }
        impl $name { fn as_str(&self)->&'static str {match self {$(Self::$variant=>$text),+}} }
        impl Ord for $name {fn cmp(&self,other:&Self)->std::cmp::Ordering {self.as_str().cmp(other.as_str())}}
        impl PartialOrd for $name {fn partial_cmp(&self,other:&Self)->Option<std::cmp::Ordering>{Some(self.cmp(other))}}
        impl Wire for $name {
            fn encode_value(&self)->RuntimeResult<Value>{Ok(Value::Text(self.as_str().to_owned()))}
            fn decode_value(v:&Value)->RuntimeResult<Self>{match v.as_text() {$(Some($text)=>Ok(Self::$variant),)+_=>invalid()}}
        }
    };
}
text_enum!(Risk, BreakGlass=>"BREAK_GLASS", High=>"HIGH", Low=>"LOW", Standard=>"STANDARD");
text_enum!(RuntimeCapability, AccessList=>"ACCESS_LIST_DISCLOSURE", Call=>"CALL_RESULT_DISCLOSURE", Gas=>"GAS_ESTIMATE_DISCLOSURE", MultiCall=>"MULTI_CALL_SIMULATION_DISCLOSURE", Status=>"OPERATION_STATUS_DISCLOSURE", Submit=>"SIGNED_TRANSACTION_SUBMISSION", Prepare=>"UNSIGNED_TRANSACTION_PREPARATION");
macro_rules! number_enum {
    ($name:ident, $($variant:ident => ($text:literal,$code:literal)),+ $(,)?) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename=$text)] $variant),+ }
        impl Wire for $name {
            fn encode_value(&self)->RuntimeResult<Value>{Ok(uint(match self {$(Self::$variant=>$code),+}))}
            fn decode_value(v:&Value)->RuntimeResult<Self>{match crate::runtime_wire::fields::number(v)? {$($code=>Ok(Self::$variant),)+_=>invalid()}}
        }
    };
}
number_enum!(IssuerKind, Platform=>("PLATFORM",1),Participant=>("PARTICIPANT",2));
number_enum!(Issuance, PlatformRoot=>("PLATFORM_ROOT",1),Child=>("CHILD",2),Rotation=>("ROTATION",3));
number_enum!(ActivateAction, Activate=>("ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1",1));
number_enum!(ActivateOperation, Activate=>("ID-OP-ENVELOPE-ACTIVATE",1));
