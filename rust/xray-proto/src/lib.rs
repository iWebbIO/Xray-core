//! Bindings generated from every original Xray protobuf schema.
//! The schemas remain the wire-format source of truth for both implementations.

// Generated names and comments mirror the shared schemas verbatim.
#[allow(clippy::module_inception, clippy::doc_lazy_continuation)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/xray.rs"));
}
pub use generated::*;

pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/xray_descriptor.bin"));

#[derive(Debug)]
pub enum UnpackError {
    TypeMismatch { expected: String, actual: String },
    Decode(prost::DecodeError),
}

impl std::fmt::Display for UnpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeMismatch { expected, actual } => {
                write!(f, "expected {expected}, got {actual}")
            }
            Self::Decode(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for UnpackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

impl xray::common::serial::TypedMessage {
    pub fn pack<M: prost::Message + prost::Name>(message: &M) -> Self {
        Self {
            r#type: M::full_name(),
            value: message.encode_to_vec(),
        }
    }

    pub fn unpack<M: prost::Message + prost::Name + Default>(&self) -> Result<M, UnpackError> {
        if self.r#type != M::full_name() {
            return Err(UnpackError::TypeMismatch {
                expected: M::full_name(),
                actual: self.r#type.clone(),
            });
        }
        M::decode(self.value.as_slice()).map_err(UnpackError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::xray::{common::serial::TypedMessage, core::Config};
    use prost::Message;

    #[test]
    fn typed_messages_preserve_xray_type_names() {
        let config = Config::default();
        let wrapped = TypedMessage::pack(&config);
        assert_eq!(wrapped.r#type, "xray.core.Config");
        assert_eq!(wrapped.unpack::<Config>().unwrap(), config);
        assert!(wrapped.unpack::<TypedMessage>().is_err());
        assert_eq!(
            TypedMessage::decode(wrapped.encode_to_vec().as_slice()).unwrap(),
            wrapped
        );
        assert!(!super::FILE_DESCRIPTOR_SET.is_empty());
    }
}
