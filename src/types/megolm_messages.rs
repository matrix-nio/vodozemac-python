use pyo3::{prelude::*, types::PyType};

use super::Ed25519Signature;
use crate::error::*;

#[pyclass]
pub struct MegolmMessage {
    pub(crate) inner: vodozemac::megolm::MegolmMessage,
}

#[pymethods]
impl MegolmMessage {
    #[classmethod]
    pub fn from_base64(_cls: &Bound<'_, PyType>, message: &str) -> Result<Self, DecodeError> {
        let message = vodozemac::megolm::MegolmMessage::from_base64(message)?;

        Ok(Self { inner: message })
    }

    #[classmethod]
    pub fn from_bytes(_cls: &Bound<'_, PyType>, message: &[u8]) -> Result<Self, DecodeError> {
        let message = vodozemac::megolm::MegolmMessage::from_bytes(message)?;

        Ok(Self { inner: message })
    }

    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn message_index(&self) -> u32 {
        self.inner.message_index()
    }

    pub fn signature(&self) -> Ed25519Signature {
        (*self.inner.signature()).into()
    }
}

impl From<vodozemac::megolm::MegolmMessage> for MegolmMessage {
    fn from(value: vodozemac::megolm::MegolmMessage) -> Self {
        Self { inner: value }
    }
}
