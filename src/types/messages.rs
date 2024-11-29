use pyo3::{
    prelude::*,
    types::{PyBytes, PyType},
};

use crate::{convert_to_pybytes, error::*};

#[pyclass]
pub struct AnyOlmMessage {
    pub(crate) inner: vodozemac::olm::OlmMessage,
}

#[pymethods]
impl AnyOlmMessage {
    #[classmethod]
    pub fn pre_key(_cls: &Bound<'_, PyType>, message: &[u8]) -> Result<Self, SessionError> {
        Ok(Self { inner: vodozemac::olm::PreKeyMessage::from_bytes(message)?.into() })
    }

    #[classmethod]
    pub fn normal(_cls: &Bound<'_, PyType>, message: &[u8]) -> Result<Self, SessionError> {
        Ok(Self { inner: vodozemac::olm::Message::from_bytes(message)?.into() })
    }

    pub fn to_pre_key(&self) -> Option<PreKeyMessage> {
        if let vodozemac::olm::OlmMessage::PreKey(message) = &self.inner {
            Some(PreKeyMessage { inner: message.clone() })
        } else {
            None
        }
    }

    #[classmethod]
    pub fn from_parts(
        _cls: &Bound<'_, PyType>,
        message_type: usize,
        ciphertext: &[u8],
    ) -> Result<Self, DecodeError> {
        Ok(Self { inner: vodozemac::olm::OlmMessage::from_parts(message_type, ciphertext)? })
    }

    pub fn to_parts(&self) -> (usize, Py<PyBytes>) {
        let (message_type, ciphertext) = self.inner.clone().to_parts();
        (message_type, convert_to_pybytes(ciphertext.as_slice()))
    }
}

#[pyclass]
pub struct PreKeyMessage {
    pub(crate) inner: vodozemac::olm::PreKeyMessage,
}

#[pymethods]
impl PreKeyMessage {
    #[classmethod]
    pub fn from_base64(_cls: &Bound<'_, PyType>, message: &str) -> Result<Self, DecodeError> {
        Ok(Self { inner: vodozemac::olm::PreKeyMessage::from_base64(message)? })
    }

    pub fn to_any(&self) -> AnyOlmMessage {
        AnyOlmMessage { inner: vodozemac::olm::OlmMessage::PreKey(self.inner.clone()) }
    }

    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }
}

impl From<PreKeyMessage> for AnyOlmMessage {
    fn from(value: PreKeyMessage) -> Self {
        Self { inner: vodozemac::olm::OlmMessage::PreKey(value.inner.clone()) }
    }
}
