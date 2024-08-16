use crate::error::*;
use pyo3::{prelude::*, types::PyType};
use vodozemac::olm::OlmMessage;

#[pyclass]
pub struct AnyOlmMessage {
    pub(crate) inner: vodozemac::olm::OlmMessage,
}

#[pymethods]
impl AnyOlmMessage {
    #[classmethod]
    pub fn pre_key(_cls: &Bound<'_, PyType>, message: &str) -> Result<Self, SessionError> {
        Ok(Self {
            inner: vodozemac::olm::PreKeyMessage::from_base64(message)?.into(),
        })
    }

    #[classmethod]
    pub fn normal(_cls: &Bound<'_, PyType>, message: &str) -> Result<Self, SessionError> {
        Ok(Self {
            inner: vodozemac::olm::Message::from_base64(message)?.into(),
        })
    }

    pub fn to_pre_key(&self) -> Option<PreKeyMessage> {
        if let vodozemac::olm::OlmMessage::PreKey(message) = &self.inner {
            Some(PreKeyMessage {
                inner: message.clone(),
            })
        } else {
            None
        }
    }

    #[classmethod]
    pub fn from_parts(
        _cls: &Bound<'_, PyType>,
        message_type: usize,
        ciphertext: &str,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            inner: OlmMessage::from_parts(message_type, ciphertext)?,
        })
    }

    pub fn to_parts(&self) -> (usize, String) {
        self.inner.clone().to_parts()
    }
}

#[pyclass]
pub struct PreKeyMessage {
    pub(crate) inner: vodozemac::olm::PreKeyMessage,
}

#[pymethods]
impl PreKeyMessage {
    #[classmethod]
    pub fn from_base64(
        _cls: &Bound<'_, PyType>,
        message: &str,
    ) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self {
            inner: vodozemac::olm::PreKeyMessage::from_base64(message)
                .unwrap()
                .into(),
        })
    }

    pub fn to_any(&self) -> AnyOlmMessage {
        AnyOlmMessage {
            inner: vodozemac::olm::OlmMessage::PreKey(self.inner.clone()),
        }
    }

    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }
}

impl From<PreKeyMessage> for AnyOlmMessage {
    fn from(value: PreKeyMessage) -> Self {
        Self {
            inner: OlmMessage::PreKey(value.inner.clone()),
        }
    }
}
