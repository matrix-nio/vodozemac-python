use crate::error::*;
use pyo3::{prelude::*, types::PyType};

#[pyclass]
pub struct AnyOlmMessage {
    pub(crate) inner: vodozemac::olm::OlmMessage,
}

#[pymethods]
impl AnyOlmMessage {
    #[classmethod]
    pub fn pre_key(_cls: &Bound<'_, PyType>, message: &str) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self {
            inner: vodozemac::olm::PreKeyMessage::from_base64(message)
                .unwrap()
                .into(),
        })
    }

    #[classmethod]
    pub fn normal(_cls: &Bound<'_, PyType>, message: &str) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self {
            inner: vodozemac::olm::Message::from_base64(message)
                .unwrap()
                .into(),
        })
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
}
