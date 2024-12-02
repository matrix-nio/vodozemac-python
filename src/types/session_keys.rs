use pyo3::prelude::*;

use crate::error::*;

#[pyclass]
pub struct SessionKey {
    pub(crate) inner: vodozemac::megolm::SessionKey,
}

#[pymethods]
impl SessionKey {
    #[new]
    pub fn from_base64(session_key: &str) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self { inner: vodozemac::megolm::SessionKey::from_base64(session_key)? })
    }

    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

impl From<vodozemac::megolm::SessionKey> for SessionKey {
    fn from(value: vodozemac::megolm::SessionKey) -> Self {
        Self { inner: value }
    }
}

#[pyclass]
pub struct ExportedSessionKey {
    pub(crate) inner: vodozemac::megolm::ExportedSessionKey,
}

#[pymethods]
impl ExportedSessionKey {
    #[new]
    pub fn from_base64(session_key: &str) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self { inner: vodozemac::megolm::ExportedSessionKey::from_base64(session_key)? })
    }

    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

impl From<vodozemac::megolm::ExportedSessionKey> for ExportedSessionKey {
    fn from(value: vodozemac::megolm::ExportedSessionKey) -> Self {
        Self { inner: value }
    }
}
