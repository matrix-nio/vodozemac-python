use crate::error::*;
use pyo3::{prelude::*, types::PyType};

#[pyclass]
#[derive(Clone)]
pub struct Curve25519PublicKey {
    pub(crate) inner: vodozemac::Curve25519PublicKey,
}

impl From<vodozemac::Curve25519PublicKey> for Curve25519PublicKey {
    fn from(value: vodozemac::Curve25519PublicKey) -> Self {
        Self { inner: value }
    }
}

#[pymethods]
impl Curve25519PublicKey {
    #[classmethod]
    pub fn from_base64(_cls: &Bound<'_, PyType>, key: &str) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self {
            inner: vodozemac::Curve25519PublicKey::from_base64(key).unwrap(),
        })
    }

    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    #[classattr]
    const __hash__: Option<PyObject> = None;

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}
