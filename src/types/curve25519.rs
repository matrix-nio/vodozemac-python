use pyo3::{
    prelude::*,
    types::{PyBytes, PyType},
};
use vodozemac::{base64_decode, base64_encode};

use crate::{convert_to_pybytes, error::*};

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
    pub fn from_base64(_cls: &Bound<'_, PyType>, key: &str) -> Result<Self, KeyError> {
        Ok(Self { inner: vodozemac::Curve25519PublicKey::from_base64(key)? })
    }

    #[classmethod]
    pub fn from_bytes(_cls: &Bound<'_, PyType>, bytes: &[u8]) -> Result<Self, KeyError> {
        let key: &[u8; 32] = bytes.try_into().map_err(|_| {
            KeyError::from(vodozemac::KeyError::InvalidKeyLength {
                key_type: "Curve25519PublicKey",
                expected_length: 32,
                length: bytes.len(),
            })
        })?;

        Ok(Self { inner: vodozemac::Curve25519PublicKey::from_slice(key)? })
    }

    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    pub fn to_bytes(&self) -> Py<PyBytes> {
        convert_to_pybytes(self.inner.to_bytes().as_slice())
    }

    #[classattr]
    const __hash__: Option<PyObject> = None;

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

/// A Curve25519 secret key.
#[pyclass]
#[derive(Clone)]
pub struct Curve25519SecretKey {
    pub(crate) inner: vodozemac::Curve25519SecretKey,
}

impl From<vodozemac::Curve25519SecretKey> for Curve25519SecretKey {
    fn from(value: vodozemac::Curve25519SecretKey) -> Self {
        Self { inner: value }
    }
}

#[pymethods]
impl Curve25519SecretKey {
    /// Generate a new, random, Curve25519SecretKey.
    #[new]
    fn new() -> Self {
        Self { inner: vodozemac::Curve25519SecretKey::new() }
    }

    /// Create a `Curve25519SecretKey` from the given base64-encoded string.
    #[classmethod]
    pub fn from_base64(_cls: &Bound<'_, PyType>, key: &str) -> Result<Self, KeyError> {
        Self::from_bytes(
            _cls,
            base64_decode(key)
                .map_err(|e| KeyError::from(vodozemac::KeyError::Base64Error(e)))?
                .as_slice(),
        )
    }

    /// Create a `Curve25519SecretKey` from the given byte array.
    #[classmethod]
    pub fn from_bytes(_cls: &Bound<'_, PyType>, bytes: &[u8]) -> Result<Self, KeyError> {
        let key: &[u8; 32] = bytes.try_into().map_err(|_| {
            KeyError::from(vodozemac::KeyError::InvalidKeyLength {
                key_type: "Curve25519SecretKey",
                expected_length: 32,
                length: bytes.len(),
            })
        })?;

        Ok(Self { inner: vodozemac::Curve25519SecretKey::from_slice(key) })
    }

    /// Convert the `Curve25519SecretKey` to a base64-encoded string.
    pub fn to_base64(&self) -> String {
        base64_encode(self.inner.to_bytes().as_slice())
    }

    /// Convert the `Curve25519SecretKey` to a byte array.
    pub fn to_bytes(&self) -> Py<PyBytes> {
        convert_to_pybytes(self.inner.to_bytes().as_slice())
    }

    /// Give the `Curve25519PublicKey` associated with this
    /// `Curve25519SecretKey`.
    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey { inner: vodozemac::Curve25519PublicKey::from(&self.inner) }
    }
}
