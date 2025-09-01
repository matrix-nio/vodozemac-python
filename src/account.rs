use std::collections::HashMap;

use pyo3::{
    prelude::*,
    types::{PyBytes, PyType},
};
use vodozemac::olm::SessionConfig;

use super::session::Session;
use crate::{
    convert_to_pybytes,
    error::{LibolmPickleError, PickleError, SessionError},
    types::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature, PreKeyMessage},
};

#[pyclass(subclass)]
pub struct Account {
    inner: vodozemac::olm::Account,
}

#[pymethods]
impl Account {
    #[new]
    fn new() -> Self {
        Self { inner: vodozemac::olm::Account::new() }
    }

    #[classmethod]
    fn from_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        let pickle = vodozemac::olm::AccountPickle::from_encrypted(pickle, pickle_key)?;

        let inner = vodozemac::olm::Account::from_pickle(pickle);

        Ok(Self { inner })
    }

    #[classmethod]
    fn from_libolm_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, LibolmPickleError> {
        let inner = vodozemac::olm::Account::from_libolm_pickle(pickle, pickle_key)?;

        Ok(Self { inner })
    }

    fn pickle(&self, pickle_key: &[u8]) -> Result<String, PickleError> {
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[getter]
    fn ed25519_key(&self) -> Ed25519PublicKey {
        self.inner.ed25519_key().into()
    }

    #[getter]
    fn curve25519_key(&self) -> Curve25519PublicKey {
        self.inner.curve25519_key().into()
    }

    fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.inner.sign(message).into()
    }

    #[getter]
    fn one_time_keys(&self) -> HashMap<String, Curve25519PublicKey> {
        self.inner.one_time_keys().into_iter().map(|(k, v)| (k.to_base64(), v.into())).collect()
    }

    #[getter]
    fn max_number_of_one_time_keys(&self) -> usize {
        self.inner.max_number_of_one_time_keys()
    }

    fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    #[getter]
    fn fallback_key(&self) -> HashMap<String, Curve25519PublicKey> {
        self.inner.fallback_key().into_iter().map(|(k, v)| (k.to_base64(), v.into())).collect()
    }

    fn generate_fallback_key(&mut self) {
        self.inner.generate_fallback_key();
    }

    fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published()
    }

    fn create_outbound_session(
        &self,
        identity_key: &Curve25519PublicKey,
        one_time_key: &Curve25519PublicKey,
    ) -> Session {
        let session = self.inner.create_outbound_session(
            SessionConfig::version_1(),
            identity_key.inner,
            one_time_key.inner,
        );

        Session { inner: session }
    }

    fn create_inbound_session(
        &mut self,
        identity_key: &Curve25519PublicKey,
        message: &PreKeyMessage,
    ) -> Result<(Session, Py<PyBytes>), SessionError> {
        let result = self.inner.create_inbound_session(identity_key.inner, &message.inner)?;

        Ok((Session { inner: result.session }, convert_to_pybytes(result.plaintext.as_slice())))
    }
}
