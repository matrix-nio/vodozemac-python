use std::collections::HashMap;

use pyo3::{prelude::*, types::PyType};

use crate::error::{KeyError, LibolmPickleError, PickleError, SessionError};

use super::{session::Session, OlmMessage};

#[pyclass]
pub struct Account {
    inner: vodozemac::olm::Account,
}

#[pymethods]
impl Account {
    #[new]
    fn new() -> Self {
        Self {
            inner: vodozemac::olm::Account::new(),
        }
    }

    #[classmethod]
    fn from_pickle(_cls: &PyType, pickle: &str, pickle_key: &[u8]) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        let pickle = vodozemac::olm::AccountPickle::from_encrypted(pickle, pickle_key)?;

        let inner = vodozemac::olm::Account::from_pickle(pickle);

        Ok(Self { inner })
    }

    #[classmethod]
    fn from_libolm_pickle(
        _cls: &PyType,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, LibolmPickleError> {
        let inner = vodozemac::olm::Account::from_libolm_pickle(pickle, pickle_key)?;

        Ok(Self { inner })
    }

    fn pickle(&self, pickle_key: &[u8]) -> Result<String, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[getter]
    fn ed25519_key(&self) -> String {
        self.inner.ed25519_key().to_base64()
    }

    #[getter]
    fn curve25519_key(&self) -> String {
        self.inner.curve25519_key().to_base64()
    }

    fn sign(&self, message: &str) -> String {
        self.inner.sign(message).to_base64()
    }

    #[getter]
    fn one_time_keys(&self) -> HashMap<String, String> {
        self.inner
            .one_time_keys()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect()
    }

    #[getter]
    fn max_number_of_one_time_keys(&self) -> usize {
        self.inner.max_number_of_one_time_keys()
    }

    fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count)
    }

    #[getter]
    fn fallback_key(&self) -> HashMap<String, String> {
        self.inner
            .fallback_key()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect()
    }

    fn generate_fallback_key(&mut self) {
        self.inner.generate_fallback_key()
    }

    fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published()
    }

    fn create_outbound_session(
        &self,
        identity_key: &str,
        one_time_key: &str,
    ) -> Result<Session, KeyError> {
        let identity_key = vodozemac::Curve25519PublicKey::from_base64(identity_key)?;
        let one_time_key = vodozemac::Curve25519PublicKey::from_base64(one_time_key)?;

        let session = self
            .inner
            .create_outbound_session(identity_key, one_time_key);

        Ok(Session { inner: session })
    }

    fn create_inbound_session(
        &mut self,
        identity_key: &str,
        message: &OlmMessage,
    ) -> Result<(Session, String), SessionError> {
        let identity_key = vodozemac::Curve25519PublicKey::from_base64(identity_key)?;

        let message =
            vodozemac::olm::OlmMessage::from_parts(message.message_type, &message.ciphertext)?;

        if let vodozemac::olm::OlmMessage::PreKey(message) = message {
            let result = self.inner.create_inbound_session(identity_key, &message)?;

            Ok((
                Session {
                    inner: result.session,
                },
                result.plaintext,
            ))
        } else {
            Err(SessionError::InvalidMessageType)
        }
    }
}
