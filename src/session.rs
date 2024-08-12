use pyo3::{prelude::*, types::PyType};

use crate::{LibolmPickleError, PickleError, SessionError};

use super::OlmMessage;

#[pyclass]
pub struct Session {
    pub(super) inner: vodozemac::olm::Session,
}

#[pymethods]
impl Session {
    #[getter]
    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    fn pickle(&self, pickle_key: &[u8]) -> Result<String, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    fn session_matches(&self, message: &OlmMessage) -> bool {
        let message =
            vodozemac::olm::OlmMessage::from_parts(message.message_type, &message.ciphertext);

        match message {
            Ok(m) => {
                if let vodozemac::olm::OlmMessage::PreKey(m) = m {
                    self.inner.session_keys() == m.session_keys()
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    #[classmethod]
    fn from_pickle(_cls: &PyType, pickle: &str, pickle_key: &[u8]) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;
        let pickle = vodozemac::olm::SessionPickle::from_encrypted(pickle, pickle_key)?;

        let session = vodozemac::olm::Session::from_pickle(pickle);

        Ok(Self { inner: session })
    }

    #[classmethod]
    fn from_libolm_pickle(
        _cls: &PyType,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, LibolmPickleError> {
        let session = vodozemac::olm::Session::from_libolm_pickle(pickle, pickle_key)?;

        Ok(Self { inner: session })
    }

    fn encrypt(&mut self, plaintext: &str) -> OlmMessage {
        let message = self.inner.encrypt(plaintext);

        let (message_type, ciphertext) = message.to_parts();

        OlmMessage {
            ciphertext,
            message_type,
        }
    }

    fn decrypt(&mut self, message: &OlmMessage) -> Result<String, SessionError> {
        let message =
            vodozemac::olm::OlmMessage::from_parts(message.message_type, &message.ciphertext)?;

        Ok(self.inner.decrypt(&message)?)
    }
}
