use pyo3::{prelude::*, types::PyType};
use vodozemac::megolm::{ExportedSessionKey, MegolmMessage, SessionConfig, SessionKey};

use crate::error::{LibolmPickleError, MegolmDecryptionError, PickleError, SessionKeyDecodeError};

#[pyclass]
pub struct GroupSession {
    pub(super) inner: vodozemac::megolm::GroupSession,
}

#[pymethods]
impl GroupSession {
    #[new]
    fn new() -> Self {
        Self {
            inner: vodozemac::megolm::GroupSession::new(SessionConfig::version_1()),
        }
    }

    #[getter]
    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    #[getter]
    fn message_index(&self) -> u32 {
        self.inner.message_index()
    }

    #[getter]
    fn session_key(&self) -> String {
        self.inner.session_key().to_base64()
    }

    fn encrypt(&mut self, plaintext: &str) -> String {
        self.inner.encrypt(plaintext).to_base64()
    }

    fn pickle(&self, pickle_key: &[u8]) -> Result<String, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[classmethod]
    fn from_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;
        let pickle = vodozemac::megolm::GroupSessionPickle::from_encrypted(pickle, pickle_key)?;

        let session = vodozemac::megolm::GroupSession::from_pickle(pickle);

        Ok(Self { inner: session })
    }
}

#[pyclass]
pub struct DecryptedMessage {
    #[pyo3(get)]
    plaintext: String,
    #[pyo3(get)]
    message_index: u32,
}

#[pyclass]
pub struct InboundGroupSession {
    pub(super) inner: vodozemac::megolm::InboundGroupSession,
}

#[pymethods]
impl InboundGroupSession {
    #[new]
    fn new(session_key: &str) -> Result<Self, SessionKeyDecodeError> {
        let key = SessionKey::from_base64(session_key)?;

        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::new(&key, SessionConfig::version_1()),
        })
    }

    #[classmethod]
    fn import_session(
        _cls: &Bound<'_, PyType>,
        session_key: &str,
    ) -> Result<Self, SessionKeyDecodeError> {
        let key = ExportedSessionKey::from_base64(session_key)?;

        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::import(&key, SessionConfig::version_1()),
        })
    }

    #[getter]
    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    #[getter]
    fn first_known_index(&self) -> u32 {
        self.inner.first_known_index()
    }

    fn export_at(&mut self, index: u32) -> Option<String> {
        self.inner.export_at(index).map(|k| k.to_base64())
    }

    fn decrypt(&mut self, ciphertext: &str) -> Result<DecryptedMessage, MegolmDecryptionError> {
        let message = MegolmMessage::from_base64(ciphertext)?;
        let ret = self.inner.decrypt(&message)?;

        Ok(DecryptedMessage {
            plaintext: String::from_utf8(ret.plaintext)?,
            message_index: ret.message_index,
        })
    }

    fn pickle(&self, pickle_key: &[u8]) -> Result<String, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[classmethod]
    fn from_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;
        let pickle =
            vodozemac::megolm::InboundGroupSessionPickle::from_encrypted(pickle, pickle_key)?;

        let session = vodozemac::megolm::InboundGroupSession::from_pickle(pickle);

        Ok(Self { inner: session })
    }

    #[classmethod]
    fn from_libolm_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, LibolmPickleError> {
        let inner = vodozemac::megolm::InboundGroupSession::from_libolm_pickle(pickle, pickle_key)?;

        Ok(Self { inner })
    }
}
