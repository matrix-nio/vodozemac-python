use pyo3::{
    prelude::*,
    types::{PyBytes, PyType},
};
use vodozemac::megolm::SessionConfig;

use crate::{
    convert_to_pybytes,
    error::{LibolmPickleError, MegolmDecryptionError, PickleError, SessionKeyDecodeError},
    types::{ExportedSessionKey, MegolmMessage, SessionKey},
};

#[pyclass]
pub struct GroupSession {
    pub(super) inner: vodozemac::megolm::GroupSession,
}

#[pymethods]
impl GroupSession {
    #[new]
    fn new() -> Self {
        Self { inner: vodozemac::megolm::GroupSession::new(SessionConfig::version_1()) }
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
    fn session_key(&self) -> SessionKey {
        self.inner.session_key().into()
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> MegolmMessage {
        self.inner.encrypt(plaintext).into()
    }

    fn pickle(&self, pickle_key: &[u8]) -> Result<String, PickleError> {
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[classmethod]
    fn from_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;
        let pickle = vodozemac::megolm::GroupSessionPickle::from_encrypted(pickle, pickle_key)?;

        let session = vodozemac::megolm::GroupSession::from_pickle(pickle);

        Ok(Self { inner: session })
    }
}

#[pyclass]
pub struct DecryptedMessage {
    #[pyo3(get)]
    plaintext: Py<PyBytes>,
    #[pyo3(get)]
    message_index: u32,
}

impl DecryptedMessage {
    fn new(plaintext: &[u8], message_index: u32) -> Self {
        DecryptedMessage { plaintext: convert_to_pybytes(plaintext), message_index }
    }
}

#[pyclass]
pub struct InboundGroupSession {
    pub(super) inner: vodozemac::megolm::InboundGroupSession,
}

#[pymethods]
impl InboundGroupSession {
    #[new]
    fn new(session_key: &SessionKey) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::new(
                &session_key.inner,
                SessionConfig::version_1(),
            ),
        })
    }

    #[classmethod]
    fn import_session(
        _cls: &Bound<'_, PyType>,
        session_key: &ExportedSessionKey,
    ) -> Result<Self, SessionKeyDecodeError> {
        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::import(
                &session_key.inner,
                SessionConfig::version_1(),
            ),
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

    fn export_at(&mut self, index: u32) -> Option<ExportedSessionKey> {
        self.inner.export_at(index).map(|k| k.into())
    }

    fn decrypt(
        &mut self,
        message: &MegolmMessage,
    ) -> Result<DecryptedMessage, MegolmDecryptionError> {
        let ret = self.inner.decrypt(&message.inner)?;

        Ok(DecryptedMessage::new(ret.plaintext.as_slice(), ret.message_index))
    }

    fn pickle(&self, pickle_key: &[u8]) -> Result<String, PickleError> {
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    #[classmethod]
    fn from_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;
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
