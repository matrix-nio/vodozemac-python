use pyo3::{
    prelude::*,
    types::{PyBytes, PyType},
};

use crate::{
    convert_to_pybytes,
    types::{AnyOlmMessage, PreKeyMessage},
    LibolmPickleError, PickleError, SessionError,
};

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
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    fn session_matches(&self, message: &PreKeyMessage) -> bool {
        self.inner.session_keys() == message.inner.session_keys()
    }

    #[classmethod]
    fn from_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, PickleError> {
        let pickle_key: &[u8; 32] =
            pickle_key.try_into().map_err(|_| PickleError::InvalidKeySize(pickle_key.len()))?;
        let pickle = vodozemac::olm::SessionPickle::from_encrypted(pickle, pickle_key)?;

        let session = vodozemac::olm::Session::from_pickle(pickle);

        Ok(Self { inner: session })
    }

    #[classmethod]
    fn from_libolm_pickle(
        _cls: &Bound<'_, PyType>,
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, LibolmPickleError> {
        let session = vodozemac::olm::Session::from_libolm_pickle(pickle, pickle_key)?;

        Ok(Self { inner: session })
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> AnyOlmMessage {
        let message = self.inner.encrypt(plaintext);
        AnyOlmMessage { inner: message }
    }

    fn decrypt(&mut self, message: &AnyOlmMessage) -> Result<Py<PyBytes>, SessionError> {
        Ok(convert_to_pybytes(self.inner.decrypt(&message.inner)?.as_slice()))
    }
}
