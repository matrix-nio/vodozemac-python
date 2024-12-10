use pyo3::{
    pyclass, pymethods,
    types::{PyBytes, PyType},
    Bound, Py, Python,
};

use crate::{
    types::{Curve25519PublicKey, Curve25519SecretKey},
    PkEncryptionError,
};

/// A message that was encrypted using a PkEncryption object.
#[pyclass]
pub struct Message {
    /// The ciphertext of the message.
    #[pyo3(get)]
    ciphertext: Vec<u8>,
    /// The message authentication code of the message.
    ///
    /// *Warning*: As stated in the module description, this does not
    /// authenticate the message.
    #[pyo3(get)]
    mac: Vec<u8>,
    /// The ephemeral Curve25519PublicKey of the message which was used to
    /// derive the individual message key.
    #[pyo3(get)]
    ephemeral_key: Vec<u8>,
}

/// ☣️  Compat support for libolm's PkDecryption.
///
/// This implements the `m.megolm_backup.v1.curve25519-aes-sha2` described in
/// the Matrix [spec]. This is a asymmetric encryption scheme based on
/// Curve25519.
///
/// **Warning**: Please note the algorithm contains a critical flaw and does not
/// provide authentication of the ciphertext.
///
/// [spec]: https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
#[pyclass]
pub struct PkDecryption {
    inner: vodozemac::pk_encryption::PkDecryption,
}

#[pymethods]
impl PkDecryption {
    /// Create a new random PkDecryption object.
    #[new]
    fn new() -> Self {
        Self { inner: vodozemac::pk_encryption::PkDecryption::new() }
    }

    /// Create a PkDecryption object from the secret key bytes.
    #[classmethod]
    fn from_key(
        _cls: &Bound<'_, PyType>,
        key: Curve25519SecretKey,
    ) -> Result<Self, PkEncryptionError> {
        Ok(Self { inner: vodozemac::pk_encryption::PkDecryption::from_key(key.inner) })
    }

    /// The secret key used to decrypt messages.
    #[getter]
    pub fn key(&self) -> Curve25519SecretKey {
        Curve25519SecretKey::from(self.inner.secret_key().clone())
    }

    /// The public key used to encrypt messages for this decryption object.
    #[getter]
    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from(self.inner.public_key())
    }

    /// Decrypt a ciphertext. See the PkEncryption::encrypt function
    /// for descriptions of the ephemeral_key and mac arguments.
    pub fn decrypt(&self, message: &Message) -> Result<Py<PyBytes>, PkEncryptionError> {
        let ephemeral_key_bytes: [u8; 32] = message
            .ephemeral_key
            .as_slice()
            .try_into()
            .map_err(|_| PkEncryptionError::InvalidKeySize(message.ephemeral_key.len()))?;

        let message = vodozemac::pk_encryption::Message {
            ciphertext: message.ciphertext.clone(),
            mac: message.mac.clone(),
            ephemeral_key: vodozemac::Curve25519PublicKey::from_bytes(ephemeral_key_bytes),
        };

        self.inner
            .decrypt(&message)
            .map(|vec| Python::with_gil(|py| PyBytes::new(py, vec.as_slice()).into()))
            .map_err(PkEncryptionError::Decode)
    }
}

/// ☣️  Compat support for libolm's PkEncryption.
///
/// This implements the `m.megolm_backup.v1.curve25519-aes-sha2` described in
/// the Matrix [spec]. This is a asymmetric encryption scheme based on
/// Curve25519.
///
/// **Warning**: Please note the algorithm contains a critical flaw and does not
/// provide authentication of the ciphertext.
///
/// [spec]: https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
#[pyclass]
pub struct PkEncryption {
    inner: vodozemac::pk_encryption::PkEncryption,
}

#[pymethods]
impl PkEncryption {
    /// Create a new PkEncryption object from public key.
    #[classmethod]
    fn from_key(
        _cls: &Bound<'_, PyType>,
        key: Curve25519PublicKey,
    ) -> Result<Self, PkEncryptionError> {
        Ok(Self { inner: vodozemac::pk_encryption::PkEncryption::from_key(key.inner) })
    }

    /// Encrypt a plaintext for the recipient. Writes to the ciphertext, mac,
    /// and ephemeral_key buffers, whose values should be sent to the
    /// recipient. mac is a Message Authentication Code to ensure that the
    /// data is received and decrypted properly. ephemeral_key is the public
    /// part of the ephemeral key used (together with the recipient's key)
    /// to generate a symmetric encryption key.
    pub fn encrypt(&self, message: &[u8]) -> Message {
        let msg = self.inner.encrypt(message);
        Message {
            ciphertext: msg.ciphertext.to_vec(),
            mac: msg.mac.to_vec(),
            ephemeral_key: msg.ephemeral_key.to_vec(),
        }
    }
}
