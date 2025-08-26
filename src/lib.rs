mod account;
mod error;
mod group_sessions;
mod pk_encryption;
mod sas;
mod session;
mod types;

use error::*;
use pyo3::{prelude::*, types::PyBytes};

#[pymodule(name = "vodozemac")]
/// Python bindings for the vodozemac Rust library.
///
/// This library provides Python bindings for vodozemac, a pure Rust
/// implementation of the Matrix cryptographic protocols including:
/// - Olm (end-to-end encryption for 1:1 conversations)
/// - Megolm (end-to-end encryption for group conversations)
/// - SAS (Short Authentication String) verification
/// - Public key encryption (PK encryption) for key backup
///
/// All the classes and functions in this module are thread-safe and can be used
/// in concurrent environments.
fn my_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<account::Account>()?;
    m.add_class::<session::Session>()?;
    m.add_class::<types::AnyOlmMessage>()?;
    m.add_class::<types::PreKeyMessage>()?;

    m.add_class::<sas::Sas>()?;
    m.add_class::<sas::EstablishedSas>()?;

    m.add_class::<group_sessions::GroupSession>()?;
    m.add_class::<group_sessions::InboundGroupSession>()?;
    m.add_class::<types::SessionKey>()?;
    m.add_class::<types::ExportedSessionKey>()?;
    m.add_class::<types::MegolmMessage>()?;

    m.add_class::<types::Ed25519PublicKey>()?;
    m.add_class::<types::Ed25519Signature>()?;
    m.add_class::<types::Curve25519PublicKey>()?;
    m.add_class::<types::Curve25519SecretKey>()?;

    m.add_class::<pk_encryption::PkDecryption>()?;
    m.add_class::<pk_encryption::PkEncryption>()?;
    m.add_class::<pk_encryption::Message>()?;

    m.add("KeyException", py.get_type::<KeyException>())?;
    m.add("SignatureException", py.get_type::<SignatureException>())?;
    m.add("DecodeException", py.get_type::<DecodeException>())?;
    m.add("LibolmPickleException", py.get_type::<LibolmPickleException>())?;
    m.add("SessionKeyDecodeException", py.get_type::<SessionKeyDecodeException>())?;
    m.add("PickleException", py.get_type::<PickleException>())?;
    m.add("SessionCreationException", py.get_type::<SessionCreationException>())?;
    m.add("SasException", py.get_type::<SasException>())?;
    m.add("OlmDecryptionException", py.get_type::<OlmDecryptionException>())?;
    m.add("MegolmDecryptionException", py.get_type::<MegolmDecryptionException>())?;
    m.add("PkInvalidKeySizeException", py.get_type::<PkInvalidKeySizeException>())?;
    m.add("PkDecodeException", py.get_type::<PkDecodeException>())?;

    Ok(())
}

pub(crate) fn convert_to_pybytes(bytes: &[u8]) -> Py<PyBytes> {
    Python::with_gil(|py| PyBytes::new(py, bytes).into())
}
