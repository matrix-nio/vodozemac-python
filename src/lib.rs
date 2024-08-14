mod account;
mod error;
mod group_sessions;
mod sas;
mod session;

use error::*;
use pyo3::prelude::*;

#[pyclass]
pub struct OlmMessage {
    #[pyo3(get)]
    ciphertext: String,
    #[pyo3(get)]
    message_type: usize,
}

#[pymethods]
impl OlmMessage {
    #[new]
    pub fn new(message_type: usize, ciphertext: &str) -> Self {
        Self {
            ciphertext: ciphertext.to_owned(),
            message_type,
        }
    }
}

#[pymodule(name = "vodozemac")]
fn my_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<account::Account>()?;
    m.add_class::<session::Session>()?;
    m.add_class::<OlmMessage>()?;
    m.add_class::<sas::Sas>()?;
    m.add_class::<group_sessions::GroupSession>()?;
    m.add_class::<group_sessions::InboundGroupSession>()?;

    m.add("KeyException", py.get_type_bound::<KeyException>())?;
    m.add("DecodeException", py.get_type_bound::<DecodeException>())?;
    m.add(
        "LibolmPickleException",
        py.get_type_bound::<LibolmPickleException>(),
    )?;
    m.add(
        "SessionKeyDecodeException",
        py.get_type_bound::<SessionKeyDecodeException>(),
    )?;
    m.add("PickleException", py.get_type_bound::<PickleException>())?;
    m.add(
        "SessionCreationException",
        py.get_type_bound::<SessionCreationException>(),
    )?;
    m.add("SasException", py.get_type_bound::<SasException>())?;
    m.add(
        "OlmDecryptionException",
        py.get_type_bound::<OlmDecryptionException>(),
    )?;
    m.add(
        "MegolmDecryptionException",
        py.get_type_bound::<MegolmDecryptionException>(),
    )?;

    Ok(())
}
