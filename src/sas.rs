use pyo3::prelude::*;

use crate::{error::SasError, types::Curve25519PublicKey};

#[pyclass]
pub struct Sas {
    inner: Option<vodozemac::sas::Sas>,
    public_key: vodozemac::Curve25519PublicKey,
}

#[pymethods]
impl Sas {
    #[new]
    fn new() -> Self {
        let sas = vodozemac::sas::Sas::new();
        let public_key = sas.public_key();

        Self {
            inner: Some(sas),
            public_key,
        }
    }

    #[getter]
    fn public_key(&self) -> Curve25519PublicKey {
        self.public_key.into()
    }

    fn diffie_hellman(&mut self, key: Curve25519PublicKey) -> Result<EstablishedSas, SasError> {
        if let Some(sas) = self.inner.take() {
            let sas = sas.diffie_hellman(key.inner)?;

            Ok(EstablishedSas { inner: sas })
        } else {
            Err(SasError::Used)
        }
    }
}

#[pyclass]
pub struct EstablishedSas {
    inner: vodozemac::sas::EstablishedSas,
}

#[pymethods]
impl EstablishedSas {
    fn bytes(&self, info: &str) -> SasBytes {
        let bytes = self.inner.bytes(info);

        SasBytes { inner: bytes }
    }

    fn calculate_mac_invalid_base64(&self, input: &str, info: &str) -> String {
        self.inner.calculate_mac_invalid_base64(input, info)
    }

    fn calculate_mac(&self, input: &str, info: &str) -> String {
        self.inner.calculate_mac(input, info).to_base64()
    }

    fn verify_mac(&self, input: &str, info: &str, tag: &str) -> Result<(), SasError> {
        let tag = vodozemac::sas::Mac::from_base64(tag)?;

        Ok(self.inner.verify_mac(input, info, &tag)?)
    }
}

#[pyclass]
pub struct SasBytes {
    inner: vodozemac::sas::SasBytes,
}

#[pymethods]
impl SasBytes {
    #[getter]
    fn emoji_indices(&self) -> [u8; 7] {
        self.inner.emoji_indices()
    }

    #[getter]
    fn decimals(&self) -> (u16, u16, u16) {
        self.inner.decimals()
    }
}
