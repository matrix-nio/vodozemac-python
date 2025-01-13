use paste::paste;
use pyo3::{exceptions::PyValueError, prelude::*};
use thiserror::Error;

macro_rules! create_error {
    ($source:ty, $target:ident) => {
        paste! {
            pyo3::create_exception!(module, [<$target Exception>], pyo3::exceptions::PyValueError);
        }

        paste! {
            #[derive(Debug, Error)]
            #[error(transparent)]
            pub struct [<$target Error>] {
                source: $source,
            }
        }

        paste! {
            impl From<$source> for [<$target Error>] {
                fn from(e: $source) -> Self {
                    [<$target Error>] { source: e }
                }
            }
        }

        paste! {
            impl From<[<$target Error>]> for PyErr {
                fn from(e: [<$target Error>]) -> PyErr {
                    [<$target Exception>]::new_err(e.source.to_string())
                }
            }
        }
    };
}

create_error!(vodozemac::KeyError, Key);
create_error!(vodozemac::SignatureError, Signature);
create_error!(vodozemac::LibolmPickleError, LibolmPickle);
create_error!(vodozemac::megolm::SessionKeyDecodeError, SessionKeyDecode);
create_error!(vodozemac::DecodeError, Decode);

pyo3::create_exception!(module, PickleException, pyo3::exceptions::PyValueError);
pyo3::create_exception!(module, SessionCreationException, pyo3::exceptions::PyValueError);
pyo3::create_exception!(module, SasException, pyo3::exceptions::PyValueError);
pyo3::create_exception!(module, OlmDecryptionException, pyo3::exceptions::PyValueError);
pyo3::create_exception!(module, MegolmDecryptionException, pyo3::exceptions::PyValueError);

#[derive(Debug, Error)]
pub enum MegolmDecryptionError {
    #[error(transparent)]
    Decryption(#[from] vodozemac::megolm::DecryptionError),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl From<MegolmDecryptionError> for PyErr {
    fn from(e: MegolmDecryptionError) -> Self {
        match e {
            MegolmDecryptionError::Decryption(e) => {
                MegolmDecryptionException::new_err(e.to_string())
            }
            MegolmDecryptionError::Utf8(e) => PyValueError::new_err(e.to_string()),
        }
    }
}

#[derive(Debug, Error)]
pub enum SasError {
    #[error(transparent)]
    Mac(#[from] vodozemac::Base64DecodeError),
    #[error(transparent)]
    Key(#[from] vodozemac::KeyError),
    #[error(transparent)]
    Sas(#[from] vodozemac::sas::SasError),
    #[error("The Sas object has already been used once.")]
    Used,
}

impl From<SasError> for PyErr {
    fn from(e: SasError) -> Self {
        match e {
            SasError::Key(e) => KeyException::new_err(e.to_string()),
            SasError::Sas(e) => SasException::new_err(e.to_string()),
            SasError::Mac(e) => SasException::new_err(e.to_string()),
            SasError::Used => SasException::new_err(e.to_string()),
        }
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(transparent)]
    Key(#[from] vodozemac::KeyError),
    #[error(transparent)]
    Decode(#[from] vodozemac::DecodeError),
    #[error(transparent)]
    Decryption(#[from] vodozemac::olm::DecryptionError),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Creation(#[from] vodozemac::olm::SessionCreationError),
}

impl From<SessionError> for PyErr {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Key(e) => KeyException::new_err(e.to_string()),
            SessionError::Decode(e) => DecodeException::new_err(e.to_string()),
            SessionError::Decryption(e) => OlmDecryptionException::new_err(e.to_string()),
            SessionError::Creation(e) => SessionCreationException::new_err(e.to_string()),
            SessionError::Utf8(e) => PyValueError::new_err(e.to_string()),
        }
    }
}

#[derive(Debug, Error)]
pub enum PickleError {
    #[error("The pickle key doesn't have the correct size, got {0}, expected 32 bytes")]
    InvalidKeySize(usize),
    #[error(transparent)]
    Unpickling(#[from] vodozemac::PickleError),
}

impl From<PickleError> for PyErr {
    fn from(e: PickleError) -> Self {
        PickleException::new_err(e.to_string())
    }
}

/// An error type describing failures which can happen during the use of
/// `PkEncryption` and `PkDecryption` objects.
#[derive(Debug, Error)]
pub enum PkEncryptionError {
    #[error("The key doesn't have the correct size, got {0}, expected 32 bytes")]
    InvalidKeySize(usize),
    #[error(transparent)]
    Decode(#[from] vodozemac::pk_encryption::Error),
    #[error(transparent)]
    Mac(#[from] vodozemac::Base64DecodeError),
}

pyo3::create_exception!(module, PkInvalidKeySizeException, pyo3::exceptions::PyValueError);
pyo3::create_exception!(module, PkDecodeException, pyo3::exceptions::PyValueError);

impl From<PkEncryptionError> for PyErr {
    fn from(e: PkEncryptionError) -> Self {
        match e {
            PkEncryptionError::InvalidKeySize(_) => {
                PkInvalidKeySizeException::new_err(e.to_string())
            }
            PkEncryptionError::Decode(_) => PkDecodeException::new_err(e.to_string()),
            PkEncryptionError::Mac(_) => PkDecodeException::new_err(e.to_string()),
        }
    }
}
