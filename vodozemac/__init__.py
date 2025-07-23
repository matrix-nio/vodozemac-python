import contextlib
from .vodozemac import *  # type: ignore

# Define all available exports for better IDE support
__all__ = [
    # Classes
    "Account",
    "Session", 
    "AnyOlmMessage",
    "PreKeyMessage",
    "Sas",
    "EstablishedSas", 
    "GroupSession",
    "InboundGroupSession",
    "SessionKey",
    "ExportedSessionKey", 
    "MegolmMessage",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "Curve25519PublicKey", 
    "Curve25519SecretKey",
    "PkDecryption",
    "PkEncryption",
    "Message",
    # Exceptions
    "KeyException",
    "SignatureException", 
    "DecodeException",
    "LibolmPickleException",
    "SessionKeyDecodeException",
    "PickleException",
    "SessionCreationException",
    "SasException", 
    "OlmDecryptionException",
    "MegolmDecryptionException",
    "PkInvalidKeySizeException",
    "PkDecodeException",
]

with contextlib.suppress(ImportError):
    from . import vodozemac  # type: ignore
    __doc__ = vodozemac.__doc__
    if hasattr(vodozemac, "__all__"):
        __all__ = vodozemac.__all__ 