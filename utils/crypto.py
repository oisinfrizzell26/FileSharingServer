import base64
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import Base64Encoder

def verify_signature(public_key_b64: str, message_b64: str, signature_b64: str, algorithm: str = 'ed25519') -> bool:

    if algorithm != 'ed25519':
        # It's good to be explicit about supported algorithms
        # app.logger.error(f"Unsupported signature algorithm: {algorithm}")
        return False

    try:
        # Decode the base64 encoded inputs to raw bytes
        public_key_bytes = base64.b64decode(public_key_b64)
        message_bytes = base64.b64decode(message_b64)
        signature_bytes = base64.b64decode(signature_b64)

        # Create a VerifyKey object from the public key bytes
        verify_key = VerifyKey(public_key_bytes)

        # Verify the signature. This will raise BadSignatureError if verification fails.
        verify_key.verify(message_bytes, signature_bytes)

        # If no exception is raised, the signature is valid
        return True
    except BadSignatureError:
        # app.logger.warning("Signature verification failed: BadSignatureError (invalid signature).")
        return False
    except Exception as e:
        # Catch other potential errors (e.g., malformed base64)
        # app.logger.error(f"An unexpected error occurred during signature verification: {e}")
        return False