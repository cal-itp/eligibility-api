import datetime
import json
import logging

from jwcrypto import jwe, jws, jwt

from .client import JWK

logger = logging.getLogger(__name__)


def get_token_payload(
    token: str,
    jwe_encryption_alg: str,
    jwe_cek_enc: str,
    server_private_key: JWK,
    jws_signing_alg: str,
    client_public_key: JWK,
) -> dict:
    """Decode a token (JWE(JWS))."""
    try:
        # decrypt
        decrypted_token = jwe.JWE(algs=[jwe_encryption_alg, jwe_cek_enc])
        decrypted_token.deserialize(token, key=server_private_key.key)
        decrypted_payload = str(decrypted_token.payload, "utf-8")
        # verify signature
        signed_token = jws.JWS()
        signed_token.deserialize(
            decrypted_payload, key=client_public_key.key, alg=jws_signing_alg
        )
        # return final payload
        payload = str(signed_token.payload, "utf-8")
        return json.loads(payload)
    except Exception:
        return False


def create_response_payload(token_payload: dict, issuer: str) -> dict:
    """Crafts a response payload. Does not include the eligibility or error fields."""
    # craft the response payload using parsed request token
    resp_payload = dict(
        jti=token_payload["jti"],
        iss=issuer,
        iat=int(
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).timestamp()
        ),
    )

    return resp_payload


def make_token(
    payload: dict,
    jws_signing_alg: str,
    server_private_key: JWK,
    jwe_encryption_alg: str,
    jwe_cek_enc: str,
    client_public_key: JWK,
) -> str:
    """Wrap payload in a signed and encrypted JWT for response."""
    # sign the payload with server's private key
    header = {"typ": "JWS", "alg": jws_signing_alg}
    signed_token = jwt.JWT(header=header, claims=payload)
    signed_token.make_signed_token(server_private_key.key)
    signed_payload = signed_token.serialize()
    # encrypt the signed payload with client's public key
    header = {
        "typ": "JWE",
        "alg": jwe_encryption_alg,
        "enc": jwe_cek_enc,
    }
    encrypted_token = jwt.JWT(header=header, claims=signed_payload)
    encrypted_token.make_encrypted_token(client_public_key.key)
    return encrypted_token.serialize()
