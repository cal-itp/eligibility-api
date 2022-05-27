import datetime
import json
import logging
import uuid

from jwcrypto import jwe, jws, jwt, jwk
from typing import Iterable
import requests

logger = logging.getLogger(__name__)


def _create_jwk(pem_data):
    if isinstance(pem_data, str):
        pem_data = bytes(pem_data, "utf-8")

    return jwk.JWK.from_pem(pem_data)


class TokenError(Exception):
    """Error with API request/response token."""

    pass


class RequestToken:
    """Eligibility Verification API request token."""

    def __init__(
        self,
        types: Iterable[str],
        agency: str,
        jws_signing_alg: str,
        client_private_key,
        jwe_encryption_alg: str,
        jwe_cek_enc: str,
        server_public_key,
        sub: str,
        name: str,
        issuer: str,
    ):
        logger.info("Initialize new request token")

        self.client_private_jwk = _create_jwk(client_private_key)
        self.server_public_jwk = _create_jwk(server_public_key)

        # craft the main token payload
        payload = dict(
            jti=str(uuid.uuid4()),
            iss=issuer,
            iat=int(
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            ),
            agency=agency,
            eligibility=types,
            sub=sub,
            name=name,
        )

        logger.debug("Sign token payload with agency's private key")
        header = {"typ": "JWS", "alg": jws_signing_alg}
        signed_token = jwt.JWT(header=header, claims=payload)
        signed_token.make_signed_token(self.client_private_jwk)
        signed_payload = signed_token.serialize()

        logger.debug("Encrypt signed token payload with verifier's public key")
        header = {
            "typ": "JWE",
            "alg": jwe_encryption_alg,
            "enc": jwe_cek_enc,
        }
        encrypted_token = jwt.JWT(header=header, claims=signed_payload)
        encrypted_token.make_encrypted_token(self.server_public_jwk)

        logger.info("Signed and encrypted request token initialized")
        self._jwe = encrypted_token

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self._jwe.serialize()


class ResponseToken:
    """Eligibility Verification API response token."""

    def __init__(
        self,
        response: requests.models.Response,
        jwe_encryption_alg: str,
        jwe_cek_enc: str,
        client_private_key,
        jws_signing_alg: str,
        server_public_key,
    ):
        logger.info("Read encrypted token from response")

        self.client_private_jwk = _create_jwk(client_private_key)
        self.server_public_jwk = _create_jwk(server_public_key)

        try:
            encrypted_signed_token = response.text
            if not encrypted_signed_token:
                raise ValueError()
            # strip extra spaces and wrapping quote chars
            encrypted_signed_token = encrypted_signed_token.strip("'\n\"")
        except ValueError:
            raise TokenError("Invalid response format")

        logger.debug("Decrypt response token using agency's private key")
        allowed_algs = [jwe_encryption_alg, jwe_cek_enc]
        decrypted_token = jwe.JWE(algs=allowed_algs)
        try:
            decrypted_token.deserialize(
                encrypted_signed_token, key=self.client_private_jwk
            )
        except jwe.InvalidJWEData:
            raise TokenError("Invalid JWE token")
        except jwe.InvalidJWEOperation:
            raise TokenError("JWE token decryption failed")

        decrypted_payload = str(decrypted_token.payload, "utf-8")

        logger.debug(
            "Verify decrypted response token's signature using verifier's public key"
        )
        signed_token = jws.JWS()
        try:
            signed_token.deserialize(
                decrypted_payload, key=self.server_public_jwk, alg=jws_signing_alg
            )
        except jws.InvalidJWSObject:
            raise TokenError("Invalid JWS token")
        except jws.InvalidJWSSignature:
            raise TokenError("JWS token signature verification failed")

        logger.info("Response token decrypted and signature verified")

        payload = json.loads(str(signed_token.payload, "utf-8"))
        self.eligibility = list(payload.get("eligibility", []))
        self.error = payload.get("error", None)
