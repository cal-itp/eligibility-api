from abc import ABC, abstractmethod, abstractclassmethod
from dataclasses import dataclass, field, asdict
import datetime
import json
import logging
import uuid
import requests

from jwcrypto import common as jwcrypto, jwe, jws, jwt, jwk


logger = logging.getLogger(__name__)


def _create_iat() -> int:
    return int(
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).timestamp()
    )


class ApiError(Exception):
    """Error calling the Eligibility Verification API."""

    pass


class TokenError(Exception):
    """Error with API request/response token."""

    pass


class JWK:
    @classmethod
    def from_pem(cls, data, password=None):
        obj = cls()
        obj.key = jwk.JWK.from_pem(data, password)
        return obj


class SigningConfig:
    """Values needed for signing JWT payload."""

    def __init__(self, jws_signing_alg, private_jwk: JWK):
        self.jws_signing_alg = jws_signing_alg
        self.private_jwk = private_jwk.key


class EncryptionConfig:
    """Values needed for encrypting JWS."""

    def __init__(self, jwe_encryption_alg, jwe_cek_enc, public_jwk: JWK):
        self.jwe_encryption_alg = jwe_encryption_alg
        self.jwe_cek_enc = jwe_cek_enc
        self.public_jwk = public_jwk.key


class Payload(ABC):
    @abstractmethod
    def to_dict(self):
        pass

    @abstractclassmethod
    def from_json(cls, json_payload: str):
        pass

    @classmethod
    def from_token(
        cls,
        token: str,
        signing_config: SigningConfig,
        encryption_config: EncryptionConfig,
    ):
        logger.debug("Decrypt response token using private key")
        decrypted_payload = cls._decrypt_token(
            token, encryption_config, signing_config.private_jwk
        )

        logger.debug("Verify decrypted response token's signature using public key")
        signed_token = cls._verify_signature(
            decrypted_payload, signing_config, encryption_config
        )

        payload = json.loads(str(signed_token.payload, "utf-8"))

        return cls.from_json(payload)

    @classmethod
    def _decrypt_token(
        cls,
        encrypted_signed_token: str,
        encryption_config: EncryptionConfig,
        private_jwk: JWK,
    ):
        allowed_algs = [
            encryption_config.jwe_encryption_alg,
            encryption_config.jwe_cek_enc,
        ]
        decrypted_token = jwe.JWE(algs=allowed_algs)
        try:
            decrypted_token.deserialize(encrypted_signed_token, key=private_jwk)
        except jwe.InvalidJWEData:
            raise TokenError("Invalid JWE token")
        except jwe.InvalidJWEOperation:
            raise TokenError("JWE token decryption failed")

        decrypted_payload = str(decrypted_token.payload, "utf-8")

        return decrypted_payload

    @classmethod
    def _verify_signature(cls, decrypted_payload, signing_config, encryption_config):
        signed_token = jws.JWS()
        try:
            signed_token.deserialize(
                decrypted_payload,
                key=encryption_config.public_jwk,
                alg=signing_config.jws_signing_alg,
            )
        except jws.InvalidJWSObject:
            raise TokenError("Invalid JWS token")
        except jws.InvalidJWSSignature:
            raise TokenError("JWS token signature verification failed")

        logger.info("Response token decrypted and signature verified")

        return signed_token


@dataclass
class RequestPayload(Payload):
    """All the other values needed in the request payload that aren't related to signing or encrypting."""

    jti: str = field(init=False)
    iss: str
    iat: int = field(init=False)
    agency_id: str
    eligibility: list[str]
    sub: str
    name: str

    def __post_init__(self):
        self.jti = str(uuid.uuid4())
        self.iat = _create_iat()

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_json(cls, json_payload: str):
        return cls(
            json_payload["agency_id"],
            json_payload["eligibility"],
            json_payload["iss"],
            json_payload["sub"],
            json_payload["name"],
        )


@dataclass
class ResponsePayload(Payload):
    """All the other values needed in the response payload that aren't related to signing or encrypting."""

    jti: str  # Needs to match the one from the request
    iss: str
    iat: int = field(default_factory=_create_iat)
    eligibility: list[str] = field(default_factory=list)
    error: dict = None

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_response(
        cls,
        response,
        signing_config: SigningConfig,
        encryption_config: EncryptionConfig,
    ):
        logger.info("Read encrypted token from response")
        encrypted_signed_token = cls._get_encrypted_token(response)
        return cls.from_token(encrypted_signed_token, signing_config, encryption_config)

    @classmethod
    def _get_encrypted_token(cls, response):
        try:
            encrypted_signed_token = response.text
            if not encrypted_signed_token:
                raise ValueError()
            # strip extra spaces and wrapping quote chars
            encrypted_signed_token = encrypted_signed_token.strip("'\n\"")
        except ValueError:
            raise TokenError("Invalid response format")

        return encrypted_signed_token

    @classmethod
    def from_json(cls, json_payload: str):
        jti = json_payload["jti"]
        iss = json_payload["iss"]
        iat = json_payload["iat"]
        eligibility = list(json_payload.get("eligibility", []))
        error = json_payload.get("error", None)

        return cls(jti, iss, iat, eligibility, error)


@dataclass
class VerifierConfig:
    """Values needed to make the request to the eligibility server."""

    api_url: str
    api_auth_header: str
    api_auth_key: str


class Token:
    """Eligibility Verification API request/response token."""

    def __init__(
        self,
        payload: Payload,
        signing_config: SigningConfig,
        encryption_config: EncryptionConfig,
    ):
        logger.info("Initialize new token")

        logger.debug("Sign token payload with agency's private key")
        signed_payload = self._sign_jwt(signing_config, payload)

        logger.info("Signed and encrypted request token initialized")
        self._jwe = self._encrypt_jws(encryption_config, signed_payload)

    def _sign_jwt(self, signing_config: SigningConfig, payload: Payload):
        """Puts header, claims, and signature into a Signed JWT (JWS)"""

        header = {"typ": "JWS", "alg": signing_config.jws_signing_alg}
        payload = payload.to_dict()

        signed_token = jwt.JWT(header=header, claims=payload)
        signed_token.make_signed_token(signing_config.private_jwk)
        signed_payload = signed_token.serialize()

        return signed_payload

    def _encrypt_jws(self, encryption_config: EncryptionConfig, signed_payload):
        """Encrypt signed payload using a public key"""
        logger.debug("Encrypt signed token payload with verifier's public key")
        header = {
            "typ": "JWE",
            "alg": encryption_config.jwe_encryption_alg,
            "enc": encryption_config.jwe_cek_enc,
        }
        encrypted_token = jwt.JWT(header=header, claims=signed_payload)
        encrypted_token.make_encrypted_token(encryption_config.public_jwk)

        return encrypted_token

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self._jwe.serialize()


class Client:
    """Eligibility Verification API HTTP client."""

    def __init__(
        self,
        signing_config: SigningConfig,
        encryption_config: EncryptionConfig,
        verifier: VerifierConfig,
    ):
        self.signing_config = signing_config
        self.encryption_config = encryption_config
        self.verifier = verifier

    def _tokenize_request(self, request_payload):
        """Create a request token."""
        return Token(request_payload, self.signing_config, self.encryption_config)

    def _parse_response(self, response):
        """Parse a response token."""
        return ResponsePayload.from_response(
            response, self.signing_config, self.encryption_config
        )

    def _auth_headers(self, token: Token):
        """Create headers for the request with the token and verifier API keys"""
        headers = dict(Authorization=f"Bearer {token}")
        headers[self.verifier.api_auth_header] = self.verifier.api_auth_key
        return headers

    def _request(self, request_payload):
        """Make an API request for eligibility verification."""
        logger.debug("Start new eligibility verification request")

        try:
            token = self._tokenize_request(request_payload)
        except jwcrypto.JWException:
            raise TokenError("Failed to tokenize form values")

        try:
            logger.debug(f"GET request to {self.verifier.api_url}")
            r = requests.get(self.verifier.api_url, headers=self._auth_headers(token))
        except requests.ConnectionError:
            raise ApiError("Connection to verification server failed")
        except requests.Timeout:
            raise ApiError("Connection to verification server timed out")
        except requests.TooManyRedirects:
            raise ApiError("Too many redirects to verification server")
        except requests.HTTPError as e:
            raise ApiError(e)

        expected_status_codes = {200, 400}
        if r.status_code in expected_status_codes:
            logger.debug("Process eligiblity verification response")
            return self._parse_response(r)
        else:
            logger.warning(
                f"Unexpected eligibility verification response status code: {r.status_code}"
            )
            raise ApiError("Unexpected eligibility verification response")

    def verify(self, request_payload: RequestPayload) -> ResponsePayload:
        """Check eligibility for the subject and name."""
        return self._request(request_payload)
