from dataclasses import dataclass
import datetime
import json
import logging
import uuid
import requests

from jwcrypto import common as jwcrypto, jwe, jws, jwt, jwk


logger = logging.getLogger(__name__)


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


@dataclass
class PayloadData:
    """All the other values needed in the payload that aren't related to signing or encrypting."""

    agency_id: str
    types: list[str]
    issuer: str
    sub: str
    name: str


@dataclass
class VerifierConfig:
    """Values needed to make the request to the eligibility server."""

    api_url: str
    api_auth_header: str
    api_auth_key: str


class RequestToken:
    """Eligibility Verification API request token."""

    def __init__(
        self,
        signing_config: SigningConfig,
        payload_data: PayloadData,
        encryption_config: EncryptionConfig,
    ):
        logger.info("Initialize new request token")

        logger.debug("Sign token payload with agency's private key")
        signed_payload = self._sign_jwt(signing_config, payload_data)

        logger.info("Signed and encrypted request token initialized")
        self._jwe = self._encrypt_jws(encryption_config, signed_payload)

    def _sign_jwt(self, signing_config: SigningConfig, payload_data: PayloadData):
        """Puts header, claims, and signature into a Signed JWT (JWS)"""
        # craft the main token payload
        payload = dict(
            jti=str(uuid.uuid4()),
            iss=payload_data.issuer,
            iat=int(
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            ),
            agency=payload_data.agency_id,
            eligibility=payload_data.types,
            sub=payload_data.sub,
            name=payload_data.name,
        )

        header = {"typ": "JWS", "alg": signing_config.jws_signing_alg}
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


class ResponseToken:
    """Eligibility Verification API response token."""

    def __init__(
        self,
        response,
        signing_config: SigningConfig,
        encryption_config: EncryptionConfig,
    ):
        logger.info("Read encrypted token from response")
        encrypted_signed_token = self._get_encrypted_token(response)

        logger.debug("Decrypt response token using agency's private key")
        decrypted_payload = self._decrypt_response(
            encrypted_signed_token, encryption_config, signing_config.private_jwk
        )

        logger.debug(
            "Verify decrypted response token's signature using verifier's public key"
        )
        payload = self._verify_signature(
            decrypted_payload,
            signing_config.jws_signing_alg,
            encryption_config.public_jwk,
        )

        self.eligibility = list(payload.get("eligibility", []))
        self.error = payload.get("error", None)

    def _get_encrypted_token(self, response):
        try:
            encrypted_signed_token = response.text
            if not encrypted_signed_token:
                raise ValueError()
            # strip extra spaces and wrapping quote chars
            encrypted_signed_token = encrypted_signed_token.strip("'\n\"")
        except ValueError:
            raise TokenError("Invalid response format")

        return encrypted_signed_token

    def _decrypt_response(
        self, encrypted_signed_token, encryption_config: EncryptionConfig, private_jwk
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

    def _verify_signature(self, decrypted_payload, jws_signing_alg, public_jwk):
        signed_token = jws.JWS()
        try:
            signed_token.deserialize(
                decrypted_payload,
                key=public_jwk,
                alg=jws_signing_alg,
            )
        except jws.InvalidJWSObject:
            raise TokenError("Invalid JWS token")
        except jws.InvalidJWSSignature:
            raise TokenError("JWS token signature verification failed")

        logger.info("Response token decrypted and signature verified")

        payload = json.loads(str(signed_token.payload, "utf-8"))

        return payload


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

    def _tokenize_request(self, payload_data):
        """Create a request token."""
        return RequestToken(self.signing_config, payload_data, self.encryption_config)

    def _tokenize_response(self, response):
        """Parse a response token."""
        return ResponseToken(response, self.signing_config, self.encryption_config)

    def _auth_headers(self, token: RequestToken):
        """Create headers for the request with the token and verifier API keys"""
        headers = dict(Authorization=f"Bearer {token}")
        headers[self.verifier.api_auth_header] = self.verifier.api_auth_key
        return headers

    def _request(self, payload_data):
        """Make an API request for eligibility verification."""
        logger.debug("Start new eligibility verification request")

        try:
            token = self._tokenize_request(payload_data)
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
            return self._tokenize_response(r)
        else:
            logger.warning(
                f"Unexpected eligibility verification response status code: {r.status_code}"
            )
            raise ApiError("Unexpected eligibility verification response")

    def verify(self, payload_data: PayloadData) -> ResponseToken:
        """Check eligibility for the subject and name."""
        return self._request(payload_data)
