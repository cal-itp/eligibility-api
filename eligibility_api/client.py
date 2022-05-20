import datetime
import json
import logging
import uuid
import requests

from jwcrypto import common as jwcrypto, jwe, jws, jwt, jwk
from typing import Iterable


logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Error calling the Eligibility Verification API."""

    pass


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
        client_private_jwk: jwk.JWK,
        jwe_encryption_alg: str,
        jwe_cek_enc: str,
        server_public_jwk: jwk.JWK,
        sub: str,
        name: str,
        issuer: str,
    ):
        logger.info("Initialize new request token")

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
        signed_token.make_signed_token(client_private_jwk)
        signed_payload = signed_token.serialize()

        logger.debug("Encrypt signed token payload with verifier's public key")
        header = {
            "typ": "JWE",
            "alg": jwe_encryption_alg,
            "enc": jwe_cek_enc,
        }
        encrypted_token = jwt.JWT(header=header, claims=signed_payload)
        encrypted_token.make_encrypted_token(server_public_jwk)

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
        client_private_jwk: jwk.JWK,
        jws_signing_alg: str,
        server_public_jwk: jwk.JWK,
    ):
        logger.info("Read encrypted token from response")

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
            decrypted_token.deserialize(encrypted_signed_token, key=client_private_jwk)
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
                decrypted_payload, key=server_public_jwk, alg=jws_signing_alg
            )
        except jws.InvalidJWSObject:
            raise TokenError("Invalid JWS token")
        except jws.InvalidJWSSignature:
            raise TokenError("JWS token signature verification failed")

        logger.info("Response token decrypted and signature verified")

        payload = json.loads(str(signed_token.payload, "utf-8"))
        self.eligibility = list(payload.get("eligibility", []))
        self.error = payload.get("error", None)


class Client:
    """Eligibility Verification API HTTP client."""

    def __init__(
        self,
        verify_url,
        issuer,
        agency,
        jws_signing_alg,
        client_private_jwk,
        jwe_encryption_alg,
        jwe_cek_enc,
        server_public_jwk,
        headers={},
    ):
        self.verify_url = verify_url

        self.issuer = issuer
        self.agency = agency
        self.jws_signing_alg = jws_signing_alg
        self.client_private_jwk = client_private_jwk
        self.jwe_encryption_alg = jwe_encryption_alg
        self.jwe_cek_enc = jwe_cek_enc
        self.server_public_jwk = server_public_jwk

        if "authorization" in set(k.lower() for k in headers):
            raise ValueError(
                '"Authorization" should not be set as an additional header.'
            )

        self.headers = headers

    def _tokenize_request(self, sub, name, types):
        """Create a request token."""
        return RequestToken(
            types,
            self.agency,
            self.jws_signing_alg,
            self.client_private_jwk,
            self.jwe_encryption_alg,
            self.jwe_cek_enc,
            self.server_public_jwk,
            sub,
            name,
            self.issuer,
        )

    def _tokenize_response(self, response):
        """Parse a response token."""
        return ResponseToken(
            response,
            self.jwe_encryption_alg,
            self.jwe_cek_enc,
            self.client_private_jwk,
            self.jws_signing_alg,
            self.server_public_jwk,
        )

    def _auth_headers(self, token):
        """Create headers for the request with the token and verifier API keys"""
        headers = dict(Authorization=f"Bearer {token}")

        for key, value in self.headers.items():
            headers[key] = value

        return headers

    def _request(self, sub, name, types):
        """Make an API request for eligibility verification."""
        logger.debug("Start new eligibility verification request")

        try:
            token = self._tokenize_request(sub, name, types)
        except jwcrypto.JWException:
            raise TokenError("Failed to tokenize form values")

        try:
            logger.debug(f"GET request to {self.verify_url}")
            r = requests.get(self.verify_url, headers=self._auth_headers(token))
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

    def verify(self, sub, name, types):
        """Check eligibility for the subject and name."""
        return self._request(sub, name, types)
