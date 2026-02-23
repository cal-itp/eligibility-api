import logging
import requests

from jwcrypto import common as jwcrypto

from .tokens import RequestToken, ResponseToken, TokenError

logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Error calling the Eligibility Verification API."""

    pass


class Client:
    """Eligibility Verification API HTTP client."""

    def __init__(
        self,
        verify_url,
        issuer,
        agency,
        jws_signing_alg,
        client_private_key,
        jwe_encryption_alg,
        jwe_cek_enc,
        server_public_key,
        headers={},
        timeout=5,
    ):
        self.verify_url = verify_url

        self.issuer = issuer
        self.agency = agency
        self.jws_signing_alg = jws_signing_alg
        self.client_private_key = client_private_key
        self.jwe_encryption_alg = jwe_encryption_alg
        self.jwe_cek_enc = jwe_cek_enc
        self.server_public_key = server_public_key

        if "authorization" in set(k.lower() for k in headers):
            raise ValueError('"Authorization" should not be set as an additional header.')

        self.headers = headers
        self.timeout = timeout

    def _tokenize_request(self, sub, name, types):
        """Create a request token."""
        return RequestToken(
            types,
            self.agency,
            self.jws_signing_alg,
            self.client_private_key,
            self.jwe_encryption_alg,
            self.jwe_cek_enc,
            self.server_public_key,
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
            self.client_private_key,
            self.jws_signing_alg,
            self.server_public_key,
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
            r = requests.get(self.verify_url, headers=self._auth_headers(token), timeout=self.timeout)
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
            logger.warning(f"Unexpected eligibility verification response status code: {r.status_code}")
            raise ApiError("Unexpected eligibility verification response")

    def verify(self, sub, name, types):
        """Check eligibility for the subject and name."""
        return self._request(sub, name, types)
