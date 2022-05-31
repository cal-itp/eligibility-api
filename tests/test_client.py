import os
from pathlib import Path

import pytest

from eligibility_api.client import Client


def test_create_valid_client():
    try:
        verify_url = ("http://localhost/verify",)
        issuer = "test-issuer"
        agency = "abc"
        jws_signing_alg = "RS256"
        client_private_key = _get_key("client.pub")
        jwe_encryption_alg = "RSA-OAEP"
        jwe_cek_enc = "A256CBC-HS512"
        server_public_key = _get_key("server.key")

        Client(
            verify_url,
            issuer,
            agency,
            jws_signing_alg,
            client_private_key,
            jwe_encryption_alg,
            jwe_cek_enc,
            server_public_key,
        )
    except Exception:
        pytest.fail("Failed to create valid Client")


def _get_key(filename):
    current_path = Path(os.path.dirname(os.path.realpath(__file__)))
    file_path = current_path / "keys" / filename

    with file_path.open(mode="rb") as pemfile:
        key = str(pemfile.read(), "utf-8")

    return key


def test_create_invalid_client_bad_headers():
    pass


def test_client_verify_success():
    pass


def test_client_verify_unexpected_response_code():
    pass


def test_client_verify_failed_request():  # should be parameterized
    pass


def test_client_verify_failed_tokenize_request():
    pass


def test_client_verify_failed_tokenize_response():
    pass
