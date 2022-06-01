import os
from pathlib import Path

import pytest
import responses

from eligibility_api.client import Client


def _valid_configuration():
    return dict(
        verify_url="http://localhost/verify",
        issuer="test-issuer",
        agency="abc",
        jws_signing_alg="RS256",
        client_private_key=_get_key("client.pub"),
        jwe_encryption_alg="RSA-OAEP",
        jwe_cek_enc="A256CBC-HS512",
        server_public_key=_get_key("server.key"),
    )


def _get_key(filename):
    current_path = Path(os.path.dirname(os.path.realpath(__file__)))
    file_path = current_path / "keys" / filename

    with file_path.open(mode="rb") as pemfile:
        key = str(pemfile.read(), "utf-8")

    return key


def test_create_valid_client():
    try:
        Client(**_valid_configuration())
    except Exception:
        pytest.fail("Failed to create valid Client")


@pytest.mark.parametrize(
    "header_name", ["Authorization", "authorization", "AuThOrIzAtIoN"]
)
def test_create_invalid_client_bad_headers(header_name):
    headers = {header_name: "value"}

    with pytest.raises(ValueError):
        Client(**_valid_configuration(), headers=headers)


@responses.activate
def test_client_verify_success(mocker):
    responses.add(responses.Response(method="GET", url="http://localhost/verify"))

    client = Client(**_valid_configuration())

    mock_request_token = mocker.patch("eligibility_api.tokens.RequestToken")
    mocker.patch.object(client, "_tokenize_request", return_value=mock_request_token)

    mock_response_token = mocker.patch("eligibility_api.tokens.ResponseToken")
    mocker.patch.object(client, "_tokenize_response", return_value=mock_response_token)

    try:
        client.verify("A1234567", "Garcia", ["type1"])
    except Exception:
        pytest.fail("Failed to return from Client.verify")


def test_client_verify_unexpected_response_code():
    pass


def test_client_verify_failed_request():  # should be parameterized
    pass


def test_client_verify_failed_tokenize_request():
    pass


def test_client_verify_failed_tokenize_response():
    pass
