import os
from functools import wraps
from pathlib import Path

import pytest
import requests
import responses

from eligibility_api.client import ApiError, Client


def _test_data():
    return ("A1234567", "Garcia", ["type1"])


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


def mock_server_response(
    _func=None, *, method="GET", url="http://localhost/verify", status=200
):
    def decorator(func):
        @responses.activate
        @wraps(func)
        def wrapper(*args, **kwargs):
            response = responses.Response(method=method, url=url)
            if "status" in kwargs:
                response.status = kwargs["status"]
            else:
                response.status = status

            responses.add(response)

            return func(*args, **kwargs)

        return wrapper

    if _func is None:
        return decorator
    else:
        return decorator(_func)


def mock_request_token(mocker, client):
    mock_request_token = mocker.patch("eligibility_api.tokens.RequestToken")
    mocker.patch.object(client, "_tokenize_request", return_value=mock_request_token)


def mock_response_token(mocker, client):
    mock_response_token = mocker.patch("eligibility_api.tokens.ResponseToken")
    mocker.patch.object(client, "_tokenize_response", return_value=mock_response_token)


@mock_server_response
def test_client_verify_success(mocker):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client)

    try:
        client.verify(*_test_data())
    except Exception:
        pytest.fail("Failed to return from Client.verify")


@mock_server_response
@pytest.mark.parametrize("status", [403, 404, 500])
def test_client_verify_unexpected_response_code(mocker, status):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client)

    with pytest.raises(ApiError):
        client.verify(*_test_data())


def mock_server_error(
    _func=None, *, method="GET", url="http://localhost/verify", exception=RuntimeError
):
    def decorator(func):
        @wraps(func)
        @responses.activate
        def wrapper(*args, **kwargs):
            response = responses.Response(method=method, url=url)

            if "expected_exception" in kwargs:
                response.body = kwargs["expected_exception"]()
            else:
                response.body = exception()

            responses.add(response)
            return func(*args, **kwargs)

        return wrapper

    if _func is None:
        return decorator
    else:
        return decorator(_func)


@mock_server_error
@pytest.mark.parametrize(
    "expected_exception",
    [
        requests.ConnectionError,
        requests.Timeout,
        requests.TooManyRedirects,
        requests.HTTPError,
    ],
)
def test_client_verify_failed_request(mocker, expected_exception):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client)

    with pytest.raises(ApiError):
        client.verify(*_test_data())


def test_client_verify_failed_tokenize_request():
    pass


def test_client_verify_failed_tokenize_response():
    pass
