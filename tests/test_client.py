import os
from functools import wraps
from pathlib import Path

from jwcrypto import common as jwcrypto
import pytest
import requests
import responses

from eligibility_api.client import ApiError, Client, TokenError


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
    # Creating a valid Client should not throw an Exception
    try:
        Client(**_valid_configuration())
    except Exception:
        pytest.fail("Failed to create valid Client")


@pytest.mark.parametrize("header_name", ["Authorization", "authorization", "AuThOrIzAtIoN"])
def test_create_invalid_client_bad_headers(header_name):
    headers = {header_name: "value"}

    with pytest.raises(ValueError):
        Client(**_valid_configuration(), headers=headers)


def mock_server_response(_func=None, *, method="GET", url="http://localhost/verify", status=200):
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


def mock_request_token(mocker, client, exception=None):
    if exception is None:
        mock_request_token = mocker.patch("eligibility_api.tokens.RequestToken")
        mocker.patch.object(client, "_tokenize_request", return_value=mock_request_token)
    else:
        mocker.patch.object(client, "_tokenize_request", side_effect=exception())


def mock_response_token(mocker, client, exception=None):
    if exception is None:
        mock_response_token = mocker.patch("eligibility_api.tokens.ResponseToken")
        mocker.patch.object(client, "_tokenize_response", return_value=mock_response_token)
    else:
        mocker.patch.object(client, "_tokenize_request", side_effect=exception())


@mock_server_response
@pytest.mark.parametrize("status", [200, 400])  # API spec has 400 as an expected code
def test_client_verify_success(mocker, status):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client)

    # Calling verify with a successful server response should not throw an Exception
    try:
        client.verify(*_test_data())
    except Exception:
        pytest.fail("Failed to return from Client.verify")


@mock_server_response
def test_create_valid_client_additional_headers(mocker):
    headers = {"X-Server-API-Key": "server-auth-token"}

    # Creating a valid client with valid additional headers should not throw an Exception
    try:
        client = Client(**_valid_configuration(), headers=headers)
    except Exception:
        pytest.fail("Failed to create valid Client")

    mock_request_token(mocker, client)
    mock_response_token(mocker, client)

    # Calling verify with a successful server response and valid additional headers
    # should not throw an Exception
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

    with pytest.raises(ApiError, match="Unexpected eligibility verification response"):
        client.verify(*_test_data())


def mock_server_error(_func=None, *, method="GET", url="http://localhost/verify", exception=RuntimeError):
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
    "expected_exception,match",
    [
        (requests.ConnectionError, "Connection to verification server failed"),
        (requests.Timeout, "Connection to verification server timed out"),
        (requests.TooManyRedirects, "Too many redirects to verification server"),
        (requests.HTTPError, ""),
    ],
)
def test_client_verify_failed_request(mocker, expected_exception, match):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client)

    with pytest.raises(ApiError, match=match):
        client.verify(*_test_data())


@mock_server_response
def test_client_verify_failed_tokenize_request(mocker):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client, exception=jwcrypto.JWException)
    mock_response_token(mocker, client)

    with pytest.raises(TokenError, match="Failed to tokenize form values"):
        client.verify(*_test_data())


@mock_server_response
def test_client_verify_failed_tokenize_response(mocker):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client, exception=TokenError)

    with pytest.raises(TokenError):
        client.verify(*_test_data())
