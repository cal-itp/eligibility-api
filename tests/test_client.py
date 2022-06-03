from jwcrypto import common as jwcrypto
import pytest
import requests
import responses

from eligibility_api.client import ApiError, Client, TokenError


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


@responses.activate
@pytest.mark.parametrize("status", [200, 400])  # API spec has 400 as an expected code
def test_client_verify_success(mocker, status):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client)
    mock_server_response(status=status)

    # Calling verify with a successful server response should not throw an Exception
    try:
        client.verify(*_test_data())
    except Exception:
        pytest.fail("Failed to return from Client.verify")


@responses.activate
def test_create_valid_client_additional_headers(mocker):
    mock_server_response()
    # Creating a valid client with valid additional headers should not throw an Exception
    headers = {"X-Server-API-Key": "server-auth-token"}
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


@responses.activate
@pytest.mark.parametrize("status", [403, 404, 500])
def test_client_verify_unexpected_response_code(mocker, status):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client)
    mock_server_response(status=status)

    with pytest.raises(ApiError, match="Unexpected eligibility verification response"):
        client.verify(*_test_data())


@responses.activate
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
    mock_server_error(exception=expected_exception)

    with pytest.raises(ApiError, match=match):
        client.verify(*_test_data())


@responses.activate
def test_client_verify_failed_tokenize_request(mocker):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client, exception=jwcrypto.JWException)
    mock_response_token(mocker, client)
    mock_server_response()

    with pytest.raises(TokenError, match="Failed to tokenize form values"):
        client.verify(*_test_data())


@responses.activate
def test_client_verify_failed_tokenize_response(mocker):
    client = Client(**_valid_configuration())
    mock_request_token(mocker, client)
    mock_response_token(mocker, client, exception=TokenError)
    mock_server_response()

    with pytest.raises(TokenError):
        client.verify(*_test_data())


def _test_data():
    return ("A1234567", "Garcia", ["type1"])


def _test_client_private_key():
    return """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1pt0ZoOuPEVPJJS+5r88
4zcjZLkZZ2GcPwr79XOLDbOi46onCa79kjRnhS0VUK96SwUPS0z9J5mDA5LSNL2R
oxFb5QGaevnJY828NupzTNdUd0sYJK3kRjKUggHWuB55hwJcH/Dx7I3DNH4NL68U
AlK+VjwJkfYPrhq/bl5z8ZiurvBa5C1mDxhFpcTZlCfxQoas7D1d+uPACF6mEMbQ
Nd3RaIaSREO50NvNywXIIt/OmCiRqI7JtOcn4eyh1I4j9WtlbMhRJLfwPMAgY5ep
TsWcURmhVofF2wVoFbib3JGCfA7tz/gmP5YoEKnf/cumKmF3e9LrZb8zwm7bTHUV
iwIDAQAB
-----END PUBLIC KEY-----
"""


def _test_server_public_key():
    return """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyYo6Pe9OSfPGX0oQXyLAblOwrMgc/j1JlF07b1ahq1lc3FH0
XEk3Dzqbt9NuQs8hz6493vBNtNWTpVmvbGe4VX3UjhpEARhN3m4jf/Z2OEuDt2A9
q19NLSjgeyhieLkYLwN1ezYXrkn7cfOngcJMnGDXp45CaA+g3DzasrjETnKUdqec
CzJ3FJ/RRwfibrju7eS/8s6H03nvydzeAJzTkEv7Fic2JJEUhh2rJhyLxt+qKkIY
eBG+5fBri4miaS8FPnD/yjZzEAFsQc7n0dGqDAhSJS8tYNmXFmGlaCfRUBNV3mvO
x0vFPuH21WQ5KKZxZP0e64/uQdotbPIImiyRJwIDAQABAoIBAQCt0ezXe+yOtZQS
nSMvmh5TSRTogBMZZyxtrFdVeGcpDIKddoWFjpPRK6Af1FeVgWXM459zBthOLaIQ
iyBUI8SE32iSQq8CLr8CJwWxGJTvipmIb5XglupOF6I8NiFvs1vbOGV7pbSY2i/m
INoIfNZsTM3SMkytyUTYjhek6txMNtc2yi/3HIVhpEaP8sZrufVGXFbLBOUKgjZC
h7la/jeSOfb48xoZ8wRq/MHQ1dedH5M19voxEBAcrZlIYiqd4cTr724NQHOJZXNf
frVq89jKqRvqkPblCPaXqwk8wBfVQyH9LFLbnul2QTxbFRxLXNeoO9qc1ZDwqSXF
7uRam8y5AoGBAPWs0l2Iilbo+sCSuZK2numdXxnFiJTVuipHpmJXAbKZY/CvayAQ
pz/mwX34kpTqN9dotnSJYv8y+HQdfdMrPGKQ96RVsl0HJbWHtbiAPtHRXo6gJYho
th1BhBa1NjJfTXeO7ulPT7OMmKRWC9CEk/OX+rlcHOmpuuebOPKFiSLlAoGBANIC
kCPL1Ol4sP1RkcDEu06+bqUdi4QvKSgHBmzLb5w+0Ufl8ay3Zp64p4rGMd29L7IV
wTXPl/B4TdpDKYw84bcsXE2NWfdT6kDaIMWCuiB/iJXTpntHVejRyrd3dz7jwHfy
PaD5k+KbN2XROIkag0xg7IRmjhJLN5ZxIJIvgScbAoGBAPMmA+J8w+Z2mc7EqRQy
2J8AmWIpZh9gVOuJlHxZ/p0kQYyyIUVQFighm7mwrmriUThKM+KtIyTO7qYFlkXM
0ev/7IliI7D85O6AjXM4wnPpUzu39s3GTRAxiqjq2uQJ/OLqvTx+ubRL37suSm0q
+j+qWITiTN9alFisATXOwkadAoGBAL6mEwJcHZohtdMSBNZSApS2ri15B9nlEmDD
F+MWP+lA4a56og4gpKl8iqShzk01XSI3O6JFJfLo1AxLomEsN+CZBeZlZwHvjR54
pv2G8r9j57PUYzNRDD2CjpxFeNx/149MOwRy7fzu2bi12bQlfIKPDsgXbexPmlQZ
uO7c70t3AoGAFrdmmr0Ygt8/b1/j7NwvdaDcQj2uadz0sbqmzBFQSEgbRpD9JRC2
d21vhv00lZ5VwJ+Bgr35zZ2LeNna1+phlj+rySSHNtz/iDplMMZQvyIHpoUMaccp
Trt9yCdC1nTavTHbChT4AYkXR87g0EHFhs5w20ILFpPHT1NAARonkJo=
-----END RSA PRIVATE KEY-----
"""


def _valid_configuration():
    return dict(
        verify_url="http://localhost/verify",
        issuer="test-issuer",
        agency="abc",
        jws_signing_alg="RS256",
        client_private_key=_test_client_private_key(),
        jwe_encryption_alg="RSA-OAEP",
        jwe_cek_enc="A256CBC-HS512",
        server_public_key=_test_server_public_key(),
    )


def mock_server_response(method="GET", url="http://localhost/verify", status=200):
    response = responses.Response(method=method, url=url, status=status)
    responses.add(response)


def mock_server_error(method="GET", url="http://localhost/verify", exception=RuntimeError):
    response = responses.Response(method=method, url=url, body=exception())
    responses.add(response)


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
