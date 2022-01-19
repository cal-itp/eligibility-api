import pytest

from tests.valid_objects import (
    valid_signing_config,
    valid_encryption_config,
    valid_response_payload_with_eligibility,
    valid_response_payload_with_error,
)
from eligibility import api


def _valid_payloads():
    return [
        valid_response_payload_with_eligibility(),
        valid_response_payload_with_error(),
    ]


def _display_names():
    return ["with eligibility", "with error"]


@pytest.mark.parametrize(
    argnames="payload",
    argvalues=_valid_payloads(),
    ids=_display_names(),
)
def test_payload_generated_values(payload):
    """Tests that generated values in ResponsePayload are as expected"""
    assert payload.iat is not None and type(payload.iat) == int


@pytest.mark.parametrize(
    argnames="payload", argvalues=_valid_payloads(), ids=_display_names()
)
def test_create_valid_token(payload, server_private_jwk, client_public_jwk):
    """Tests that a valid ResponsePayload and valid configs can create a valid Token."""
    # Given
    signing_config = valid_signing_config(server_private_jwk)
    encryption_config = valid_encryption_config(client_public_jwk)

    # When
    token = api.Token(payload, signing_config, encryption_config)

    # Then
    assert token._jwe is not None


@pytest.mark.parametrize(
    argnames="payload",
    argvalues=_valid_payloads(),
    ids=_display_names(),
)
def test_valid_token_to_payload(
    payload,
    client_private_jwk,
    client_public_jwk,
    server_private_jwk,
    server_public_jwk,
):
    """Tests that given a Token, you can get back a ResponsePayload that is
    equivalent to the original one (ignoring generated values).
    """
    # Given
    token = api.Token(
        payload,
        valid_signing_config(server_private_jwk),
        valid_encryption_config(client_public_jwk),
    )

    # When
    parsed_payload = api.ResponsePayload.from_token(
        str(token),
        valid_signing_config(client_private_jwk),  # decrypt using client's private key
        valid_encryption_config(
            server_public_jwk
        ),  # verify signature using the server's public key
    )

    # Then
    expected = payload

    # ignore iat since it is generated
    parsed_payload.iat = 0
    expected.iat = 0

    assert parsed_payload == expected
