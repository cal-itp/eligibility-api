import pytest
import uuid
from jwcrypto import jws

from tests.valid_objects import (
    valid_signing_config,
    valid_encryption_config,
    valid_request_payload,
)

from eligibility import api


def test_payload_generated_values():
    """Tests that generated values in RequestPayload are as expected."""
    # Given/When
    payload = valid_request_payload()
    # Then
    assert uuid.UUID(payload.jti) is not None
    assert payload.iat is not None and type(payload.iat) == int


def test_create_valid_token(client_private_jwk, server_public_jwk):
    """Tests that a valid RequestPayload and valid configs can create a valid Token."""
    # Given
    payload = valid_request_payload()
    signing_config = valid_signing_config(client_private_jwk)
    encryption_config = valid_encryption_config(server_public_jwk)

    # When
    token = api.Token(payload, signing_config, encryption_config)

    # Then
    assert token._jwe is not None


def test_valid_token_to_payload(
    client_private_jwk, client_public_jwk, server_private_jwk, server_public_jwk
):
    """Tests that given a Token, you can get back a RequestPayload that is
    equivalent to the original one (ignoring generated values).
    """
    # Given
    token = api.Token(
        valid_request_payload(),
        valid_signing_config(client_private_jwk),
        valid_encryption_config(server_public_jwk),
    )

    # When
    parsed_payload = api.RequestPayload.from_token(
        str(token),
        valid_signing_config(server_private_jwk),  # decrypt using server's private key
        valid_encryption_config(
            client_public_jwk
        ),  # verify signature using the client's public key
    )

    # Then
    expected = valid_request_payload()

    # ignore jti and iat fields since they are generated
    parsed_payload.jti = ""
    parsed_payload.iat = 0
    expected.jti = ""
    expected.iat = 0

    assert parsed_payload == expected


def test_invalid_signing_config_raises_exception(client_private_jwk, server_public_jwk):
    """Tests that given an invalid signing algorithm, an attempt to create a Token will raise an exception."""
    with pytest.raises(jws.InvalidJWSOperation):
        # Given
        invalid_signing_config = api.SigningConfig("invalid", client_private_jwk)

        # When
        api.Token(
            valid_request_payload(),
            invalid_signing_config,
            valid_encryption_config(server_public_jwk),
        )
