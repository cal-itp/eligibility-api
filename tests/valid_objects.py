"""
Helper functions for creating valid objects for testing.
"""
from eligibility import api
import uuid


def valid_signing_config(private_jwk):
    return api.SigningConfig("RS256", private_jwk)


def valid_encryption_config(public_jwk):
    return api.EncryptionConfig("RSA-OAEP", "A256CBC-HS512", public_jwk)


def valid_request_payload():
    return api.RequestPayload(
        iss="localhost",
        agency_id="abc",
        eligibility=["type1"],
        sub="A1234567",
        name="Garcia",
    )


def valid_response_payload_with_eligibility():
    return api.ResponsePayload(
        jti=_get_jti_for_response(), iss="verifier.app", eligibility=["type1"]
    )


def valid_response_payload_with_error():
    return api.ResponsePayload(
        jti=_get_jti_for_response(), iss="verifier.app", error={"sub": "invalid"}
    )


def _get_jti_for_response():
    """In actual usage, the response's jti should be set from the request's jti."""
    return str(uuid.uuid4())
