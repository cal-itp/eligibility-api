import pytest
import os

from eligibility import api


@pytest.fixture
def client_private_jwk() -> api.JWK:
    return load_pem_file("fixtures/client_private_key.pem")


@pytest.fixture
def client_public_jwk() -> api.JWK:
    return load_pem_file("fixtures/client_public_key.pem")


@pytest.fixture
def server_private_jwk() -> api.JWK:
    return load_pem_file("fixtures/server_private_key.pem")


@pytest.fixture
def server_public_jwk() -> api.JWK:
    return load_pem_file("fixtures/server_public_key.pem")


def load_pem_file(file_name: str) -> api.JWK:
    file_name = os.path.join(os.path.dirname(__file__), file_name)
    with open(file_name, "r") as file:
        jwk = api.JWK.from_pem(bytes(file.read(), "utf-8"))

    return jwk
