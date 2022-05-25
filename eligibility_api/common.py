from jwcrypto import jwk


def create_jwk(self, pem_data):
    if isinstance(pem_data, str):
        pem_data = bytes(pem_data, "utf-8")

    return jwk.JWK.from_pem(pem_data)
