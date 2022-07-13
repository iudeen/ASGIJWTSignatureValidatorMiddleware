import inspect

import jwt_signature_validator


def test_smoke() -> None:
    assert inspect.ismodule(jwt_signature_validator)
