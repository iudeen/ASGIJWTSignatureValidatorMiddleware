<h1 align="center">
    <strong>JWT Signature Validator</strong>
</h1>
<p align="center">
    <a href="https://github.com/iudeen/jwt-signature-validator" target="_blank">
        <img src="https://img.shields.io/github/last-commit/iudeen/ASGIJWTSignatureValidatorMiddleware" alt="Latest Commit">
    </a>
        <img src="https://img.shields.io/github/workflow/status/iudeen/ASGIJWTSignatureValidatorMiddleware/CI">
        <img src="https://img.shields.io/codecov/c/github/iudeen/jwt-signature-validator">
    <br />
    <a href="https://pypi.org/project/jwt-signature-validator" target="_blank">
        <img src="https://img.shields.io/pypi/v/jwt-signature-validator" alt="Package version">
    </a>
    <img src="https://img.shields.io/pypi/pyversions/jwt-signature-validator">
    <img src="https://img.shields.io/github/license/iudeen/ASGIJWTSignatureValidatorMiddleware">
</p>

JWT Signature Middleware is a pure ASGI Middleware that can be used with AGSI frameworks like FastAPI, Starlette and Sanic.


## Installation

```bash
pip install jwt-signature-validator
```

## Usage

```python
from fastapi import FastAPI
from jwt_signature_validator import EncodedPayloadSignatureMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    EncodedPayloadSignatureMiddleware,
    jwt_secret="hello",
    jwt_algorithms=["HS256"],
    protect_hosts=["*"]
)


class Model(BaseModel):
    text: str


@app.post("/")
def check(req: Model):
    return req

```

## License

This project is licensed under the terms of the MIT license.
