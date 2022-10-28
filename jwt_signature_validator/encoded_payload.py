# mypy: ignore-errors

import logging
import pathlib
from os import PathLike
from typing import Optional, Union

try:
    import jwt
    from jwt.exceptions import (
        DecodeError,
        ExpiredSignatureError,
        InvalidSignatureError,
        MissingRequiredClaimError,
    )
except ImportError:
    logging.warning("pyjwt not found. Run pip install pyjwt")
    jwt = None
    InvalidSignatureError = None
    ExpiredSignatureError = None
    MissingRequiredClaimError = None
    DecodeError = None

try:
    import ujson as json
except ImportError:
    import json

from jwt_signature_validator.datastructures import MutableHeaders
from jwt_signature_validator.exceptions import HTTPException
from jwt_signature_validator.types import Receive, Scope, Send

ENFORCE_DOMAIN_WILDCARD = "Domain wildcard patterns must be like '*.example.com'."


class EncodedPayloadSignatureMiddleware:
    def __init__(
        self,
        app,
        jwt_algorithms: list[str],
        protect_hosts: list = None,
        jwt_secret: Optional[str] = None,
        secret_path: Union[str, None, "PathLike[str]"] = None,
    ):
        self.app = app
        self.protect_hosts = protect_hosts
        if secret_path:
            self.path = pathlib.Path(secret_path)
            if not self.path.is_file():
                raise FileExistsError
            with open(self.path, "r") as secret_path_file:
                self.jwt_secret = secret_path_file.read()
        else:
            self.jwt_secret = jwt_secret
        self.jwt_algorithms = jwt_algorithms
        self.validate_request_types = ["POST", "PUT", "DELETE"]
        if not self.protect_hosts:
            self.protect_hosts = ["*"]

        for _pattern in self.protect_hosts:
            assert "*" not in _pattern[1:], ENFORCE_DOMAIN_WILDCARD
            if _pattern.startswith("*") and _pattern != "*":
                assert _pattern.startswith("*."), ENFORCE_DOMAIN_WILDCARD

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            """
            this middleware only handles http scope.
            Ignore other ASGI compatible scopes (lifespan and websockets) here.
            """

            return await self.app(scope, receive, send)

        async def decode_jwt(signature):
            try:
                return jwt.decode(signature, self.jwt_secret, self.jwt_algorithms)
            except (
                InvalidSignatureError,
                ExpiredSignatureError,
                MissingRequiredClaimError,
                DecodeError,
            ) as inv_exp:
                logging.error(inv_exp)
                raise HTTPException(
                    status_code=403, detail="Payload Tampered or Invalid!"
                )

        async def verify_signature():
            try:
                receive_ = await receive()
                signature = bytearray()
                signature.extend(receive_.get("body"))
                while receive_["more_body"]:
                    receive_ = await receive()
                    signature.extend(receive_["body"])

                signature = bytes(signature).decode()
                decoded_signature = await decode_jwt(signature)
                _payload = json.dumps(decoded_signature).encode()
                return {"type": receive_["type"], "body": _payload, "more_body": False}
            except HTTPException:
                raise
            except Exception as e:
                logging.error(e)
                raise HTTPException(
                    status_code=403,
                    detail=f"Unable to authorize payload signature. Error: {e}",
                )

        async def content_type_validation_failed():
            raise HTTPException(status_code=406, detail="Unacceptable Content Type!")

        headers = MutableHeaders(scope=scope)

        if (
            headers.get("Content-Type") in ["", None]
            and scope.get("method", "POST") in self.validate_request_types
        ):
            await self.app(scope, content_type_validation_failed, send)
            return
        elif headers.get("Content-Type") == "application/json":
            host = headers.get("host", "").split(":")[0]
            is_protected_host = False
            for pattern in self.protect_hosts:
                if any(
                    [
                        host == pattern,
                        (pattern.startswith("*") and host.endswith(pattern[1:])),
                    ]
                ):
                    is_protected_host = True
                    break
            if is_protected_host:
                await self.app(scope, verify_signature, send)
                return
        await self.app(scope, receive, send)
