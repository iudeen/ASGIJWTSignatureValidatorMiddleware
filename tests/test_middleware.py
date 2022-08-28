import httpx
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from jwt_signature_validator import EncodedPayloadSignatureMiddleware
from jwt_signature_validator.exceptions import HTTPException
from tests.utils import encode_payload, encode_payload_modify, generate_large_data


@pytest.mark.asyncio
async def test_unprotected_request() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive=receive)
        data = await request.json()
        response = JSONResponse(data)
        await response(scope, receive, send)

    app = EncodedPayloadSignatureMiddleware(
        app,
        jwt_secret="hello",
        jwt_algorithms=["HS256"],
        protect_hosts=["www.example.com"],
    )

    async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
        body = {"test": "test"}
        r = await client.post("/", json=body)
        assert r.status_code == 200
        assert r.json() == body


@pytest.mark.asyncio
async def test_protected_request_fail() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive=receive)
        data = await request.json()
        response = JSONResponse(data)
        await response(scope, receive, send)

    app = EncodedPayloadSignatureMiddleware(
        app, jwt_secret="hello", jwt_algorithms=["HS256"], protect_hosts=["testserver"]
    )
    with pytest.raises(HTTPException):
        async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
            body = {"test": "test"}
            await client.post("/", json=body)


@pytest.mark.asyncio
async def test_protected_request_success() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive=receive)
        data = await request.json()
        response = JSONResponse(data)
        await response(scope, receive, send)

    app = EncodedPayloadSignatureMiddleware(
        app, jwt_secret="hello", jwt_algorithms=["HS256"], protect_hosts=["testserver"]
    )
    async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
        body = {"test": "test"}
        encoded_body = encode_payload(body, "hello", "HS256")
        r = await client.post(
            "/", content=encoded_body, headers={"content-type": "application/json"}
        )
        assert r.status_code == 200
        assert r.json() == body


@pytest.mark.asyncio
async def test_protected_request_tampered() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive=receive)
        data = await request.json()
        response = JSONResponse(data)
        await response(scope, receive, send)

    app = EncodedPayloadSignatureMiddleware(
        app, jwt_secret="hello", jwt_algorithms=["HS256"], protect_hosts=["testserver"]
    )
    with pytest.raises(HTTPException):
        async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
            body = {"test": "test"}
            encoded_body = encode_payload_modify(body, "hello", "HS256")
            await client.post(
                "/", content=encoded_body, headers={"content-type": "application/json"}
            )


@pytest.mark.asyncio
async def test_protected_request_large() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive=receive)
        data = await request.json()
        response = JSONResponse(data)
        await response(scope, receive, send)

    app = EncodedPayloadSignatureMiddleware(
        app, jwt_secret="hello", jwt_algorithms=["HS256"], protect_hosts=["testserver"]
    )
    async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
        body = await generate_large_data()
        encoded_body = encode_payload(body, "hello", "HS256")
        await client.post(
            "/", content=encoded_body, headers={"content-type": "application/json"}
        )


@pytest.mark.asyncio
async def test_unprotected_request_large() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive=receive)
        data = await request.json()
        response = JSONResponse(data)
        await response(scope, receive, send)

    app = EncodedPayloadSignatureMiddleware(
        app, jwt_secret="hello", jwt_algorithms=["HS256"], protect_hosts=["example.com"]
    )
    async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
        body = await generate_large_data()
        await client.post("/", json=body, headers={"content-type": "application/json"})
