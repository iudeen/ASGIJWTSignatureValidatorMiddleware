import random
import string

import jwt
from starlette.types import Message


async def mock_receive() -> Message:
    raise NotImplementedError  # pragma: no cover


async def mock_send(message: Message) -> None:
    raise NotImplementedError  # pragma: no cover


def encode_payload(payload: dict, key: str, algorithm: str):
    return jwt.encode(payload, key, algorithm)


def encode_payload_modify(payload: dict, key: str, algorithm: str):
    encoded_payload = jwt.encode(payload, key, algorithm)
    encoded_payload = list(encoded_payload)
    random.shuffle(encoded_payload)
    return "".join(encoded_payload)


async def generate_large_data():
    async def get_string(n: int = 10):
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))

    data = {}
    for _ in range(1000):
        data.update({await get_string(): await get_string(100)})
    return data
