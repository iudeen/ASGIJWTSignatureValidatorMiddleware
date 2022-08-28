import random
import string
from typing import Any

import jwt


def encode_payload(payload: dict[Any, Any], key: str, algorithm: str) -> str:
    return jwt.encode(payload, key, algorithm)


def encode_payload_modify(payload: dict[Any, Any], key: str, algorithm: str) -> str:
    _encoded_payload = jwt.encode(payload, key, algorithm)
    encoded_payload = list(_encoded_payload)
    random.shuffle(encoded_payload)
    return "".join(encoded_payload)


async def generate_large_data() -> dict[str, str]:
    async def get_string(n: int = 10) -> str:
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))

    data = {}
    for _ in range(1000):
        data.update({await get_string(): await get_string(100)})
    return data
