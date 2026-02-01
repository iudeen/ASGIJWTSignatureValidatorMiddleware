import http
import logging
import typing

try:
    from fastapi.exceptions import HTTPException as FastAPIHTTPException
except ImportError:
    logging.warning("FastAPI not found. Using base Exception for HTTPException.")
    FastAPIHTTPException = Exception


class HTTPException(FastAPIHTTPException):
    def __init__(
        self,
        status_code: int,
        detail: str | None = None,
        headers: dict[typing.Any, typing.Any] | None = None,
    ) -> None:
        if detail is None:
            detail = http.HTTPStatus(status_code).phrase
        self.status_code = status_code
        self.detail = detail
        self.headers = headers
        try:
            super().__init__(status_code=status_code, detail=detail, headers=headers)
        except TypeError:
            super().__init__(detail)

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}(status_code={self.status_code!r}, detail={self.detail!r})"
