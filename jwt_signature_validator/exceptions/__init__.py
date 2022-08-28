import http
import typing

try:
    from fastapi.exceptions import HTTPException as FastAPIHTTPException
except ImportError:
    FastAPIHTTPException = Exception


class HTTPException(FastAPIHTTPException):
    def __init__(
        self,
        status_code: int,
        detail: typing.Optional[str] = None,
        headers: typing.Optional[dict[typing.Any, typing.Any]] = None,
    ) -> None:
        if detail is None:
            detail = http.HTTPStatus(status_code).phrase
        self.status_code = status_code
        self.detail = detail
        self.headers = headers
        super().__init__(status_code=status_code, detail=detail, headers=headers)

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}(status_code={self.status_code!r}, detail={self.detail!r})"
