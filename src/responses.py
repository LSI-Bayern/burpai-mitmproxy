import datetime
import json
import time
from http import HTTPStatus

import mitmproxy.http


def headers():
    return {
        "Content-Type": "application/json",
        "Portswigger-Hakawai-Ai": ",".join(
            [
                "creditCost=0.00000000000000000",
                "balance=1337",
                f"balanceTimestamp={datetime.datetime.now(tz=datetime.UTC).isoformat().replace('+00:00', 'Z')}",
            ]
        ),
    }


class Response(mitmproxy.http.Response):
    def __init__(
        self,
        status_code: HTTPStatus,
        content: str,
        headers: dict[str, str],
    ) -> None:
        encodeargs = {
            "encoding": "utf-8",
            "errors": "surrogateescape",
        }
        super().__init__(
            http_version=b"HTTP/1.1",
            status_code=status_code,
            reason=status_code.phrase.encode(),
            headers=mitmproxy.http.Headers(
                (k.encode(**encodeargs), v.encode(**encodeargs)) for k, v in headers.items()
            ),
            content=content.encode("utf-8"),
            trailers=None,
            timestamp_start=time.time(),
            timestamp_end=time.time(),
        )


class CreditBalanceResponse(Response):
    def __init__(self) -> None:
        super().__init__(
            status_code=HTTPStatus.OK,
            headers=headers(),
            content=json.dumps(
                {
                    "balance": 1337,
                    "timestamp": datetime.datetime.now(tz=datetime.UTC).isoformat().replace("+00:00", "Z"),
                }
            ),
        )
