import json
from http import HTTPStatus

from src.responses import CreditBalanceResponse, Response


class TestResponses:
    def test_response(self):
        content = "Hello 世界 🌍 <script>alert('xss')</script>"
        test_headers = {"Content-Type": "text/plain", "X-Custom": "café ñ"}

        response = Response(HTTPStatus.OK, content, test_headers)

        assert response.status_code == HTTPStatus.OK
        assert content.encode("utf-8") == response.content
        assert "X-Custom" in response.headers

    def test_credit_balance_response(self):
        response = CreditBalanceResponse()

        body = json.loads(response.text)
        assert body["balance"] > 0
        assert body["timestamp"].endswith("Z")
