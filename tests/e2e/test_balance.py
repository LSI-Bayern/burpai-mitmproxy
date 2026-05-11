import pytest

pytestmark = [pytest.mark.anyio, pytest.mark.e2e]


async def test_balance_returns_200_with_credit_header(burp):
    resp = await burp.get_balance()

    assert resp.status_code == 200
    assert "Portswigger-Hakawai-Ai" in resp.headers
    header = resp.headers["Portswigger-Hakawai-Ai"]
    assert "balance=1337" in header
    assert "creditCost=" in header
