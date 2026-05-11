import pytest

pytestmark = [pytest.mark.anyio, pytest.mark.e2e]


async def test_montoya_returns_content(fake_llm, burp):
    fake_llm.enqueue_response("SQL injection occurs when...")

    resp = await burp.montoya(
        messages=[
            {"type": "system", "text": "You are a security expert."},
            {"type": "user", "text": "What is SQL injection?"},
        ]
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["content"] == "SQL injection occurs when..."


async def test_montoya_passes_temperature(fake_llm, burp):
    fake_llm.enqueue_response("Response")

    await burp.montoya(
        messages=[{"type": "user", "text": "Hello"}],
        temperature=0.5,
    )

    assert len(fake_llm.received_requests) == 1
    assert fake_llm.received_requests[0]["temperature"] == 0.5
