import pytest

pytestmark = [pytest.mark.anyio, pytest.mark.e2e]


async def test_explain_returns_content(fake_llm, burp):
    fake_llm.enqueue_response("This header reveals the server software version.")

    resp = await burp.explain(text="Server: Apache/2.4.41", context="RESPONSE_HEADERS")

    assert resp.status_code == 200
    data = resp.json()
    assert data["content"] == "This header reveals the server software version."


async def test_explain_sends_context_in_system_prompt(fake_llm, burp):
    fake_llm.enqueue_response("Explanation text")

    await burp.explain(text="GET /admin HTTP/1.1", context="REQUEST_LINE")

    assert len(fake_llm.received_requests) == 1
    messages = fake_llm.received_requests[0]["messages"]
    system_msg = next(m for m in messages if m["role"] == "system")
    assert "request line" in system_msg["content"].lower()
