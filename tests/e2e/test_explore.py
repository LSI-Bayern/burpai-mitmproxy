import json

import pytest

from .conftest import make_tool_call

pytestmark = [pytest.mark.anyio, pytest.mark.e2e]

SAMPLE_ISSUE = {
    "name": "REQUEST_RESPONSE_EXPLORE",
    "type": "INFORMATION",
    "detail": "Send a request",
    "target": "https://example.org",
    "evidence": [
        {
            "type": "REQUEST_RESPONSE",
            "request": "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n",
        }
    ],
}


def repeater_response(tool_id="tool-1", title="Probe", action="Send request"):
    return {
        "content": "",
        "tool_calls": [
            make_tool_call(tool_id, "repeater", {
                "step_title": title,
                "step_action": action,
                "request": "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n",
            })
        ],
    }


async def test_start_and_poll_complete(fake_llm, burp):
    fake_llm.enqueue_response(repeater_response())

    resp = await burp.explore_start(SAMPLE_ISSUE)
    assert resp.status_code == 202
    accepted = resp.json()
    assert "step_id" in accepted
    assert "exploration_id" not in accepted

    status = await burp.poll_until_terminal(accepted["step_id"])
    assert status["state"] == "COMPLETE"
    assert "exploration_id" in status
    assert status["response"]["tool_calls"][0]["tool_name"] == "repeater"


async def test_status_pending_or_processing_before_complete(fake_llm, burp):
    fake_llm.enqueue_delayed_response(0.5, repeater_response())

    resp = await burp.explore_start(SAMPLE_ISSUE)
    step_id = resp.json()["step_id"]

    # Check intermediate state before the delayed response arrives
    status_resp = await burp.explore_status(step_id)
    intermediate = status_resp.json()
    assert intermediate["state"] in ("PENDING", "PROCESSING")
    assert "poll_interval_seconds" in intermediate

    status = await burp.poll_until_terminal(step_id)
    assert status["state"] == "COMPLETE"


async def test_continue_with_tool_results(fake_llm, burp):
    fake_llm.enqueue_response(repeater_response("tool-1"))

    resp = await burp.explore_start(SAMPLE_ISSUE)
    start_status = await burp.poll_until_terminal(resp.json()["step_id"])
    exploration_id = start_status["response"]["exploration_id"]
    tool_call_id = start_status["response"]["tool_calls"][0]["id"]

    fake_llm.enqueue_response(repeater_response("tool-2", title="Follow-up"))

    resp = await burp.explore_continue(
        exploration_id,
        [{"tool_id": tool_call_id, "result": "HTTP/1.1 200 OK\r\n\r\nOK"}],
    )
    assert resp.status_code == 202
    assert resp.json()["exploration_id"] == exploration_id

    status = await burp.poll_until_terminal(resp.json()["step_id"])
    assert status["state"] == "COMPLETE"
    assert status["response"]["tool_calls"][0]["tool_name"] == "repeater"


async def test_internal_tools_loop_to_burp_tool(fake_llm, burp):
    # First LLM call returns internal update_files tool (not exposed to Burp)
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [
            make_tool_call("files-1", "update_files", {
                "operations": [
                    {"action": "append", "filename": "observations.md", "content": "\n- Noted behavior"},
                ],
            })
        ],
    })
    # Second LLM call returns Burp repeater tool
    fake_llm.enqueue_response(repeater_response("tool-2"))

    resp = await burp.explore_start(SAMPLE_ISSUE)
    status = await burp.poll_until_terminal(resp.json()["step_id"])

    assert status["state"] == "COMPLETE"
    assert len(fake_llm.received_requests) == 2
    assert status["response"]["tool_calls"][0]["tool_name"] == "repeater"


async def test_finish_returns_reporter_and_cleans_session(fake_llm, burp):
    # Start
    fake_llm.enqueue_response(repeater_response("tool-1"))
    resp = await burp.explore_start(SAMPLE_ISSUE)
    start_status = await burp.poll_until_terminal(resp.json()["step_id"])
    exploration_id = start_status["response"]["exploration_id"]
    tool_id = start_status["response"]["tool_calls"][0]["id"]

    # Continue
    fake_llm.enqueue_response(repeater_response("tool-2"))
    resp = await burp.explore_continue(
        exploration_id,
        [{"tool_id": tool_id, "result": "HTTP/1.1 200 OK\r\n\r\nOK"}],
    )
    continue_status = await burp.poll_until_terminal(resp.json()["step_id"])
    tool_id = continue_status["response"]["tool_calls"][0]["id"]

    # Finish
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [
            make_tool_call("reporter-1", "reporter", {
                "step_title": "Final report",
                "step_action": "Summarize findings",
                "report": "No vulnerabilities found.",
            })
        ],
    })
    resp = await burp.explore_finish(
        exploration_id,
        [{"tool_id": tool_id, "result": "HTTP/1.1 403 Forbidden\r\n\r\nDenied"}],
    )
    finish_status = await burp.poll_until_terminal(resp.json()["step_id"])
    assert finish_status["state"] == "COMPLETE"
    assert finish_status["response"]["tool_calls"][0]["tool_name"] == "reporter"

    # Session should be deleted — continue returns 400
    resp = await burp.explore_continue(exploration_id, [])
    assert resp.status_code == 400


async def test_error_state_and_retry(fake_llm, burp):
    # LLM returns unknown tool -> validation error -> ERROR state
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [
            make_tool_call("bad-1", "nonexistent_tool", {"foo": "bar"})
        ],
    })

    resp = await burp.explore_start(SAMPLE_ISSUE)
    status = await burp.poll_until_terminal(resp.json()["step_id"])
    assert status["state"] == "ERROR"
    step_id = status["step_id"]

    # Retry with valid response
    fake_llm.enqueue_response(repeater_response("tool-retry"))
    resp = await burp.explore_retry(step_id)
    assert resp.status_code == 202
    assert resp.json()["step_id"] == step_id

    retry_status = await burp.poll_until_terminal(step_id)
    assert retry_status["state"] == "COMPLETE"


async def test_network_error_on_connection_failure(fake_llm, burp):
    # Enqueue an HTTP error so the proxy's LLM call fails with APIStatusError
    fake_llm.enqueue_error(502, "Bad Gateway")

    resp = await burp.explore_start(SAMPLE_ISSUE)
    status = await burp.poll_until_terminal(resp.json()["step_id"])
    assert status["state"] == "NETWORK_ERROR"


async def test_unknown_session_returns_400(burp):
    resp = await burp.explore_continue("nonexistent-session-id", [])
    assert resp.status_code == 400


async def test_unknown_step_returns_404(burp):
    resp = await burp.explore_status("nonexistent-step-id")
    assert resp.status_code == 404


async def test_intruder_tool_call(fake_llm, burp):
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [
            make_tool_call("intruder-1", "intruder", {
                "step_title": "Fuzz parameter",
                "step_action": "Test SQL injection payloads",
                "request_template": "GET /search?q=§test§ HTTP/1.1\r\nHost: example.org\r\n\r\n",
                "payloads": ["' OR 1=1--", "\" OR 1=1--"],
                "auto_url_encode": True,
            })
        ],
    })

    resp = await burp.explore_start(SAMPLE_ISSUE)
    status = await burp.poll_until_terminal(resp.json()["step_id"])

    assert status["state"] == "COMPLETE"
    tool_call = status["response"]["tool_calls"][0]
    assert tool_call["tool_name"] == "intruder"
    assert "payloads" in tool_call["arguments"]


async def test_response_headers_present(fake_llm, burp):
    fake_llm.enqueue_response(repeater_response())

    resp = await burp.explore_start(SAMPLE_ISSUE)
    assert "Portswigger-Hakawai-Ai" in resp.headers

    step_id = resp.json()["step_id"]
    await burp.poll_until_terminal(step_id)

    status_resp = await burp.explore_status(step_id)
    assert "Portswigger-Hakawai-Ai" in status_resp.headers


async def test_context_compression_flow(fake_llm, burp):
    # Start with usage above 70% of token_limit (100000) to flag history for clearing
    fake_llm.enqueue_response(
        repeater_response("tool-1"),
        usage={"prompt_tokens": 80000, "completion_tokens": 100, "total_tokens": 80100},
    )
    resp = await burp.explore_start(SAMPLE_ISSUE)
    start_status = await burp.poll_until_terminal(resp.json()["step_id"])
    exploration_id = start_status["response"]["exploration_id"]
    tool_id = start_status["response"]["tool_calls"][0]["id"]

    # Continue: first LLM call gets only update_files, second gets normal tools after clear
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [make_tool_call("files-1", "update_files", {
            "operations": [{"action": "append", "filename": "findings.md", "content": "\nSaved context"}],
        })],
    })
    fake_llm.enqueue_response(repeater_response("tool-2"))

    resp = await burp.explore_continue(
        exploration_id,
        [{"tool_id": tool_id, "result": "HTTP/1.1 200 OK\r\n\r\nOK"}],
    )
    status = await burp.poll_until_terminal(resp.json()["step_id"])
    assert status["state"] == "COMPLETE"

    pre_clear_req = fake_llm.received_requests[1]
    assert [t["function"]["name"] for t in pre_clear_req["tools"]] == ["update_files"]
    assert any(
        m.get("role") == "user" and "CONTEXT WINDOW FULL" in (m.get("content") or "")
        for m in pre_clear_req["messages"]
    )

    # History cleared, so the next LLM call has fewer messages
    post_clear_req = fake_llm.received_requests[2]
    assert len(post_clear_req["messages"]) < len(pre_clear_req["messages"])


async def test_retry_exhaustion_returns_explore_failed(fake_llm, burp):
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [make_tool_call("bad-0", "nonexistent_tool", {})],
    })
    resp = await burp.explore_start(SAMPLE_ISSUE)
    status = await burp.poll_until_terminal(resp.json()["step_id"])
    assert status["state"] == "ERROR"
    original_step_id = status["step_id"]

    for i in range(5):
        fake_llm.enqueue_response({
            "content": "",
            "tool_calls": [make_tool_call(f"bad-{i+1}", "nonexistent_tool", {})],
        })
        retry_resp = await burp.explore_retry(original_step_id)
        await burp.poll_until_terminal(retry_resp.json()["step_id"])

    final = await burp.explore_status(original_step_id)
    assert final.json()["state"] == "EXPLORE_FAILED"


async def test_reporter_unlocks_when_all_tasks_completed(fake_llm, burp):
    # Start: add a task, then call repeater. Reporter must not be offered yet.
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [make_tool_call("tasks-1", "update_tasks", {
            "operations": [{"action": "add", "title": "Probe endpoint"}],
        })],
    })
    fake_llm.enqueue_response(repeater_response("tool-1"))

    resp = await burp.explore_start(SAMPLE_ISSUE)
    start_status = await burp.poll_until_terminal(resp.json()["step_id"])
    exploration_id = start_status["response"]["exploration_id"]
    tool_id = start_status["response"]["tool_calls"][0]["id"]

    start_tools = [t["function"]["name"] for t in fake_llm.received_requests[0]["tools"]]
    assert "reporter" not in start_tools

    # Continue: complete the task, reporter unlocks on the next iteration
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [make_tool_call("tasks-2", "update_tasks", {
            "operations": [{"action": "complete", "id": 0}],
        })],
    })
    fake_llm.enqueue_response({
        "content": "",
        "tool_calls": [make_tool_call("reporter-1", "reporter", {
            "step_title": "Final report",
            "step_action": "Summarize findings",
            "report": "Testing complete.",
        })],
    })

    resp = await burp.explore_continue(
        exploration_id,
        [{"tool_id": tool_id, "result": "HTTP/1.1 200 OK\r\n\r\nOK"}],
    )
    status = await burp.poll_until_terminal(resp.json()["step_id"])
    assert status["state"] == "COMPLETE"
    assert status["response"]["tool_calls"][0]["tool_name"] == "reporter"

    final_tools = [t["function"]["name"] for t in fake_llm.received_requests[-1]["tools"]]
    assert "reporter" in final_tools

    # Session should be deleted after reporter, so continue returns 400
    resp = await burp.explore_continue(exploration_id, [])
    assert resp.status_code == 400
