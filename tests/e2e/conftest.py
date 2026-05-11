import json
import os
import socket

import pytest

from .fake_llm import FakeLLMServer
from .proxy_harness import ProxyHarness
from .burp_client import BurpClient


@pytest.fixture(autouse=True)
def _bypass_proxy_for_localhost(monkeypatch):
    """Ensure HTTP clients connect directly to localhost, bypassing corporate proxies."""
    current = os.environ.get("no_proxy", os.environ.get("NO_PROXY", ""))
    if "127.0.0.1" not in current:
        new_val = f"{current},127.0.0.1,localhost" if current else "127.0.0.1,localhost"
        monkeypatch.setenv("no_proxy", new_val)
        monkeypatch.setenv("NO_PROXY", new_val)


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_tool_call(tool_id, tool_name, arguments):
    """Build an OpenAI-format tool call dict."""
    return {
        "id": tool_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(arguments),
        },
    }


@pytest.fixture
async def fake_llm():
    port = _get_free_port()
    server = FakeLLMServer(port=port, model_name="test-model")
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
async def proxy(fake_llm, tmp_path):
    port = _get_free_port()
    harness = ProxyHarness(
        proxy_port=port,
        llm_url=fake_llm.base_url,
        config_dir=tmp_path / "mitmproxy",
    )
    await harness.start()
    yield harness
    await harness.stop()


@pytest.fixture
async def burp(proxy, tmp_path):
    ca_cert = tmp_path / "mitmproxy" / "mitmproxy-ca-cert.pem"
    client = BurpClient(
        proxy_url=f"http://127.0.0.1:{proxy.port}", ca_cert=ca_cert
    )
    yield client
    await client.close()
