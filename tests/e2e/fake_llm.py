import asyncio
import time
import uuid
from collections import deque

from aiohttp import web


class FakeLLMServer:
    """Fake OpenAI-compatible LLM server for E2E testing."""

    def __init__(self, port, model_name="test-model"):
        self.port = port
        self.model_name = model_name
        self._queue = deque()
        self.received_requests = []
        self._runner = None

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}/v1"

    def enqueue_response(self, message, usage=None):
        """Enqueue a canned response.

        message: str (content only) or dict (full message with optional tool_calls).
        usage: optional dict with prompt_tokens, completion_tokens, total_tokens.
        """
        self._queue.append(("ok", message, usage))

    def enqueue_error(self, status, message):
        """Make the next request return an HTTP error."""
        self._queue.append(("error", status, message))

    def enqueue_delayed_response(self, delay, message, usage=None):
        """Enqueue a response with artificial delay before returning."""
        self._queue.append(("delayed", delay, message, usage))

    async def _handle_completions(self, request):
        body = await request.json()
        self.received_requests.append(body)

        if not self._queue:
            return web.json_response(
                {"error": {"message": "No responses enqueued in fake LLM", "type": "server_error"}},
                status=500,
            )

        item = self._queue.popleft()
        kind = item[0]

        if kind == "error":
            _, status, msg = item
            return web.json_response(
                {"error": {"message": msg, "type": "server_error"}},
                status=status,
            )

        if kind == "delayed":
            _, delay, message, usage = item
            await asyncio.sleep(delay)
        else:
            _, message, usage = item

        # Normalize message to dict
        if isinstance(message, str):
            msg_dict = {"content": message}
        else:
            msg_dict = dict(message)

        if usage is None:
            usage = {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}

        tool_calls = msg_dict.pop("tool_calls", None)
        msg_dict.pop("role", None)
        content = msg_dict.get("content")

        choice_message = {"role": "assistant", "content": content}
        if tool_calls:
            choice_message["tool_calls"] = tool_calls

        return web.json_response({
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": self.model_name,
            "choices": [{
                "index": 0,
                "message": choice_message,
                "finish_reason": "tool_calls" if tool_calls else "stop",
            }],
            "usage": usage,
        })

    async def _handle_models(self, request):
        return web.json_response({
            "object": "list",
            "data": [{
                "id": self.model_name,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "test",
            }],
        })

    async def start(self):
        app = web.Application()
        app.router.add_post("/v1/chat/completions", self._handle_completions)
        app.router.add_get("/v1/models", self._handle_models)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await site.start()

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
