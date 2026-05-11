import asyncio
import ssl

import httpx


class BurpClient:
    """HTTP client that sends requests through the proxy, mimicking Burp Suite."""

    HOST = "https://ai.portswigger.net"

    def __init__(self, proxy_url, ca_cert):
        ctx = ssl.create_default_context(cafile=str(ca_cert))
        self._client = httpx.AsyncClient(
            proxy=proxy_url, verify=ctx, timeout=30.0
        )

    async def get_balance(self):
        return await self._client.get(f"{self.HOST}/burp/balance")

    async def explain(self, text, context):
        return await self._client.post(
            f"{self.HOST}/ai/hakawai-explain-this/api/v1/explainthis",
            json={"text": text, "context": context},
        )

    async def montoya(self, messages, temperature=None):
        payload = {"messages": messages}
        if temperature is not None:
            payload["config"] = {"temperature": temperature}
        return await self._client.post(
            f"{self.HOST}/ai/hakawai-montoya-service/api/v1/prompt",
            json=payload,
        )

    async def explore_start(self, issue_definition):
        return await self._client.post(
            f"{self.HOST}/ai/hakawai-explore-service/api/v1/async/start",
            json={"issue_definition": issue_definition},
        )

    async def explore_status(self, step_id):
        return await self._client.get(
            f"{self.HOST}/ai/hakawai-explore-service/api/v1/async/status/{step_id}",
        )

    async def explore_continue(self, exploration_id, tool_results):
        return await self._client.post(
            f"{self.HOST}/ai/hakawai-explore-service/api/v1/async/continue",
            json={"exploration_id": exploration_id, "tool_results": tool_results},
        )

    async def explore_finish(self, exploration_id, tool_results):
        return await self._client.post(
            f"{self.HOST}/ai/hakawai-explore-service/api/v1/async/finish",
            json={"exploration_id": exploration_id, "tool_results": tool_results},
        )

    async def explore_retry(self, step_id):
        return await self._client.post(
            f"{self.HOST}/ai/hakawai-explore-service/api/v1/async/status/{step_id}/retry",
        )

    async def poll_until_terminal(self, step_id, timeout=10.0, interval=0.1):
        """Poll explore status until a terminal state is reached."""
        deadline = asyncio.get_event_loop().time() + timeout
        data = None
        while asyncio.get_event_loop().time() < deadline:
            resp = await self.explore_status(step_id)
            data = resp.json()
            if data.get("state") not in ("PENDING", "PROCESSING"):
                return data
            await asyncio.sleep(interval)
        raise TimeoutError(
            f"Step {step_id} did not reach terminal state within {timeout}s; last: {data}"
        )

    async def close(self):
        await self._client.aclose()
