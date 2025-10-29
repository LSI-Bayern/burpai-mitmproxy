import json
import mitmproxy.http
from .prompt import Prompt, Role, Message

MIN_TEMPERATURE = 0.0
MAX_TEMPERATURE = 2.0


class MontoyaPrompt(Prompt):
    """Handles /ai/hakawai-montoya-service/api/v1/prompt requests."""

    montoya_path = "/ai/hakawai-montoya-service/api/v1/prompt"

    async def handle_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        payload = flow.request.text or "{}"
        j = json.loads(payload)

        self._messages: list[Message] = []
        for m in j.get("messages", []):
            if m.get("type", "").lower() == "system":
                self._messages.append({"role": Role.SYSTEM, "content": m.get("text", "")})
            elif m.get("type", "").lower() == "user":
                self._messages.append({"role": Role.USER, "content": m.get("text", "")})

        self._temperature = 1.0
        if "config" in j:
            config = j["config"]
            if "temperature" in config:
                try:
                    temp = float(config["temperature"])
                    if MIN_TEMPERATURE <= temp <= MAX_TEMPERATURE:
                        self._temperature = temp
                except ValueError:
                    pass

        llm_request = self.build_llm_request(self._messages, temperature=self._temperature)
        await self.proxy_request(flow, llm_request)

    async def handle_response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if flow.response is None:
            return

        data = json.loads(flow.response.text or "{}")
        content = data.get("message", {}).get("content", "")

        # Convert to format expected by Burp
        message = {"content": content}
        flow.response.text = json.dumps(message)
