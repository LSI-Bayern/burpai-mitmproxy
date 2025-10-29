import json
import mitmproxy.http
from .prompt import Prompt, Role


class ExplainThisPrompt(Prompt):
    """Handles /ai/hakawai-explain-this/api/v1/explainthis requests."""

    explain_path = "/ai/hakawai-explain-this/api/v1/explainthis"

    async def handle_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        request_data = json.loads(flow.request.text or "{}")
        text_to_analyze = request_data.get("text", "")
        context = request_data.get("context")

        self._messages = [
            {"role": Role.SYSTEM, "content": self.get_system_prompt(context)},
            {"role": Role.USER, "content": text_to_analyze},
        ]
        llm_request = self.build_llm_request(self._messages)

        await self.proxy_request(flow, llm_request)

    async def handle_response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        data = json.loads(flow.response.text or "{}")
        content = data.get("message", {}).get("content", "")

        # Convert to format expected by Burp
        message = {"content": content}
        flow.response.text = json.dumps(message)

    def get_system_prompt(self, context: str) -> str:
        """Build context-aware system prompt."""
        context_descriptions = {
            "RESPONSE": "The user selected text from the HTTP response.",
            "REQUEST_LINE": "The user selected text from the HTTP request line.",
            "REQUEST_BODY": "The user selected text from the HTTP request body.",
            "REQUEST_HEADERS": "The user selected text from the HTTP request headers.",
            "REQUEST": "The user selected text from the HTTP request.",
            "RESPONSE_STATUS_LINE": "The user selected text from the HTTP response status line.",
            "RESPONSE_BODY": "The user selected text from the HTTP response body.",
            "RESPONSE_HEADERS": "The user selected text from the HTTP response headers.",
        }

        if context not in context_descriptions:
            raise ValueError(f"Unknown context: {context}")

        context_info = context_descriptions[context]

        return (
            f"You are an expert security researcher analyzing HTTP traffic. {context_info} "
            "Provide a short explanation of the given text, briefly summarizing any potential "
            "security implications from an attacker perspective. "
            "Do not include mitigation recommendations or other descriptions. "
            "Minimize the use of newlines."
        )
