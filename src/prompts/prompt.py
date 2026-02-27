import abc
import enum
import http
import json
from typing import Any, TypedDict

import mitmproxy.http
from openai import APIError

from src.utils import logger


class Role(enum.StrEnum):
    SYSTEM = "system"
    USER = "user"


class Message(TypedDict):
    role: Role
    content: str


class Prompt(abc.ABC):
    """Base class for all prompts."""

    def __init__(self, proxy_instance):
        self.proxy = proxy_instance

    def build_llm_request(
        self,
        messages: list,
        model: str | None = None,
        temperature: float | None = None,
        tools: list[dict] | None = None,
        tool_choice: str | dict | None = None,
    ) -> dict[str, Any]:
        llm_request: dict[str, Any] = {
            "messages": messages,
        }

        if model is not None:
            llm_request["model"] = model

        if temperature is not None:
            llm_request["temperature"] = temperature

        if tools is not None:
            llm_request["tools"] = tools

        if tool_choice is not None:
            llm_request["tool_choice"] = tool_choice

        return llm_request

    async def proxy_request(
        self,
        flow: mitmproxy.http.HTTPFlow,
        llm_request: dict,
    ) -> None:
        """Send request to LLM and set flow.response with result or error."""
        try:
            message_obj, eval_info = await self.proxy._llm.request(llm_request)

            payload = {
                "message": message_obj,
                "eval_info": eval_info,
            }

            response_json = json.dumps(payload)
            flow.response = mitmproxy.http.Response.make(
                http.HTTPStatus.OK,
                response_json,
                {"Content-Type": "application/json"},
            )

        except (APIError, ValueError) as e:
            if flow.response is None:
                flow.response = mitmproxy.http.Response.make(
                    http.HTTPStatus.BAD_GATEWAY,
                    json.dumps({"error": str(e)}),
                    {"Content-Type": "application/json"},
                )
                logger.error("Request failed - returning error: %s", str(e))

    @abc.abstractmethod
    async def handle_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def handle_response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        raise NotImplementedError

    def process_response_json(self, response_json: dict[str, Any], flow: mitmproxy.http.HTTPFlow) -> dict[str, Any]:  # noqa: ARG002
        return response_json
