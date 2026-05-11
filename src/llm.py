import json
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from jsonschema import Draft202012Validator
from openai import AsyncOpenAI, APITimeoutError, APIConnectionError, APIStatusError
from rich.color import Color as RichColor
from rich.highlighter import NullHighlighter
from .utils import logger


@dataclass
class LLM:
    """Wrapper around openai-python with a custom httpx client."""

    base_url: str
    api_key: str
    default_model: str
    token_limit: int
    default_temperature: float = 1.0
    proxy: str | None = None
    proxy_username: str | None = None
    proxy_password: str | None = None

    def __post_init__(self):
        # Optional upstream proxy, might be necessary for corporate environments
        proxy_url = None
        if self.proxy:
            if self.proxy_username and self.proxy_password:
                parsed = urlparse(self.proxy)
                parsed = parsed._replace(netloc=f"{self.proxy_username}:{self.proxy_password}@{parsed.netloc}")
                proxy_url = parsed.geturl()
            else:
                proxy_url = self.proxy

        # The OpenAI library is unable to set those values directly,
        # so we must create our own httpx client
        client_kwargs = {"verify": self._find_ssl_cert()}
        if proxy_url:
            client_kwargs["proxy"] = proxy_url
        http_client = httpx.AsyncClient(**client_kwargs)

        # For some reason, Anthropic requires certain headers on their "openai-compatible" backend
        default_headers = {}
        if self.base_url.rstrip("/") == "https://api.anthropic.com/v1":
            default_headers["x-api-key"] = self.api_key
            default_headers["anthropic-version"] = "2023-06-01"

        self._client = AsyncOpenAI(
            base_url=self.base_url,
            api_key=self.api_key or "sk-dummy",  # openai-python requires an API key, regardless of the backend used
            http_client=http_client,
            timeout=180.0,
            default_headers=default_headers,
        )

    async def check_llm_setup(self) -> bool:
        """Check LLM connectivity and model availability."""
        logger.info("Checking LLM setup...")

        try:
            models = await self._client.models.list()
        except (APITimeoutError, APIStatusError, APIConnectionError) as e:
            logger.error("LLM API error: [yellow]%s[/yellow]", self._format_error(e))
            return False

        available_models = [model.id for model in models.data]
        if self.default_model not in available_models:
            logger.error(
                "Model '%s' not found in available models: %s", self.default_model, ", ".join(available_models)
            )
            return False
        logger.info("Model [cyan]%s[/cyan] is available at %s", self.default_model, self.base_url)
        return True

    async def request(
        self, payload: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Send chat completion request and return message object and usage info."""
        if not self.base_url:
            raise ValueError("Base URL is not configured")

        if "model" not in payload and self.default_model:
            payload["model"] = self.default_model

        if "temperature" not in payload and self.default_temperature is not None:
            payload["temperature"] = self.default_temperature

        if "max_completion_tokens" not in payload and self.token_limit:
            payload["max_completion_tokens"] = self.token_limit

        tools = payload.get("tools", [])

        if tools and "parallel_tool_calls" not in payload:
            payload["parallel_tool_calls"] = True

        if tools and "tool_choice" not in payload:
            payload["tool_choice"] = "required"

        message_obj, usage_info = await self._make_llm_request(payload)
        if tools:
            self._validate_single_tool_response(message_obj, tools)
        return message_obj, usage_info

    def _format_error(self, error: Exception) -> str:
        """Format error message, optionally with truncation."""
        if isinstance(error, APIStatusError):
            error_msg = getattr(error.response, "text", "No response body available")
        else:
            error_msg = str(error)

        return error_msg

    def _build_jsonpath(self, path_elements) -> str:
        """Convert path elements to JSONPath notation. That should be easier to read for LLMs."""
        if not path_elements:
            return "$"

        path = "$"
        for p in path_elements:
            if isinstance(p, int):
                path += f"[{p}]"
            else:
                escaped = str(p).replace("'", "\\'")
                path += f"['{escaped}']"
        return path

    def _validate_tool_calls(
        self, tool_calls: list[dict[str, Any]] | None, tool_schemas: list[dict[str, Any]]
    ) -> list[str]:
        errors = []

        # Some providers like Ollama don't support tool_choice="required", so we enforce it here
        if not tool_calls:
            errors.append("No tools called. You must select and call at least one tool to proceed.")
            return errors

        tool_schema_map = {}
        for tool in tool_schemas:
            func = tool.get("function", {})
            if func.get("name"):
                tool_schema_map[func["name"]] = func.get("parameters", {})

        for tool_call in tool_calls:
            function_data = tool_call.get("function", {})
            tool_name = function_data.get("name", "unknown")
            arguments_json = function_data.get("arguments", "{}")

            # Check if the tool is available
            if tool_name not in tool_schema_map:
                errors.append(f"Unknown tool '{tool_name}'")
                continue

            # Check if the JSON is invalid
            try:
                arguments = json.loads(arguments_json)
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON for '{tool_name}': {e.msg}")
                continue

            # Check if the schema was not respected
            validator = Draft202012Validator(tool_schema_map[tool_name])
            validation_errors = list(validator.iter_errors(arguments))
            for e in validation_errors:
                json_path = self._build_jsonpath(e.path)
                errors.append(f"Invalid tool call for '{tool_name}' at '{json_path}': {e.message}")

        return errors

    def _validate_single_tool_response(self, message_obj: dict[str, Any], tools: list[dict[str, Any]]) -> None:
        tool_calls = message_obj.get("tool_calls")
        validation_errors = self._validate_tool_calls(tool_calls, tools)
        if validation_errors:
            raise ValueError("\n".join(f"- {e}" for e in validation_errors))

    async def _make_llm_request(self, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Make a single LLM request and return message object and usage info."""
        messages = payload.get("messages", [])
        message_count = len(messages)
        if message_count > 0:
            logger.info("Sending LLM request to %s with %s messages", self.base_url, message_count)

        response = await self._client.chat.completions.create(stream=False, **payload)

        message = response.choices[0].message

        message_obj: dict[str, Any] = {
            "role": "assistant",
            "content": message.content,
        }

        if message.tool_calls:
            message_obj["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in message.tool_calls
            ]

        usage_info = None
        if response.usage:
            usage_info = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }

        self._log_context_usage(usage_info)
        return message_obj, usage_info

    def _find_ssl_cert(self) -> ssl.SSLContext | bool:
        """Find SSL certificate bundle, might be necessary for corporate environments."""
        cert_locations = [
            Path("/etc/ssl/certs/ca-certificates.crt"),
            Path("/etc/pki/tls/certs/ca-bundle.crt"),
            Path("/etc/ssl/ca-bundle.pem"),
            Path("/etc/ssl/cert.pem"),
        ]
        for cert in cert_locations:
            if cert.exists():
                return ssl.create_default_context(cafile=str(cert))
        return True

    def _log_context_usage(self, usage_info: dict[str, Any]) -> None:
        """Log context usage with color gradient. Mostly relevant for sessions."""
        if not usage_info or not self.token_limit:
            return

        total_tokens = usage_info.get("total_tokens", 0)
        if total_tokens == 0:
            return

        percentage = (total_tokens / self.token_limit) * 100

        if percentage >= 100:  # noqa: PLR2004
            r, g = 255, 0
        else:
            r = min(255, int(510 * percentage / 100))  # noqa: PLR2004
            g = min(255, int(510 * (100 - percentage) / 100))  # noqa: PLR2004

        rgb_color = RichColor.from_rgb(r, g, 0)

        logger.info(
            "LLM response complete - Context: [%s]%d%%[/%s]",
            rgb_color.name,
            int(percentage),
            rgb_color.name,
            extra={"highlighter": NullHighlighter()},
        )
