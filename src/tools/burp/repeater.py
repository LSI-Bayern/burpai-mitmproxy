from typing import Any

from src.tools.tool import Tool


class RepeaterTool(Tool):
    """Tool for sending single HTTP requests through Burp Suite Repeater."""

    def process(
        self,
        tool_call: dict[str, Any],
        _session=None,
        _session_id="",
    ) -> dict[str, Any]:
        """Process a tool call and return the format expected by Burp. The tool call must conform to the schema."""
        return {
            "tool_name": "repeater",
            "step_title": tool_call["step_title"],
            "step_action": tool_call["step_action"],
            "arguments": {"request": tool_call["request"]},
        }

    def get_schema(self, _session=None) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "repeater",
                "description": self._get_documentation(),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "step_title": {"type": "string"},
                        "step_action": {"type": "string"},
                        "request": {"type": "string"},
                    },
                    "required": ["step_title", "step_action", "request"],
                    "additionalProperties": False,
                },
            },
        }

    def format_result(self, result_data: str) -> str:
        formatted = ""

        if result_data.endswith("<truncated tool result>"):
            content_length = None
            for line in result_data.split("\n"):
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                        break
                    except (ValueError, IndexError):
                        pass

            truncation_marker_pos = result_data.find("<truncated tool result>")
            total_bytes_shown = truncation_marker_pos

            separator = "\r\n\r\n" if "\r\n\r\n" in result_data else "\n\n"
            body_start = result_data.find(separator)
            truncation_in_body = body_start != -1 and total_bytes_shown > (body_start + len(separator))

            if truncation_in_body and content_length is not None:
                body_bytes_shown = total_bytes_shown - (body_start + len(separator))
                body_bytes_missing = content_length - body_bytes_shown
                formatted += (
                    f"NOTE: Showing first {total_bytes_shown:,} bytes "
                    f"(body: {body_bytes_shown:,}/{content_length:,} bytes, "
                    f"{body_bytes_missing:,} bytes likely truncated from body based on Content-Length header).\n\n"
                )
            else:
                formatted += f"NOTE: Showing first {total_bytes_shown:,} bytes (response truncated).\n\n"

        if result_data.startswith("HTTP/"):
            formatted += "```http\n"
        else:
            formatted += "```\n"

        for line in result_data.split("\n"):
            if line.endswith("<truncated tool result>"):
                formatted += line[: -len("<truncated tool result>")] + "\n"
            else:
                formatted += line + "\n"
        formatted += "```\n"

        return formatted

    def _get_documentation(self) -> str:
        return """The repeater sends a single HTTP request and returns the HTTP response.

**ENCODING**: The HTTP request is sent exactly as you provide it. No automatic encoding happens.

**IMPORTANT LIMITATIONS**:
- Burp Suite will reject any identical request previously sent. If you really need to resend the same request (e.g., retrieving a new CSRF token), make it unique by adding a parameter like `?123` or a custom header.
- Large responses (>10KB) are automatically truncated by Burp Suite. When truncated, you'll receive a note indicating how much was truncated. It's not always possible, but to retrieve the missing content, you can try using the `Range` header, e.g., `Range: bytes=10000-` if the server supports it, or use API-specific pagination parameters like `offset`/`limit` if available.

**Parameters**:
- `step_title`: Brief title for this testing step (displayed in Burp UI)
- `step_action`: Detailed explanation of what you're doing and why (displayed in Burp UI)
- `request`: Complete HTTP request as a single string. Separate lines with CRLF (`\r\n`). You may deviate from this if you are testing non-standard behavior.

**Examples**:

**Basic GET Request**:
```json
{
  "step_title": "Testing search parameter",
  "step_action": "Sending a request with a test value in the q parameter to observe the response",
  "request": "GET /search?q=test+abc HTTP/1.1\r\nHost: example.org\r\n\r\n"
}
```

**POST with Form Data**:
```json
{
  "step_title": "Testing login form",
  "step_action": "Submitting credentials to the login endpoint to analyze the response",
  "request": "POST /login HTTP/1.1\r\nHost: example.org\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=admin&password=123"
}
```

**Retrieving Truncated Content**:
```json
{
  "step_title": "Fetching remaining response data",
  "step_action": "Using Range header to retrieve the truncated portion of the previous response",
  "request": "GET /large-page HTTP/1.1\r\nHost: example.org\r\nRange: bytes=10000-\r\n\r\n"
}
```"""  # noqa: E501
