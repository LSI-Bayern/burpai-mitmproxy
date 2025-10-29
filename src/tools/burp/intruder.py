import csv
import io
import urllib.parse
from typing import Any

from src.tools.tool import Tool
from src.utils import logger


class IntruderTool(Tool):
    """Tool for fuzzing HTTP requests through Burp Suite Intruder."""

    def process(
        self,
        tool_call: dict[str, Any],
        _session=None,
        _session_id="",
    ) -> dict[str, Any]:
        """Process a tool call and return the format expected by Burp. The tool call must conform to the schema."""
        arguments = {"request": tool_call["request_template"]}

        payloads: list[str] = []
        for entry in tool_call["payloads"]:
            if tool_call["auto_url_encode"]:
                payloads.append(self._url_encode_chars(str(entry)))
            else:
                payloads.append(str(entry))

        arguments["payloads"] = payloads

        return {
            "tool_name": "intruder",
            "step_title": tool_call["step_title"],
            "step_action": tool_call["step_action"],
            "arguments": arguments,
        }

    def get_schema(self, _session=None) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "intruder",
                "description": self._get_documentation(),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "step_title": {"type": "string"},
                        "step_action": {"type": "string"},
                        "request_template": {"type": "string"},
                        "auto_url_encode": {
                            "type": "boolean",
                        },
                        "payloads": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": [
                        "step_title",
                        "step_action",
                        "request_template",
                        "payloads",
                        "auto_url_encode",
                    ],
                    "additionalProperties": False,
                },
            },
        }

    def format_result(self, result_data: str) -> str:
        formatted = ""

        reader = csv.DictReader(io.StringIO(result_data))
        request_offset = 0

        # Validate expected structure
        # If there are breaking changes, simply return the raw data
        required_columns = {"payloads", "status code", "content length", "content type", "truncated body"}
        issues = []
        return_raw_data = False

        if reader.fieldnames is None:
            issues.append("CSV data has no header row")
            return_raw_data = True
        else:
            actual_columns = set(reader.fieldnames)
            missing_columns = required_columns - actual_columns

            if missing_columns:
                issues.append(f"Missing required columns {missing_columns}")
                return_raw_data = True

            extra_columns = actual_columns - required_columns
            if extra_columns:
                issues.append(f"Unexpected additional columns {extra_columns}")

        if issues:
            logger.warning(f"Intruder output format changed: {'; '.join(issues)}")
            if return_raw_data:
                return result_data

        # Beautify output format for LLM
        for row in reader:
            payloads = row["payloads"]
            payload_count = len(payloads.split(",")) if payloads else 1

            if payload_count > 1:
                formatted += f"**Requests {request_offset}-{request_offset + payload_count - 1}:**\n"
            else:
                formatted += f"**Request {request_offset}:**\n"

            request_offset += payload_count

            formatted += f"Payloads: {payloads}\n"
            formatted += f"Status: {row['status code']}\n"
            formatted += f"Content-Length: {row['content length']}\n"
            formatted += f"Content-Type: {row['content type']}\n"

            try:
                content_length = int(row["content length"])
                actual_length = len(row["truncated body"])
                if content_length > 0 and actual_length < content_length:
                    formatted += f"Response: Truncated ({actual_length}/{content_length} bytes captured)\n"
                else:
                    formatted += "Response: Complete\n"
            except ValueError:
                pass

            formatted += "Body:\n```\n"
            formatted += row["truncated body"]
            formatted += "\n```\n\n"

        return formatted

    def _get_documentation(self) -> str:
        return """The intruder sends many HTTP requests by inserting different payloads into a template. Afterwards, it returns a summary with status codes, content lengths, and truncated response bodies. Mark insertion points with §placeholder§ in your template. Great for testing lots of variations quickly - the more payloads, the better.

**ENCODING**: Set `auto_url_encode` to control payload encoding behavior.
- `request_template`: YOU MUST encode the template yourself (except `§payload§` markers)
- `payloads`: Provide raw payloads when `auto_url_encode: true`
- For JSON contexts, set `auto_url_encode: false` and manually escape payloads

**IMPORTANT**: The Intruder tool only returns the first 200 bytes of each response BODY. This truncation is fixed and cannot be changed.
- Status codes, `content-length` and `content-type` are always fully captured
- Only the response body is truncated to 200 bytes
- If you need to check for reflected payloads or content that appears later in the response body, DO NOT use Intruder - use Repeater instead

**Parameters**:
- `step_title`: Brief title for this testing step
- `step_action`: Detailed explanation of what you're doing and why
- `request_template`: HTTP request template as a single string with a `§payload§` marker for fuzzing. Only ONE marker is supported. Separate lines with CRLF (`\r\n`), but you may deviate from this if you are testing non-standard behavior.
- `payloads`: Array of string payloads to insert at the `§payload§` marker.
- `auto_url_encode`: Boolean to enable/disable automatic URL-encoding. When `true`, special characters like spaces, slashes, brackets, and quotes are automatically encoded (specifically: `` ./\\=<>?+&*;:"{}|^`# ``). When `false`, payloads are sent as-is.

**Examples**:

**Directory Fuzzing**:
```json
{
  "step_title": "Discovering hidden API endpoints",
  "step_action": "Fuzzing /api/ path with common endpoint names to find accessible resources",
  "request_template": "GET /api/§payload§ HTTP/1.1\r\nHost: example.org\r\n\r\n",
  "payloads": ["users/list", "admin config", "../etc/passwd"],
  "auto_url_encode": true
}
```

**XSS/SQL Injection Testing**:
```json
{
  "step_title": "Testing search parameter for XSS and SQLi",
  "step_action": "Sending various XSS and SQL injection payloads to identify if the parameter is vulnerable",
  "request_template": "GET /search?q=§payload§ HTTP/1.1\r\nHost: example.org\r\n\r\n",
  "payloads": ["<script>console.log(1)</script>", "test' OR '1'='1--"],
  "auto_url_encode": true
}
```

**JSON Context (Manual Encoding)**:
```json
{
  "step_title": "Testing JSON user parameter",
  "step_action": "Testing for injection in JSON context with auto-encoding disabled",
  "request_template": "POST /api HTTP/1.1\r\nHost: example.org\r\nContent-Type: application/json\r\n\r\n{\"user\":\"§payload§\"}",
  "payloads": ["admin", "test\";}//", "' OR '1'='1"],
  "auto_url_encode": false
}
```"""  # noqa: E501

    def _url_encode_chars(self, text: str) -> str:
        chars_to_encode = ' ./\\=<>?+&*;:"{}|^`#'
        result = text
        for char in chars_to_encode:
            encoded = urllib.parse.quote(char, safe="")
            result = result.replace(char, encoded)
        return result
