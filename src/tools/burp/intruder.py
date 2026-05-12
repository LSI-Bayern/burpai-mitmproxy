import csv
import io
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
        return {
            "tool_name": "intruder",
            "step_title": tool_call["step_title"],
            "step_action": tool_call["step_action"],
            "arguments": {
                "request": tool_call["request_template"],
                "payloads": [str(p) for p in tool_call["payloads"]],
            },
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

**ENCODING**: Both `request_template` and `payloads` are sent verbatim. The proxy does NOT auto-encode anything, so you're responsible for encoding correctly for the context the payload lands in:
- URL/form parameters and path segments -> URL-encode special characters yourself (`<script>` -> `%3Cscript%3E`, space -> `%20`)
- A trailing slash in a path payload? Write `dashboard/` and it goes through as a path separator. Write `dashboard%2F` and it goes through as a literal `%2F`. Pick deliberately.
- JSON bodies -> JSON-escape values yourself (`a"b\\` -> `a\\"b\\\\`)
- If you want a literal `&`, `=`, `?`, or other structural character inside a query-string value, you must encode it (`%26`, `%3D`, `%3F`) or it will break out of the parameter

**IMPORTANT**: The Intruder tool only returns the first 200 bytes of each response BODY. This truncation is fixed and cannot be changed.
- Status codes, `content-length` and `content-type` are always fully captured
- Only the response body is truncated to 200 bytes
- If you need to check for reflected payloads or content that appears later in the response body, DO NOT use Intruder - use Repeater instead

**Parameters**:
- `step_title`: Brief title for this testing step
- `step_action`: Detailed explanation of what you're doing and why
- `request_template`: HTTP request template as a single string with a `§payload§` marker for fuzzing. Only ONE marker is supported. Separate lines with CRLF (`\r\n`), but you may deviate from this if you are testing non-standard behavior.
- `payloads`: Array of string payloads to insert at the `§payload§` marker. Sent exactly as written.

**Examples**:

**Directory Fuzzing** (path segment, no encoding needed for simple names):
```json
{
  "step_title": "Discovering hidden API endpoints",
  "step_action": "Fuzzing /api/ path with common endpoint names to find accessible resources",
  "request_template": "GET /api/§payload§ HTTP/1.1\r\nHost: example.org\r\n\r\n",
  "payloads": ["users", "users/list", "admin%20config", "..%2F..%2Fetc%2Fpasswd"]
}
```

**XSS/SQL Injection Testing** (query parameter, encode special chars):
```json
{
  "step_title": "Testing search parameter for XSS and SQLi",
  "step_action": "Sending various XSS and SQL injection payloads to identify if the parameter is vulnerable",
  "request_template": "GET /search?q=§payload§ HTTP/1.1\r\nHost: example.org\r\n\r\n",
  "payloads": ["%3Cscript%3Econsole.log(1)%3C%2Fscript%3E", "test%27%20OR%20%271%27%3D%271--"]
}
```

**JSON Context** (escape quotes/backslashes, no URL-encoding):
```json
{
  "step_title": "Testing JSON user parameter",
  "step_action": "Testing for injection in JSON context",
  "request_template": "POST /api HTTP/1.1\r\nHost: example.org\r\nContent-Type: application/json\r\n\r\n{\"user\":\"§payload§\"}",
  "payloads": ["admin", "test\\\";}//", "' OR '1'='1"]
}
```"""  # noqa: E501
