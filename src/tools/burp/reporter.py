from __future__ import annotations

from typing import Any

from src.tools.tool import Tool


class ReporterTool(Tool):
    """Tool for reporting findings through Burp Suite."""

    def process(
        self,
        tool_call: dict[str, Any],
        _session=None,
        _session_id: str = "",
    ) -> dict[str, Any]:
        """Process a tool call and return the format expected by Burp. The tool call must conform to the schema."""
        return {
            "tool_name": "reporter",
            "step_title": tool_call["step_title"],
            "step_action": tool_call["step_action"],
            "arguments": {"report": tool_call["report"]},
        }

    def get_schema(self, _session=None) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "reporter",
                "description": self._get_documentation(),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "step_title": {"type": "string"},
                        "step_action": {"type": "string"},
                        "report": {"type": "string"},
                    },
                    "required": ["step_title", "step_action", "report"],
                    "additionalProperties": False,
                },
            },
        }

    def _get_documentation(self) -> str:
        return """Report your findings and give the user guidance on how to continue the penetration test. You must admit this in case we didn't yield any interesting results.

**Parameters**:
- `step_title`: Brief title for the final report (displayed in Burp UI)
- `step_action`: Detailed explanation of your findings (displayed in Burp UI)
- `report`: String containing your summary

**Example**:

```json
{
  "step_title": "Testing Complete - Findings Report",
  "step_action": "Completed all testing tasks. Summarizing key findings and recommendations.",
  "report": "We identified a reflected XSS vulnerability in the search parameter that allows arbitrary JavaScript execution. The application does not properly encode user input before reflecting it in the HTML response. We recommend implementing proper output encoding and Content Security Policy headers."
}
```"""  # noqa: E501
