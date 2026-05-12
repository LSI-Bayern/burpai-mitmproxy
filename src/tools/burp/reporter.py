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

**WHEN TO USE**: Only call this tool when you have fully addressed the user's instruction. Calling it terminates the exploration session. There are no more chances to test, document, or refine after this.

**Parameters**:
- `step_title`: Brief title for the final report (displayed in Burp UI)
- `step_action`: Detailed explanation of your findings (displayed in Burp UI)
- `report`: Plain-text summary (see writing guidance below)

**How to write `report`**:
- Open with one or two sentences that directly answer the user's instruction. Don't bury the conclusion under an introductory header.
- Then justify the answer with the evidence you actually gathered: relevant requests, responses, status codes, observed behavior. Keep it concrete.
- If there are next steps or follow-up testing worth doing, add them. If not, don't pad.
- If anything is uncertain or untested, name it honestly.

**How to format `report`**:
Burp renders the report as plain text. There is no markdown parser, so `**bold**`, `# headings`, and `[links](...)` would just appear as literal characters and add noise. Don't use them. A few markdown-style conventions ARE still worth using even as literal characters, because the characters themselves visually separate code-like tokens from prose and help the reader scan:
- Inline backticks around code-like tokens: parameter names (`` `q` ``), header names (`` `Content-Type` ``), short payloads (`` `<svg onload=...>` ``), file paths (`` `/etc/passwd` ``), status codes, short response snippets
- Triple-backtick fenced blocks around multi-line snippets like a full HTTP request/response or a longer payload
- Blank lines between sections for visual separation
- Short ALL-CAPS labels when sections are warranted (e.g. `EVIDENCE`, `RECOMMENDATIONS`)
- Plain `- ` bullets or numbered lists; two-space indentation for nested detail

Structure follows content, not the reverse. A simple question deserves a short paragraph with no headers. A complex finding with evidence, recommendations, and caveats warrants sections. Pick labels that fit the question you're answering. Don't force a fixed template.

**Examples**:

A short, direct answer for a simple question:

```json
{
  "step_title": "Homepage summary",
  "step_action": "Summarizing the homepage content per user request.",
  "report": "The homepage at `https://example.org` is the marketing landing page for ExampleCorp's analytics product. It loads ~44 KB of static HTML served by Apache, references Matomo for analytics, and links to `/pricing`, `/docs`, and `/signup`. No login or authenticated area is exposed from the homepage itself."
}
```

A structured finding for a confirmed vulnerability:

```json
{
  "step_title": "Reflected XSS in search parameter",
  "step_action": "Confirmed reflected XSS in /search and reporting recommended fixes.",
  "report": "Reflected XSS confirmed in the `q` query parameter on `/search`. The payload executes because user input is reflected unencoded into the HTML body and the response is served as `text/html`.\\n\\nEVIDENCE\\n\\n```\\nGET /search?q=%3Csvg%20onload=console.log(1)%3E HTTP/1.1\\nHost: example.org\\n```\\nResponse snippet: `<div class=\\"results\\">No results for <svg onload=console.log(1)></div>`\\nSeverity: High. No authentication required.\\n\\nRECOMMENDATIONS\\n\\n1. HTML-escape the `q` parameter before reflecting it (`<` -> `&lt;`, `>` -> `&gt;`, `&` -> `&amp;`).\\n2. Add a restrictive `Content-Security-Policy` that blocks inline event handlers.\\n3. Review sibling search endpoints (`/users/search`, `/products/search`) for the same pattern.\\n\\nUNTESTED\\n\\nOnly the `q` parameter was probed. Other parameters on `/search` were not reached."
}
```"""  # noqa: E501
