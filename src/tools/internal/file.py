from __future__ import annotations

from typing import Any, TYPE_CHECKING
from xml.dom import minidom

from src.utils import logger, display_sessid
from src.tools.tool import Tool

if TYPE_CHECKING:
    from src.session_manager import Session


class FileTool(Tool):
    """Tool for managing markdown files throughout the exploration session."""

    def __init__(self, default_files: dict[str, dict[str, Any]] | None = None):
        self._default_files = default_files or {}

    def process(self, tool_call: dict[str, Any], session: Session, session_id: str) -> dict[str, Any]:
        """Process a tool call and return an internal format. The tool call must conform to the schema."""
        operations = tool_call["operations"]
        self._process_operations(operations, session, session_id)

        # Summary of changes
        filenames = {op.get("filename") for op in operations if op.get("filename")}
        if filenames:
            files_str = ", ".join(sorted(filenames))
            content = f"Updated files: {files_str}"
        else:
            content = f"Updated files ({len(operations)} operation{'s' if len(operations) != 1 else ''})"

        return {"tool_name": "update_files", "content": content}

    def get_default_files(self) -> dict[str, dict[str, Any]]:
        """Get default user files that are pre-created in every session."""
        return self._default_files

    def get_schema(self, _session=None) -> dict[str, Any]:
        """Get the JSON schema for the update_files tool."""
        md_filename_pattern = r"^[a-zA-Z0-9_-]+\.md$"

        append_file_op = {
            "properties": {
                "action": {"const": "append"},
                "filename": {"type": "string", "pattern": md_filename_pattern},
                "content": {"type": "string"},
            },
            "required": ["action", "filename", "content"],
            "additionalProperties": False,
        }

        write_file_op = {
            "properties": {
                "action": {"const": "write"},
                "filename": {"type": "string", "pattern": md_filename_pattern},
                "content": {"type": "string"},
            },
            "required": ["action", "filename", "content"],
            "additionalProperties": False,
        }

        file_ops_schema = {
            "type": "object",
            "anyOf": [
                append_file_op,
                write_file_op,
            ],
        }

        parameters_schema = {
            "type": "object",
            "properties": {
                "operations": {
                    "type": "array",
                    "minItems": 1,
                    "items": file_ops_schema,
                },
            },
            "required": ["operations"],
            "additionalProperties": False,
        }

        return {
            "type": "function",
            "function": {
                "name": "update_files",
                "description": self._get_documentation(),
                "parameters": parameters_schema,
            },
        }

    def get_system_prompt_section(self, session: Session) -> str:
        """Get the current files state as XML."""
        doc = minidom.Document()
        files_container = doc.createElement("files")

        files = session.files

        if files:
            sorted_filenames = sorted(files.keys())
            for filename in sorted_filenames:
                file_data = files[filename]
                content = file_data.get("content", "")

                file_elem = doc.createElement("file")
                file_elem.setAttribute("name", filename)
                file_elem.appendChild(doc.createTextNode(content))

                files_container.appendChild(file_elem)

        return files_container.toxml()

    def _get_documentation(self) -> str:
        default_files = self.get_default_files()

        pre_created_section = ""
        if default_files:
            file_list = "\n".join(
                [
                    f"- `{filename}` - {file_data.get('description', '')}"
                    for filename, file_data in default_files.items()
                ]
            )
            pre_created_section = f"\n**Pre-created files:**\n{file_list}\n"

        return f"""
Maintain markdown files to organize your security testing findings and observations.
It is highly encouraged to call this tool regularly to update your memory.

**Parameters:**
- `operations`: Array of file operation objects:
  - **write**: {{"action": "write", "filename": "name.md", "content": "..."}} - Like > in Unix, writes to files (creates or replaces)
  - **append**: {{"action": "append", "filename": "name.md", "content": "..."}} - Like >> in Unix, appends to existing files
{pre_created_section}
**Examples:**

Document confirmed vulnerability:
```json
{{
  "operations": [
    {{
      "action": "append",
      "filename": "findings.md",
      "content": "\\n## Reflected XSS in search parameter\\n\\n**Severity**: High\\n**Parameter**: q\\n**Payload**: `<script>console.log(1)</script>`\\n**Evidence**: Payload reflected unencoded in HTML response"
    }}
  ]
}}
```

Record application behavior:
```json
{{
  "operations": [
    {{
      "action": "append",
      "filename": "observations.md",
      "content": "\\n- Login form filters `<script>` tags but allows `<svg onload>`\\n- SQL keywords appear to be blocked (tested: SELECT, UNION, OR)"
    }}
  ]
}}
```
"""  # noqa: E501

    def _process_operations(self, operations: list[dict], session: Session, session_id: str) -> None:
        """Process file operations: append and write."""
        files = session.files

        for op in operations:
            action = op.get("action")
            filename = op.get("filename", "")
            content = op.get("content", "")

            if action == "append":
                if filename not in files:
                    files[filename] = {"content": ""}
                existing_content = files[filename].get("content", "")
                if existing_content and not existing_content.endswith("\n"):
                    existing_content += "\n"
                files[filename]["content"] = existing_content + content
                logger.info("Session %s: Appended to file '%s'", display_sessid(session_id), filename)
            elif action == "write":
                if filename not in files:
                    files[filename] = {"content": ""}
                files[filename]["content"] = content
                logger.info("Session %s: Wrote file '%s'", display_sessid(session_id), filename)

        logger.info(
            "Session %s: Processed %s file operations, now %s files",
            display_sessid(session_id),
            len(operations),
            len(files),
        )
