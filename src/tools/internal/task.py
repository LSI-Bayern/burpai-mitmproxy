from __future__ import annotations

from typing import Any, TYPE_CHECKING
from xml.dom import minidom

from src.utils import logger, display_sessid
from src.tools.tool import Tool

if TYPE_CHECKING:
    from src.session_manager import Session


class TaskTool(Tool):
    """Tool for managing task list throughout the exploration session."""

    def process(self, tool_call: dict[str, Any], session: Session, session_id: str) -> dict[str, Any]:
        """Process a tool call and return an internal format. The tool call must conform to the schema."""
        operations = tool_call["operations"]
        self._process_operations(operations, session, session_id)

        session.tasks_initialized = True

        # Summary of changes
        op_count = len(operations)
        return {
            "tool_name": "update_tasks",
            "content": f"Updated tasks ({op_count} operation{'s' if op_count != 1 else ''})",
        }

    def get_schema(self, session: Session | None = None) -> dict[str, Any]:
        """Get the JSON schema for the update_tasks tool with dynamic constraints."""
        task_count = 0
        if session:
            task_count = len(session.tasks)

        schema_items = [
            {
                "properties": {
                    "action": {"const": "add"},
                    "title": {"type": "string"},
                },
                "required": ["action", "title"],
                "additionalProperties": False,
            }
        ]

        # Add actions if we have tasks
        if task_count > 0:
            id_schema = {"type": "integer", "minimum": 0, "maximum": task_count - 1}

            schema_items.extend(
                [
                    {
                        "properties": {
                            "action": {"const": "complete"},
                            "id": id_schema,
                        },
                        "required": ["action", "id"],
                        "additionalProperties": False,
                    },
                    {
                        "properties": {
                            "action": {"const": "reopen"},
                            "id": id_schema,
                        },
                        "required": ["action", "id"],
                        "additionalProperties": False,
                    },
                    {
                        "properties": {
                            "action": {"const": "delete"},
                            "id": id_schema,
                        },
                        "required": ["action", "id"],
                        "additionalProperties": False,
                    },
                ]
            )

        return {
            "type": "function",
            "function": {
                "name": "update_tasks",
                "description": self._get_documentation(),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operations": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "anyOf": schema_items,
                            },
                        },
                    },
                    "required": ["operations"],
                    "additionalProperties": False,
                },
            },
        }

    def _get_documentation(self) -> str:
        return """
Track your testing progress with a dynamic task list based on the user's instructions.

**Purpose:**
Start with tasks derived from the user's request, then evolve the list as you discover
new findings, pivot your approach, or complete tasks.

**Parameters:**
- `operations`: Array of operation objects:
  - **add**: `{"action": "add", "title": "description"}`
  - **complete**: `{"action": "complete", "id": N}`
  - **reopen**: `{"action": "reopen", "id": N}`
  - **delete**: `{"action": "delete", "id": N}` (IDs don't shift during batch operations)

**Examples:**

Add initial tasks:
```json
{
  "operations": [
    {"action": "add", "title": "Test ping parameter for command injection"},
    {"action": "add", "title": "Try different command separators"},
    {"action": "add", "title": "Verify if commands are executed"}
  ]
}
```

Complete first task:
```json
{"operations": [{"action": "complete", "id": 0}]}
```

Add new task as you discover more:
```json
{"operations": [{"action": "add", "title": "Test with command substitution"}]}
```

Reopen second task if you need to revisit:
```json
{"operations": [{"action": "reopen", "id": 1}]}
```

Delete third task if no longer relevant:
```json
{"operations": [{"action": "delete", "id": 2}]}
```

Tasks appear in `<memory>` as:
```xml
<tasks>
  <task id="0" status="completed">Test ping parameter for command injection</task>
  <task id="1" status="incomplete">Try different command separators</task>
  <task id="2" status="incomplete">Verify if commands are executed</task>
</tasks>
```

The `reporter` tool unlocks when all tasks are completed.
"""

    def _process_operations(self, operations: list[dict], session: Session, session_id: str) -> None:
        """Process task operations: add, complete, reopen, delete."""
        tasks = session.tasks

        deletes = []
        other_ops = []
        for op in operations:
            if op.get("action") == "delete":
                deletes.append(op)
            else:
                other_ops.append(op)

        for op in other_ops:
            action = op.get("action")

            if action == "add":
                title = op.get("title", "")
                tasks.append({"title": title, "completed": False})
                logger.info("Session %s: Added task '%s'", display_sessid(session_id), title)
            elif action == "complete":
                task_id = op.get("id")
                if task_id is not None and 0 <= task_id < len(tasks):
                    tasks[task_id]["completed"] = True
                    logger.info("Session %s: Completed task #%s", display_sessid(session_id), task_id)
                else:
                    logger.warning("Session %s: Invalid id %s for complete", display_sessid(session_id), task_id)
            elif action == "reopen":
                task_id = op.get("id")
                if task_id is not None and 0 <= task_id < len(tasks):
                    tasks[task_id]["completed"] = False
                    logger.info("Session %s: Reopened task #%s", display_sessid(session_id), task_id)
                else:
                    logger.warning("Session %s: Invalid id %s for reopen", display_sessid(session_id), task_id)

        # Process deletes last in descending order to avoid ID shifting
        delete_ids = []
        for op in deletes:
            task_id = op.get("id")
            if task_id is not None and 0 <= task_id < len(tasks):
                delete_ids.append(task_id)
            else:
                logger.warning("Session %s: Invalid id %s for delete", display_sessid(session_id), task_id)

        for task_id in sorted(delete_ids, reverse=True):
            removed = tasks.pop(task_id)
            logger.info("Session %s: Deleted task #%s: '%s'", display_sessid(session_id), task_id, removed.get("title"))

        logger.info(
            "Session %s: Processed %s task operations, now %s tasks",
            display_sessid(session_id),
            len(operations),
            len(tasks),
        )

    def get_system_prompt_section(self, session: Session) -> str:
        """Get the current tasks state as XML."""
        doc = minidom.Document()
        tasks_container = doc.createElement("tasks")

        tasks = session.tasks

        if tasks:
            for i, task in enumerate(tasks):
                title = task.get("title", "")
                completed = task.get("completed", False)

                task_elem = doc.createElement("task")
                task_elem.setAttribute("id", str(i))
                task_elem.setAttribute("status", "completed" if completed else "incomplete")
                task_elem.appendChild(doc.createTextNode(title))
                tasks_container.appendChild(task_elem)

        return tasks_container.toxml()

    def are_all_tasks_completed(self, session: Session) -> bool:
        """Check if all tasks are completed (for enabling reporter tool)."""
        if not session.tasks:
            return False

        return all(task.get("completed", False) for task in session.tasks)
