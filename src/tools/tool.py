from abc import ABC, abstractmethod
from typing import Any


class Tool(ABC):
    """Base class for tools that can be used in prompts."""

    @abstractmethod
    def get_schema(self, session: dict[str, Any] | None = None) -> dict[str, Any]:
        """Get the JSON schema for this tool."""
        pass

    @abstractmethod
    def process(
        self, tool_call: dict[str, Any], session: dict[str, Any] | None = None, session_id: str = ""
    ) -> dict[str, Any]:
        """Process a tool call and return normalized result."""
        pass

    def get_system_prompt_section(self, _session) -> str:
        """Get any additional system prompt content related to this tool's state."""
        return ""
