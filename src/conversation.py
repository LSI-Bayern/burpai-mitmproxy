import time
from dataclasses import dataclass, field


@dataclass
class ConversationMessage:
    role: str
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict] | None = None
    timestamp: float = field(default_factory=time.time)


class Conversation:
    """Manages a conversation with tool support and easy integration with sessions."""

    def __init__(self):
        self._messages: list[ConversationMessage] = []

    def add_message(
        self,
        message: ConversationMessage,
    ) -> None:
        self._messages.append(message)

    def update_content(self, name: str, content: str) -> bool:
        for msg in self._messages:
            if msg.name == name:
                msg.content = content
                msg.timestamp = time.time()
                return True

        return False

    def export_for_llm(self) -> list[dict[str, str]]:
        """Export to openai-compatible conversation format."""
        exported = []
        for msg in self._messages:
            exported_msg = {"role": msg.role, "content": msg.content}
            if msg.tool_call_id:
                exported_msg["tool_call_id"] = msg.tool_call_id
            if msg.tool_calls:
                exported_msg["tool_calls"] = msg.tool_calls
            exported.append(exported_msg)
        return exported

    def clear(self) -> bool:
        """Remove all messages without a name."""
        original_count = len(self._messages)
        self._messages = [msg for msg in self._messages if msg.name is not None]
        return len(self._messages) < original_count

    def get_latest_timestamp(self) -> float | None:
        if not self._messages:
            return None
        return max(msg.timestamp for msg in self._messages)

    def __len__(self) -> int:
        return len(self._messages)
