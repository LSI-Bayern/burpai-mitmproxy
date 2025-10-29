import json
import time
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable

import mitmproxy.http
from httpx import codes as status_codes

from src.conversation import Conversation, ConversationMessage
from src.utils import logger, display_sessid


@dataclass
class Session:
    conversation: Conversation = field(default_factory=Conversation)
    created_at: float = field(default_factory=time.time)
    needs_history_clear: bool = False
    files: dict[str, dict] = field(default_factory=dict)
    tasks: list = field(default_factory=list)
    tasks_initialized: bool = False
    tool_id_map: dict[str, str] = field(default_factory=dict)
    tool_timing: dict[str, float] = field(default_factory=dict)
    internal_tool_results: dict[str, dict] = field(default_factory=dict)
    issue_definition: dict = field(default_factory=dict)
    is_finishing: bool = False


class SessionManager:
    """Manages stateful sessions with conversation history."""

    def __init__(
        self,
        llm_token_limit: int | None,
        token_compression_threshold: float = 0.70,
        min_conversation_length: int = 2,
    ):
        self._sessions: dict[str, Session] = {}
        self._llm_token_limit = llm_token_limit

        self.token_compression_threshold = token_compression_threshold
        self.min_conversation_length = min_conversation_length

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def create_session(self, session_id: str) -> Session:
        self._sessions[session_id] = Session(
            conversation=Conversation(),
            created_at=time.time(),
        )

        return self._sessions[session_id]

    def delete_session(self, session_id: str) -> None:
        if session_id in self._sessions:
            logger.info("Session %s: Deleted", display_sessid(session_id))
            del self._sessions[session_id]

    def process_session_response(
        self,
        flow: mitmproxy.http.HTTPFlow,
        session_header_key: str,
        session_id_key: str,
        response_modifier: Callable[[dict[str, Any], mitmproxy.http.HTTPFlow], dict[str, Any]] | None = None,
    ) -> None:
        """Process LLM response and add to session conversation."""
        if not self._validate_response(flow):
            return

        response_data = self._parse_response_data(flow)
        if not response_data:
            return

        session_id = flow.request.headers.get(session_header_key, "")
        if not session_id:
            return

        # Check for content or tool_calls
        content = self._extract_message_content(response_data)
        message = response_data.get("message", {})
        tool_calls = message.get("tool_calls") if isinstance(message, dict) else None
        has_tool_calls = tool_calls is not None and len(tool_calls) > 0

        session = self.get_session(session_id)
        if not session:
            return

        if content or has_tool_calls:
            session.conversation.add_message(
                ConversationMessage(
                    role="assistant",
                    content=content or "",
                    tool_calls=tool_calls,
                )
            )
            self._modify_response(flow, session_id, session_id_key, response_modifier)
        else:
            # If there are no tool calls, nudge the LLM to select a tool
            session.conversation.add_message(ConversationMessage(role="assistant", content=""))
            session.conversation.add_message(
                ConversationMessage(
                    role="user",
                    content="You must select and call at least one tool. "
                    "Please choose an appropriate tool based on the current task.",
                )
            )
            self._modify_response(flow, session_id, session_id_key, response_modifier)

        self._handle_token_usage(session_id, response_data)

    def _validate_response(self, flow: mitmproxy.http.HTTPFlow) -> bool:
        if flow.response is None or not flow.response.text or not flow.response.text.strip():
            return False
        return flow.response.status_code == status_codes.OK

    def _parse_response_data(self, flow: mitmproxy.http.HTTPFlow) -> dict[str, Any] | None:
        return json.loads(flow.response.text)

    def _extract_message_content(self, data: dict[str, Any]) -> str | None:
        message = data.get("message")
        if isinstance(message, dict) and "content" in message:
            return message["content"]
        return None

    def _modify_response(
        self,
        flow: mitmproxy.http.HTTPFlow,
        session_id: str,
        session_id_key: str,
        response_modifier: Callable[[dict[str, Any], mitmproxy.http.HTTPFlow], dict[str, Any]] | None,
    ) -> None:
        """Modify the response by adding session ID and optionally processing with callback."""
        response_json = json.loads(flow.response.text)
        response_json[session_id_key] = session_id

        if response_modifier:
            response_json = response_modifier(response_json, flow)

        flow.response.text = json.dumps(response_json)

    def _handle_token_usage(self, session_id: str, data: dict[str, Any]) -> None:
        eval_info = data.get("eval_info")
        if not eval_info or not session_id:
            return

        total_tokens = eval_info.get("total_tokens", 0)

        if self._llm_token_limit:
            threshold = int(self._llm_token_limit * self.token_compression_threshold)
            if total_tokens > threshold:
                self._mark_history_for_clearing(session_id)

    def _mark_history_for_clearing(self, session_id: str) -> None:
        session = self.get_session(session_id)
        if not session:
            return

        # Edge case: very few messages already exceed the threshold
        if len(session.conversation) <= self.min_conversation_length:
            logger.error(
                "Session %s: Token limit exceeded with only %s messages - cannot clear further",
                display_sessid(session_id),
                len(session.conversation),
            )
            return

        # Set flag to force file update before clearing on next request
        session.needs_history_clear = True
        logger.info("Session %s: Marked for history clearing", display_sessid(session_id))
