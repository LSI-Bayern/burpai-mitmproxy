import json
import time
import uuid
from typing import Any
from xml.dom import minidom

import mitmproxy.http

from src.conversation import ConversationMessage
from src.session_manager import Session, SessionManager
from .prompt import Prompt
from openai import APIError
from src.tools import TaskTool, FileTool, RepeaterTool, IntruderTool, ReporterTool
from src.utils import logger, display_sessid


class ExplorePrompt(Prompt):
    """Handles /ai/hakawai-explore-service/api/v1/start, /continue, and /finish requests."""

    start_path = "/ai/hakawai-explore-service/api/v1/start"
    continue_path = "/ai/hakawai-explore-service/api/v1/continue"
    finish_path = "/ai/hakawai-explore-service/api/v1/finish"

    session_header_key = "X-Exploration-Id"
    session_id_key = "exploration_id"

    def __init__(self, proxy_instance):
        super().__init__(proxy_instance)
        self.sessions = SessionManager(llm_token_limit=proxy_instance._llm.token_limit)
        self.todo_tool = TaskTool()
        self.file_tool = FileTool(
            default_files={
                "target.md": {
                    "description": (
                        "Attack surface inventory: URLs, endpoints, parameters, technologies, auth mechanisms"
                    ),
                },
                "findings.md": {
                    "description": "Confirmed vulnerabilities with severity, evidence, and exploitation details",
                },
                "observations.md": {
                    "description": "Application behavior: filtering, encoding, WAF, bypasses, error patterns",
                },
            }
        )
        self.repeater_tool = RepeaterTool()
        self.intruder_tool = IntruderTool()
        self.reporter_tool = ReporterTool()

    def build_session_request(self, session_id: str, tools: list[dict]) -> dict[str, Any]:
        """Build LLM request from session conversation."""
        session = self.sessions.get_session(session_id)
        if not session:
            raise KeyError(f"Unknown session_id: {session_id}")

        return self.build_llm_request(
            session.conversation.export_for_llm(),
            tools=tools,
        )

    def create_session(self, session_id: str) -> Session:
        """Create a new session with pre-initialized default files."""
        session = self.sessions.create_session(session_id)

        for filename, file_data in self.file_tool.get_default_files().items():
            description = file_data.get("description", "")
            content = f"<!-- {description} -->\n" if description else ""
            session.files[filename] = {"content": content}

        return session

    async def handle_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Route to appropriate handler based on path."""
        path = flow.request.path.split("?", 1)[0]

        try:
            if path == self.start_path:
                await self.handle_start_request(flow)
            elif path == self.continue_path:
                await self.handle_continue_request(flow)
            elif path == self.finish_path:
                await self.handle_finish_request(flow)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in request: %s", str(e))
            flow.response = mitmproxy.http.Response.make(
                400,
                json.dumps({"error": f"Invalid JSON: {str(e)}"}),
                {"Content-Type": "application/json"},
            )
        except (APIError, ValueError) as e:
            logger.error("LLM API error: %s", str(e))
            session_id = flow.request.headers.get(self.session_header_key)
            if session_id:
                self.sessions.delete_session(session_id)
            flow.response = mitmproxy.http.Response.make(
                500,
                json.dumps({"error": f"LLM API request failed: {str(e)}"}),
                {"Content-Type": "application/json"},
            )

    async def handle_start_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Handle start request by creating new conversation: /start."""
        request_data = json.loads(flow.request.text)
        issue_definition = request_data.get("issue_definition", {})

        session_id = str(uuid.uuid4())
        session = self.create_session(session_id)
        session.issue_definition = issue_definition

        # Add system message
        system_content = self._create_system_message(issue_definition)
        session.conversation.add_message(
            ConversationMessage(
                name="system_prompt",
                role="system",
                content=system_content,
            )
        )

        # Add memory
        memory_content = self._create_memory_message(session_id)
        session.conversation.add_message(
            ConversationMessage(
                name="memory",
                role="assistant",
                content=memory_content,
            )
        )

        # Add user message
        user_content = self._create_start_user_content(flow.request.text)
        session.conversation.add_message(ConversationMessage(role="user", content=user_content))

        # Send LLM request
        logger.info("Session %s: Created with %s messages", display_sessid(session_id), len(session.conversation))
        llm_request = self.build_session_request(session_id, self._get_tools_for_request(session_id))
        flow.request.headers[self.session_header_key] = session_id
        await self.proxy_request(flow, llm_request)

    async def handle_continue_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Handle continue request by extending existing conversation: /continue."""
        request_data = json.loads(flow.request.text)
        session_id = request_data.get(self.session_id_key, "")

        session = self.sessions.get_session(session_id)
        if not session:
            logger.error("Session %s: Unknown/expired session", display_sessid(session_id))
            flow.response = mitmproxy.http.Response.make(400, b"Unknown session_id")
            return

        user_message = None
        if session.needs_history_clear:
            user_message = (
                "**CONTEXT WINDOW FULL**: This conversation has grown too large. Afterwards, "
                "all messages in this conversation will be deleted except for `<system_prompt>` and `<memory>`. "
                "Use `update_files` NOW to update your files with any missing information from this conversation "
                "to ensure nothing important is lost."
            )

        await self._process_and_continue(
            flow, session_id, request_data.get("tool_results", []), user_message, "Continuing"
        )

    async def handle_finish_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Handle finish request by providing final summary: /finish."""
        request_data = json.loads(flow.request.text)
        session_id = request_data.get(self.session_id_key, "")

        session = self.sessions.get_session(session_id)
        if not session:
            logger.error("Session %s: Unknown/expired session", display_sessid(session_id))
            flow.response = mitmproxy.http.Response.make(400, b"Unknown session_id")
            return

        session.is_finishing = True

        user_message = (
            'The user has clicked "Finish Task" to end this exploration session. Based on all the tool '
            "results and exploration performed so far, provide a comprehensive final summary using the "
            'reporter" tool, calling out any uncertainty if the evidence is incomplete.'
        )

        await self._process_and_continue(
            flow, session_id, request_data.get("tool_results", []), user_message, "Finishing"
        )

    async def handle_response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Handle LLM response, looping until Burp tools are used."""
        session_id = flow.request.headers.get(self.session_header_key)
        session = self.sessions.get_session(session_id) if session_id else None

        if not session:
            self.sessions.process_session_response(
                flow,
                self.session_header_key,
                self.session_id_key,
                response_modifier=self.process_response_json,
            )
            return

        while True:
            self.sessions.process_session_response(
                flow,
                self.session_header_key,
                self.session_id_key,
                response_modifier=self.process_response_json,
            )

            response_json = json.loads(flow.response.text)
            burp_tool_calls = response_json.get("tool_calls", [])

            if burp_tool_calls:
                break

            # Only internal tools were used (no Burp tools)
            logger.info(
                "Session %s: Only internal tools used",
                display_sessid(session_id),
            )

            self._append_tool_result_messages([], session_id)

            # Clear history if needed
            if session.needs_history_clear:
                cleared = session.conversation.clear()
                if cleared:
                    logger.info("Session %s: Cleared", display_sessid(session_id))
                session.needs_history_clear = False

            # Provide feedback to proceed with testing
            feedback = (
                "You've updated your internal state. You may proceed with active testing using the available tools."
            )
            session.conversation.add_message(ConversationMessage(role="user", content=feedback))
            await self._update_and_send_llm_request(flow, session_id)

    def process_response_json(self, response_json: dict[str, Any], flow: mitmproxy.http.HTTPFlow) -> dict[str, Any]:
        """Parse OpenAI tool calls and normalize for Burp Suite."""
        session_id = flow.request.headers.get(self.session_header_key)
        session = self.sessions.get_session(session_id) if session_id else None

        message = response_json.get("message", {})
        tool_calls_from_llm = message.get("tool_calls", [])

        burp_tool_calls: list[dict[str, Any]] = []
        finalize_session = False
        top_level_step_title, top_level_step_action = "", ""

        for llm_tool_call in tool_calls_from_llm:
            if not isinstance(llm_tool_call, dict):
                logger.warning(
                    "Skipping non-dict tool call: %s (type: %s)", llm_tool_call, type(llm_tool_call).__name__
                )
                continue

            tool_call_id = llm_tool_call.get("id", "")
            function_data = llm_tool_call.get("function", {})
            tool_name = function_data.get("name", "")
            arguments_json = function_data.get("arguments", "{}")

            logger.debug("Processing tool call: id=%s, name=%s", tool_call_id, tool_name)
            logger.debug("Raw arguments JSON: %s", arguments_json)

            arguments = json.loads(arguments_json)
            logger.debug("Parsed arguments type: %s, value: %s", type(arguments).__name__, arguments)

            # Process internal tools
            if self._process_internal_tool_call(tool_name, arguments, tool_call_id, session, session_id):
                continue

            # Process Burp tools
            processed_call, is_finalize = self._process_burp_tool_call(tool_name, arguments, session, session_id)
            if not processed_call:
                continue

            processed_call["id"] = tool_call_id

            if session:
                session.tool_id_map[tool_call_id] = tool_name
                session.tool_timing[tool_call_id] = time.time()

            if not top_level_step_title:
                top_level_step_title = processed_call.get("step_title", "")
                top_level_step_action = processed_call.get("step_action", "")

            if is_finalize:
                finalize_session = True

            burp_tool_calls.append(processed_call)

        response_json["step_title"] = top_level_step_title
        response_json["step_action"] = top_level_step_action
        response_json["tool_calls"] = burp_tool_calls

        if finalize_session and session_id:
            self.sessions.delete_session(session_id)

        return response_json

    def _get_tools_for_request(self, session_id: str) -> list[dict]:
        """Get list of available tools in OpenAI format based on session state."""
        session = self.sessions.get_session(session_id)

        if session.needs_history_clear:
            tools = [self.file_tool.get_schema()]
        elif session.is_finishing:
            tools = [self.reporter_tool.get_schema()]
        else:
            tools = []
            tools.append(self.todo_tool.get_schema(session))
            tools.append(self.file_tool.get_schema())
            tools.append(self.repeater_tool.get_schema())
            tools.append(self.intruder_tool.get_schema())

            if session.tasks_initialized and self.todo_tool.are_all_tasks_completed(session):
                tools.append(self.reporter_tool.get_schema())

        tool_names = [t["function"]["name"] for t in tools]
        logger.debug("Session %s: Available tools for this round: %s", display_sessid(session_id), tool_names)

        return tools

    def _process_internal_tool_call(
        self, tool_name: str, arguments: dict, tool_call_id: str, session: Session | None, session_id: str
    ) -> bool:
        """Process internal tool calls (update_tasks, update_files). Returns True if processed."""
        if not session:
            return False

        if tool_name == "update_tasks":
            result_dict = self.todo_tool.process(arguments, session, session_id)
            session.internal_tool_results[tool_call_id] = result_dict
            return True

        if tool_name == "update_files":
            result_dict = self.file_tool.process(arguments, session, session_id)
            session.internal_tool_results[tool_call_id] = result_dict
            return True

        return False

    def _process_burp_tool_call(
        self, tool_name: str, arguments: dict, session: Session | None, session_id: str
    ) -> tuple[dict[str, Any] | None, bool]:
        """Process Burp tool calls (repeater, intruder, reporter). Returns (processed_call, is_finalize)."""
        if tool_name == "repeater":
            return self.repeater_tool.process(arguments), False
        if tool_name == "intruder":
            return self.intruder_tool.process(arguments), False
        if tool_name == "reporter":
            return self.reporter_tool.process(arguments, session, session_id), True

        logger.warning("Unknown tool name: %s", tool_name)
        return None, False

    def _format_timing_info(self, elapsed_seconds: float) -> str:
        if elapsed_seconds < 1:
            return f"**Time since tool call**: {elapsed_seconds * 1000:.0f}ms\n\n"
        if elapsed_seconds < 60:  # noqa: PLR2004
            return f"**Time since tool call**: {elapsed_seconds:.2f}s\n\n"
        minutes = int(elapsed_seconds // 60)
        seconds = elapsed_seconds % 60
        return f"**Time since tool call**: {minutes}m {seconds:.1f}s\n\n"

    def _create_memory_message(self, session_id: str) -> str:
        """Create the memory message as XML, containing tasks and files."""
        session = self.sessions.get_session(session_id)
        if not session:
            return "<memory><tasks></tasks><files></files></memory>"

        todo_xml_string = self.todo_tool.get_system_prompt_section(session)
        files_xml_string = self.file_tool.get_system_prompt_section(session)

        return f"<memory>{todo_xml_string}{files_xml_string}</memory>"

    def _create_start_user_content(self, payload: str) -> str:
        """Create user content for explore start requests."""
        request_data = json.loads(payload)
        issue_definition = request_data.get("issue_definition", {})

        # Extract details from "Explore Issue" functionality
        detail = issue_definition.get("detail", "")
        target = issue_definition.get("target", "")
        evidence = issue_definition.get("evidence", [])

        # Build the initial context
        context = ""
        if evidence:
            for i, ev in enumerate(evidence):
                if ev.get("type") == "REQUEST_RESPONSE":
                    context += f"\nRequest {i + 1}:\n{ev.get('request', '')}"
                    if ev.get("response"):
                        context += f"\nResponse {i + 1}:\n{ev.get('response', '')}"
                    if ev.get("request_highlights"):
                        context += f"\nRequest {i + 1} Highlights:\n{ev.get('request_highlights', '')}"
                    if ev.get("response_highlights"):
                        context += f"\nResponse {i + 1} Highlights:\n{ev.get('response_highlights', '')}"
                    if ev.get("notes"):
                        context += f"\nNotes {i + 1}:\n{ev.get('notes', '')}"

        return f"""Target: {target}
User Instruction: {detail}

Evidence:
{context}"""

    def _create_system_message(self, issue_definition: dict) -> str:
        """Create dynamic system message based on issue type and context (returns compact XML)."""
        issue_name = issue_definition.get("name", "")

        # Create document
        doc = minidom.Document()
        root = doc.createElement("system_prompt")
        doc.appendChild(root)

        # Metadata
        if issue_name == "REQUEST_RESPONSE_EXPLORE":
            invocation_source = "Burp Suite Repeater"
            task_description = (
                "You are performing analysis and testing on HTTP traffic based on user instructions and provided "
                "evidence."
            )
            vulnerability_info = ""
        else:
            invocation_source = "Burp Suite 'Explore issue with AI'"
            task_description = (
                "You are investigating an issue flagged by Burp Scanner. Determine whether it's genuine or a false "
                "positive. If confirmed, explore further to assess impact and discover related issues."
            )
            vulnerability_info = f"\n**Vulnerability Type**: {issue_name}"
            background = issue_definition.get("background", "")
            if background:
                vulnerability_info += f"\n**Background**: {background}"

        metadata = doc.createElement("metadata")
        metadata.appendChild(
            doc.createCDATASection(
                f"""**Role**: BurpAI Security Assistant
**Invoked From**: {invocation_source}
**Task**: {task_description}{vulnerability_info}"""
            )
        )
        root.appendChild(metadata)

        # Core mission
        core_mission = doc.createElement("core_mission")
        core_mission.appendChild(
            doc.createCDATASection(
                """Your PRIMARY job is active security testing. Follow this workflow:

1. **Plan**: Create tasks for the testing strategy
2. **Test**: Use the Repeater and Intruder tools to actively test the application
3. **Document**: Update tasks and files with findings as you progress
4. **Iterate**: Test thoroughly and persistently
5. **Report**: Summarize findings when all tasks complete

**Mindset:**
- Only test what the user asked - don't expand scope
- Aim for conclusive proof: weak indicators aren't enough - develop working exploit payloads"""  # noqa: E501
            )
        )
        root.appendChild(core_mission)

        # Tool usage
        tool_usage = doc.createElement("tool_usage")
        tool_usage.appendChild(
            doc.createCDATASection(
                """**Tools:**
- Testing: `repeater`, `intruder`, `reporter`
- Progress tracking: `update_tasks`, `update_files`

**Tool selection:**
- `intruder` -> Test many variations quickly (returns status codes, bodies truncated to 200 bytes each)
- `repeater` -> Examine individual requests in detail (returns larger responses)
- Use Intruder to discover, Repeater to investigate"""  # noqa: E501
            )
        )
        root.appendChild(tool_usage)

        # Testing methodology
        testing_methodology = doc.createElement("testing_methodology")
        testing_methodology.appendChild(
            doc.createCDATASection(
                """**Encoding requirements:**
Encode payloads based on context:
- URL/form parameters -> URL-encode (`<script>` -> `%3Cscript%3E`)
- Form data -> URL-encode (`key=<val>` -> `key=%3Cval%3E`)
- JSON bodies -> JSON-escape (value `a"b\\` -> `{"x":"a\\"b\\\\"}`)`

**Key principles:**
- Be persistent and thorough: Try multiple bypass techniques before concluding negative
- Non-destructive: NEVER use `DROP TABLE`, `DELETE`, `rm -rf`, etc.
- Considerate: Use `console.log()` instead of `alert()` for Stored XSS

**Bypass techniques when encountering filters:**
1. Test simple payload first to understand filtering
2. Case variations: `<ScRiPt>`, `SeLeCt`, mixed case bypasses
3. Encoding: URL encode (`%3Cscript%3E`), double encode, unicode
4. Comments: `'/**/OR/**/1=1`, `UNION/*comment*/SELECT`
5. Alternative syntax: `<svg onload=...>`, `$(cmd)`, `{{7*7}}` (SSTI), `....//` (traversal)
6. Concatenation: Breaking up keywords, using string concat operators

(This list is incomplete and dependent on the context.)

Make sure to always document what works and what's blocked."""  # noqa: E501
            )
        )
        root.appendChild(testing_methodology)

        # Evaluation criteria
        evaluation_criteria = doc.createElement("evaluation_criteria")
        evaluation_criteria.appendChild(
            doc.createCDATASection(
                """**Judge success from HTTP responses** (no browser execution environment available):

**When to conclude testing:**
- Positive: Clear evidence of exploitation (unencoded reflection, SQL error, command output, etc.)
- Negative: After multiple bypass attempts with no success
- Blocked: WAF/rate limiting prevents further testing

However, even with a negative conclusion some uncertainty remains, since testing rarely covers all possibilities."""  # noqa: E501
            )
        )
        root.appendChild(evaluation_criteria)

        # Progress tracking reminder
        progress_tracking = doc.createElement("progress_tracking_reminder")
        progress_tracking.appendChild(
            doc.createCDATASection(
                """Use progress tracking tools (`update_tasks`, `update_files`) regularly to maintain context:
- Call them in parallel with testing tools if possible (e.g., `repeater` / `intruder` + `update_files` at once)
- Your tasks and files are the only persistent memory across the entire session

**Finishing the exploration session:**
1. **You finish on your own**: After creating tasks and marking all as completed, the `reporter` tool becomes available
2. **User triggers finish**: The user clicks "Finish Task". In this case, ONLY the `reporter` tool is available (no testing or tracking tools). You must provide a final summary based on whatever progress was made, even if incomplete."""  # noqa: E501
            )
        )
        root.appendChild(progress_tracking)

        return doc.toxml()

    async def _process_and_continue(
        self,
        flow: mitmproxy.http.HTTPFlow,
        session_id: str,
        tool_results: list,
        user_message: str | None,
        log_action: str,
    ) -> None:
        """Process tool results, optionally add user message, and continue LLM conversation."""
        session = self.sessions.get_session(session_id)
        if not session:
            return

        self._append_tool_result_messages(tool_results, session_id)

        if user_message:
            session.conversation.add_message(ConversationMessage(role="user", content=user_message))

        logger.info(
            "Session %s: %s with %s messages",
            display_sessid(session_id),
            log_action,
            len(session.conversation),
        )
        flow.request.headers[self.session_header_key] = session_id
        await self._update_and_send_llm_request(flow, session_id)

    async def _update_and_send_llm_request(self, flow: mitmproxy.http.HTTPFlow, session_id: str) -> None:
        """Update memory/system messages and send LLM request."""
        session = self.sessions.get_session(session_id)
        if not session:
            return

        memory_content = self._create_memory_message(session_id)
        session.conversation.update_content("memory", memory_content)

        issue_definition = session.issue_definition
        system_content = self._create_system_message(issue_definition)
        session.conversation.update_content("system_prompt", system_content)

        llm_request = self.build_session_request(session_id, self._get_tools_for_request(session_id))
        await self.proxy_request(flow, llm_request)

    def _format_single_tool_result(self, result_data: str, tool_type: str | None) -> str:
        """Format a single tool result based on its type."""
        is_empty = not result_data or not result_data.strip()
        is_burp_error = result_data == "This request could not be sent."
        is_intruder_empty = tool_type == "intruder" and result_data.count("\n") == 1

        if is_empty or is_burp_error or is_intruder_empty:
            tool_name = tool_type or "tool"
            return f"**ERROR**: The {tool_name} tool failed. Possible connection error, timeout, or target offline.\n"

        if tool_type == "repeater":
            return self.repeater_tool.format_result(result_data)
        if tool_type == "intruder" and result_data.startswith(
            "status code,content length,content type,truncated body,payloads\n"
        ):
            return self.intruder_tool.format_result(result_data)
        return f"```\n{result_data}\n```\n"

    def _append_tool_result_messages(self, tool_results: list, session_id: str) -> None:
        """Append individual tool result messages to conversation."""
        session = self.sessions.get_session(session_id)
        if not session:
            return

        tool_id_map = session.tool_id_map
        tool_timing = session.tool_timing
        internal_tool_results = session.internal_tool_results

        # Append Burp tool results
        for result in tool_results:
            tool_id = result.get("tool_id", "")
            result_data = result.get("result", "")
            tool_type = tool_id_map.get(tool_id)

            formatted_content = self._format_single_tool_result(result_data, tool_type)

            # Add timing information
            if tool_id in tool_timing:
                elapsed_seconds = time.time() - tool_timing[tool_id]
                timing_info = self._format_timing_info(elapsed_seconds)
                formatted_content = timing_info + formatted_content
                del tool_timing[tool_id]

            session.conversation.add_message(
                ConversationMessage(role="tool", content=formatted_content, tool_call_id=tool_id)
            )

        # Append internal results
        for tool_call_id, tool_result in internal_tool_results.items():
            session.conversation.add_message(
                ConversationMessage(role="tool", content=tool_result["content"], tool_call_id=tool_call_id)
            )

        session.internal_tool_results = {}
