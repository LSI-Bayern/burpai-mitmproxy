import xml.etree.ElementTree as ET

from src.session_manager import Session
from src.tools.burp.intruder import IntruderTool
from src.tools.burp.repeater import RepeaterTool
from src.tools.burp.reporter import ReporterTool
from src.tools.internal.file import FileTool
from src.tools.internal.task import TaskTool


class TestRepeaterTool:
    def test_get_schema(self):
        tool = RepeaterTool()
        schema = tool.get_schema()

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "repeater"
        assert "step_title" in schema["function"]["parameters"]["properties"]
        assert "step_action" in schema["function"]["parameters"]["properties"]
        assert "request" in schema["function"]["parameters"]["properties"]
        assert schema["function"]["parameters"]["required"] == ["step_title", "step_action", "request"]
        assert len(schema["function"]["description"]) > 0

    def test_process_basic_request(self):
        tool = RepeaterTool()
        tool_call = {
            "step_title": "Test XSS",
            "step_action": "Testing for XSS vulnerability",
            "request": "GET /search?q=test HTTP/1.1\r\nHost: example.org",
        }

        result = tool.process(tool_call)

        assert result["tool_name"] == "repeater"
        assert result["step_title"] == "Test XSS"
        assert result["step_action"] == "Testing for XSS vulnerability"
        assert result["arguments"]["request"] == "GET /search?q=test HTTP/1.1\r\nHost: example.org"

    def test_process_post_request(self):
        tool = RepeaterTool()
        expected_request = (
            "POST /login HTTP/1.1\r\n"
            "Host: example.org\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n"
            "username=admin&password=123"
        )
        tool_call = {
            "step_title": "SQL Injection Test",
            "step_action": "Testing login for SQL injection",
            "request": expected_request,
        }

        result = tool.process(tool_call)

        assert result["tool_name"] == "repeater"
        assert result["step_title"] == "SQL Injection Test"
        assert result["arguments"]["request"] == expected_request

    def test_process_empty_request(self):
        tool = RepeaterTool()
        tool_call = {
            "step_title": "Empty test",
            "step_action": "Testing empty request",
            "request": "",
        }

        result = tool.process(tool_call)

        assert result["tool_name"] == "repeater"
        assert result["arguments"]["request"] == ""

    def test_format_result_basic_http(self):
        tool = RepeaterTool()
        result_data = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>test</html>"

        formatted = tool.format_result(result_data)
        expected = "```http\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>test</html>\n```\n"

        assert formatted == expected

    def test_format_result_non_http(self):
        tool = RepeaterTool()
        result_data = "Some error message"

        formatted = tool.format_result(result_data)
        expected = "```\nSome error message\n```\n"

        assert formatted == expected

    def test_format_result_truncated_with_content_length(self):
        tool = RepeaterTool()
        body_content = "some content"
        content_length = 1000
        result_data = f"HTTP/1.1 200 OK\nContent-Length: {content_length}\n\n{body_content}<truncated tool result>"

        formatted = tool.format_result(result_data)

        body_bytes = len(body_content)
        missing_bytes = content_length - body_bytes

        assert f"body: {body_bytes:,}/{content_length:,} bytes" in formatted
        assert f"{missing_bytes:,} bytes likely truncated from body based on Content-Length header" in formatted
        assert "```http\n" in formatted
        assert body_content in formatted
        assert "<truncated tool result>" not in formatted

    def test_format_result_truncated_without_content_length(self):
        tool = RepeaterTool()
        body_content = "some content"
        result_data = f"HTTP/1.1 200 OK\n\n{body_content}<truncated tool result>"

        formatted = tool.format_result(result_data)

        total_bytes = len("HTTP/1.1 200 OK\n\n" + body_content)
        assert f"first {total_bytes:,} bytes" in formatted
        assert "response truncated" in formatted
        assert body_content in formatted
        assert "<truncated tool result>" not in formatted


class TestIntruderTool:
    def test_get_schema(self):
        tool = IntruderTool()
        schema = tool.get_schema()

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "intruder"
        assert "request_template" in schema["function"]["parameters"]["properties"]
        assert "payloads" in schema["function"]["parameters"]["properties"]
        assert len(schema["function"]["description"]) > 0

    def test_process_with_default_encoding(self):
        tool = IntruderTool()
        tool_call = {
            "step_title": "XSS Test",
            "step_action": "Testing XSS payloads",
            "request_template": "GET /search?q=§payload§ HTTP/1.1\r\nHost: example.org",
            "payloads": ["<script>alert(1)</script>", "test value"],
            "auto_url_encode": True,
        }

        result = tool.process(tool_call)

        assert result["tool_name"] == "intruder"
        assert result["step_title"] == "XSS Test"
        assert result["arguments"]["request"] == "GET /search?q=§payload§ HTTP/1.1\r\nHost: example.org"
        assert result["arguments"]["payloads"][0] == "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        assert result["arguments"]["payloads"][1] == "test%20value"

    def test_process_with_encoding_enabled(self):
        tool = IntruderTool()
        tool_call = {
            "step_title": "Path fuzzing",
            "step_action": "Testing with path characters",
            "request_template": "GET /test§payload§ HTTP/1.1",
            "payloads": ["test/path", "value"],
            "auto_url_encode": True,
        }

        result = tool.process(tool_call)

        assert result["arguments"]["payloads"][0] == "test%2Fpath"
        assert result["arguments"]["payloads"][1] == "value"

    def test_process_with_no_encoding(self):
        tool = IntruderTool()
        tool_call = {
            "step_title": "No encoding",
            "step_action": "Raw payloads",
            "request_template": "POST /api HTTP/1.1",
            "payloads": ['{"user":"test"}'],
            "auto_url_encode": False,
        }

        result = tool.process(tool_call)

        assert result["arguments"]["payloads"][0] == '{"user":"test"}'


class TestReporterTool:
    def test_get_schema(self):
        tool = ReporterTool()
        schema = tool.get_schema()

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "reporter"
        assert "report" in schema["function"]["parameters"]["properties"]
        assert len(schema["function"]["description"]) > 0

    def test_process(self):
        tool = ReporterTool()
        tool_call = {
            "step_title": "Final Report",
            "step_action": "Summarizing findings",
            "report": "We found XSS vulnerability in search parameter.",
        }

        result = tool.process(tool_call)

        assert result["tool_name"] == "reporter"
        assert result["step_title"] == "Final Report"
        assert result["step_action"] == "Summarizing findings"
        assert result["arguments"]["report"] == "We found XSS vulnerability in search parameter."


class TestFileTool:
    def test_get_schema(self):
        tool = FileTool()
        schema = tool.get_schema()

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "update_files"
        assert len(schema["function"]["description"]) > 0

    def test_process_append_new_file(self):
        tool = FileTool()
        session = Session()
        tool_call = {"operations": [{"action": "append", "filename": "findings.md", "content": "XSS found"}]}

        result = tool.process(tool_call, session, "test-session")

        assert result["tool_name"] == "update_files"
        assert "findings.md" in session.files
        assert session.files["findings.md"]["content"] == "XSS found"

    def test_process_append_existing_file(self):
        tool = FileTool()
        session = Session(files={"findings.md": {"content": "First finding\n"}})
        tool_call = {"operations": [{"action": "append", "filename": "findings.md", "content": "Second finding"}]}

        tool.process(tool_call, session, "test-session")

        assert session.files["findings.md"]["content"] == "First finding\nSecond finding"

    def test_process_write_file(self):
        tool = FileTool()
        session = Session(files={"test.md": {"content": "old content"}})
        tool_call = {"operations": [{"action": "write", "filename": "test.md", "content": "new content"}]}

        tool.process(tool_call, session, "test-session")

        assert session.files["test.md"]["content"] == "new content"

    def test_get_system_prompt_section(self):
        tool = FileTool()
        test_files = {"findings.md": {"content": "XSS found"}, "notes.md": {"content": "Test note"}}
        session = Session(files=test_files)

        xml = tool.get_system_prompt_section(session)

        root = ET.fromstring(xml)
        assert root.tag == "files"

        files = root.findall("file")
        assert len(files) == len(test_files)

        for file_elem, (expected_name, expected_data) in zip(files, test_files.items(), strict=True):
            assert file_elem.get("name") == expected_name
            assert file_elem.text == expected_data["content"]


class TestTaskTool:
    def test_get_schema_no_tasks(self):
        tool = TaskTool()
        session = Session()
        schema = tool.get_schema(session=session)

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "update_tasks"
        assert len(schema["function"]["description"]) > 0

    def test_process_add_tasks(self):
        tool = TaskTool()
        session = Session()
        tool_call = {
            "operations": [
                {"action": "add", "title": "Test task 1"},
                {"action": "add", "title": "Test task 2"},
            ]
        }

        result = tool.process(tool_call, session, "test-session")

        assert result["tool_name"] == "update_tasks"
        assert len(session.tasks) == 2  # noqa: PLR2004
        assert session.tasks[0]["title"] == "Test task 1"
        assert session.tasks[0]["completed"] is False

    def test_process_complete_task(self):
        tool = TaskTool()
        session = Session(tasks=[{"title": "Task 1", "completed": False}])
        tool_call = {"operations": [{"action": "complete", "id": 0}]}

        tool.process(tool_call, session, "test-session")

        assert session.tasks[0]["completed"] is True

    def test_process_reopen_task(self):
        tool = TaskTool()
        session = Session(tasks=[{"title": "Task 1", "completed": True}])
        tool_call = {"operations": [{"action": "reopen", "id": 0}]}

        tool.process(tool_call, session, "test-session")

        assert session.tasks[0]["completed"] is False

    def test_process_delete_task(self):
        tool = TaskTool()
        session = Session(tasks=[{"title": "Task 1", "completed": False}, {"title": "Task 2", "completed": False}])
        tool_call = {"operations": [{"action": "delete", "id": 0}]}

        tool.process(tool_call, session, "test-session")

        assert len(session.tasks) == 1
        assert session.tasks[0]["title"] == "Task 2"

    def test_are_all_tasks_completed(self):
        tool = TaskTool()

        session_incomplete = Session(tasks=[{"completed": True}, {"completed": False}])
        assert tool.are_all_tasks_completed(session_incomplete) is False

        session_complete = Session(tasks=[{"completed": True}, {"completed": True}])
        assert tool.are_all_tasks_completed(session_complete) is True

        session_empty = Session()
        assert tool.are_all_tasks_completed(session_empty) is False

    def test_get_system_prompt_section(self):
        tool = TaskTool()
        test_tasks = [
            {"title": "Task 1", "completed": True},
            {"title": "Task 2", "completed": False},
        ]
        session = Session(tasks=test_tasks)

        xml = tool.get_system_prompt_section(session)

        root = ET.fromstring(xml)
        assert root.tag == "tasks"

        tasks = root.findall("task")
        assert len(tasks) == len(test_tasks)

        for task_elem, expected_task in zip(tasks, test_tasks, strict=True):
            expected_status = "completed" if expected_task["completed"] else "incomplete"
            assert task_elem.get("status") == expected_status
            assert task_elem.text == expected_task["title"]
