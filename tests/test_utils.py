import socket

import pytest

from src.utils import ask, ask_yn, display_sessid, init_logger, is_port_available, logger


class TestInitLogger:
    def test_normal_mode(self, capsys):
        init_logger(debug=False)

        logger.debug("Debug message")
        logger.info("Info message")

        captured = capsys.readouterr()
        assert "Debug message" not in captured.err
        assert "Info message" in captured.err
        assert "test_utils.py" not in captured.err

    def test_debug_mode(self, capsys):
        init_logger(debug=True)

        logger.debug("Debug message")
        logger.info("Info message")

        captured = capsys.readouterr()
        assert "Debug message" in captured.err
        assert "Info message" in captured.err
        assert "test_utils.py" in captured.err


class TestDisplaySessid:
    session_id1 = "c8c4513b-69ea-466f-9bdb-99d2875e313f"
    session_id2 = "f441907c-65ba-4dbc-963a-ec54b021b9ff"

    def test_abbreviates_uuid(self):
        result = display_sessid(self.session_id1)
        assert self.session_id1[:8] in result
        assert self.session_id1[8:] not in result

        result_short = display_sessid(self.session_id1, length=4)
        assert self.session_id1[:4] in result_short
        assert self.session_id1[4:8] not in result_short

    def test_colors(self):
        result1 = display_sessid(self.session_id1)
        result2 = display_sessid(self.session_id2)

        assert result1.startswith("[bold rgb(")
        assert "[/bold rgb(" in result1
        assert result1.split("]")[0] != result2.split("]")[0]


class TestAsk:
    def test_prompts_user_for_input(self, mocker, capsys):
        prompt = "Enter LLM URL"
        user_input = "http://localhost:11434/v1"
        mocker.patch("builtins.input", return_value=user_input)

        result = ask(prompt)

        assert result == user_input
        captured = capsys.readouterr()
        assert prompt in captured.err

    def test_returns_secret_input_when_is_secret_true(self, mocker, capsys):
        prompt = "Enter API key"
        api_key = "sk-1234567890abcdef"
        mock_getpass = mocker.patch("getpass.getpass", return_value=api_key)

        result = ask(prompt, is_secret=True)

        assert result == api_key
        mock_getpass.assert_called()
        captured = capsys.readouterr()
        assert prompt in captured.err

    def test_validates_input_and_reprompts(self, mocker, capsys):
        prompt = "Enter a positive number"
        valid_input = "42"
        side_effect = ["-5", valid_input]
        mock_input = mocker.patch("builtins.input", side_effect=side_effect)

        def is_positive(value):
            return value.isdigit() and int(value) > 0

        result = ask(prompt, validator=is_positive)

        assert result == valid_input
        assert mock_input.call_count == len(side_effect)
        captured = capsys.readouterr()
        assert prompt in captured.err


class TestAskYn:
    @pytest.mark.parametrize(
        "user_input,expected",
        [
            ("y", True),
            ("Y", True),
            ("n", False),
            ("N", False),
        ],
    )
    def test_returns_correct_boolean_for_valid_input(self, mocker, capsys, user_input, expected):
        prompt = "Continue?"
        mocker.patch("builtins.input", return_value=user_input)

        result = ask_yn(prompt)

        assert result is expected
        captured = capsys.readouterr()
        assert prompt in captured.err

    def test_reprompts_on_invalid_input(self, mocker, capsys):
        prompt = "Continue?"
        side_effect = ["invalid", "y"]
        mock_input = mocker.patch("builtins.input", side_effect=side_effect)

        result = ask_yn(prompt)

        assert result
        assert mock_input.call_count == len(side_effect)
        captured = capsys.readouterr()
        assert prompt in captured.err


class TestIsPortAvailable:
    def test_port_availability(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("localhost", 0))
            sock.listen(1)
            _, port = sock.getsockname()

            assert not is_port_available("localhost", port)

        assert is_port_available("localhost", port)
