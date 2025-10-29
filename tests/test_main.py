import asyncio
import contextlib
import socket
from pathlib import Path

import pytest

from src.main import main, master_loop, setup_argument_parser, cli


@pytest.fixture
def test_config(tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        _, port = sock.getsockname()

    return {
        "port": port,
        "llm_url": "http://localhost:11434/v1",
        "model": "test-model",
        "token_limit": 32000,
        "api_key": None,
        "mitmproxy_config_dir": str(tmp_path / "mitmproxy"),
        "burpsuite_dir": str(tmp_path / "burp"),
        "burpsuite_config_dir": str(tmp_path / "burp_config"),
        "passthrough": True,
        "debug": False,
        "web": False,
        "proxy": None,
        "proxy_username": None,
        "proxy_password": None,
    }


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


class TestProxyServer:
    @pytest.mark.anyio
    async def test_proxy_starts_and_listens(self, test_config):
        Path(test_config["mitmproxy_config_dir"]).mkdir(parents=True, exist_ok=True)

        proxy_task = asyncio.create_task(master_loop(test_config))

        await asyncio.sleep(1)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                result = sock.connect_ex(("127.0.0.1", test_config["port"]))
                assert result == 0, "Proxy should be listening on the configured port"
        finally:
            proxy_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await proxy_task


class TestArgumentParser:
    def test_argument_parser_has_required_arguments(self):
        parser = setup_argument_parser()

        llm_url = "http://localhost:11434/v1"
        model = "test-model"
        port = "12345"

        args = parser.parse_args(["--llm-url", llm_url, "--model", model, "--port", port])

        assert args.llm_url == "http://localhost:11434/v1"
        assert args.model == "test-model"
        assert args.port == int(port)


class TestCLI:
    def test_cli_handles_keyboard_interrupt(self, mocker):
        mocker.patch("src.main.main", side_effect=KeyboardInterrupt)

        with pytest.raises(SystemExit) as exc_info:
            cli()

        assert exc_info.value.code == 0

    def test_settings_load_failure_exits(self, mocker):
        mocker.patch("src.main.init_logger")
        mocker.patch("sys.argv", ["burpai"])

        mock_settings = mocker.MagicMock()
        mock_settings.load_config.return_value = False
        mocker.patch("src.main.Settings", return_value=mock_settings)

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

    def test_burp_setup_failure_exits(self, mocker):
        mocker.patch("src.main.init_logger")
        mocker.patch("sys.argv", ["burpai"])

        mock_settings = mocker.MagicMock()
        mock_settings.load_config.return_value = True
        mock_settings.resolve.return_value = {"port": 8080}
        mocker.patch("src.main.Settings", return_value=mock_settings)

        mock_burp = mocker.MagicMock()
        mock_burp.setup.return_value = False
        mocker.patch("src.main.Burp", return_value=mock_burp)

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
