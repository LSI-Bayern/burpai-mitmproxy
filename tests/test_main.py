import pytest

from src.main import main, setup_argument_parser, cli


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
