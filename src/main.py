import argparse
import asyncio
import sys
from urllib.parse import urlparse, urlunparse

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web.master import WebMaster

from src.burp import Burp
from src.proxy_addon import ProxyAddon
from src.settings import Settings
from src.utils import logger, is_port_available, init_logger

LISTEN_HOST = "127.0.0.1"


async def master_loop(config: dict):
    opts = Options()
    opts.listen_host = LISTEN_HOST
    opts.listen_port = config["port"]
    opts.confdir = config["mitmproxy_config_dir"]
    debug_enabled = config["debug"]

    # Skip cert validation when mitmproxy connects to LLM server in server_connect hook
    # Purely cosmetic to prevent TLS errors for localhost or self-signed certs
    if not config["passthrough"]:
        opts.ssl_insecure = True

    if config["proxy"]:
        proxy_url = config["proxy"]
        if config["proxy_username"] and config["proxy_password"]:
            parsed = urlparse(proxy_url)
            proxy_url = urlunparse(
                (
                    parsed.scheme,
                    f"{config['proxy_username']}:{config['proxy_password']}@{parsed.netloc}",
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )
        opts.mode = [f"upstream:{proxy_url}"]
        logger.info("Using upstream proxy: [cyan]%s[/cyan]", config["proxy"])

    if config["web"]:
        master = WebMaster(opts)
        logger.info("Web interface at [cyan]http://%s:%s[/cyan]", master.options.web_host, master.options.web_port)
    else:
        master = DumpMaster(opts, with_termlog=True, with_dumper=True)

        # flow_detail can only be configured afterwards:
        master.options.flow_detail = 3 if debug_enabled else 1

    logger.info("Proxy server listening at [cyan]%s:%s[/cyan]", LISTEN_HOST, opts.listen_port)

    proxy_addon = ProxyAddon(config)
    master.addons.add(proxy_addon)

    await master.run()


def setup_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="burpai-mitmproxy",
        description="Proxy that intercepts and processes Burp AI requests using a custom LLM instance",
        epilog="Settings are saved to ~/.config/burpai/settings.json",
    )

    # LLM configuration
    llm_group = parser.add_argument_group("LLM configuration")
    llm_group.add_argument(
        "-u",
        "--llm-url",
        metavar="URL",
        dest="llm_url",
        help="LLM API endpoint URL",
    )
    llm_group.add_argument("-k", "--api-key", metavar="KEY", help="API key for authentication")
    llm_group.add_argument("-m", "--model", metavar="NAME", help="AI model name")
    llm_group.add_argument("--token-limit", type=int, metavar="N", help="Maximum context window size in tokens")

    # Mitmproxy settings
    mitmproxy_group = parser.add_argument_group("Mitmproxy settings")
    mitmproxy_group.add_argument("-p", "--port", type=int, metavar="PORT", help="Proxy port")

    # Upstream proxy
    upstream_proxy_group = parser.add_argument_group("Upstream proxy")
    upstream_proxy_group.add_argument(
        "--proxy", metavar="URL", help="Proxy URL for LLM requests (e.g., http://proxy:8080)"
    )
    upstream_proxy_group.add_argument("--proxy-username", metavar="USER", help="Proxy username")
    upstream_proxy_group.add_argument("--proxy-password", metavar="PASS", help="Proxy password")

    # Configuration paths
    path_group = parser.add_argument_group("Configuration paths")
    path_group.add_argument("--burpsuite-dir", metavar="PATH", help="Path to the BurpSuitePro installation directory")
    path_group.add_argument("--burpsuite-config-dir", metavar="PATH", help="Path to BurpSuite config directory")
    path_group.add_argument("--mitmproxy-config-dir", metavar="PATH", help="Path to mitmproxy config directory")

    # Operation modes
    mode_group = parser.add_argument_group("Operation modes")
    mode_group.add_argument(
        "-P", "--passthrough", action="store_true", help="Enable passthrough mode for testing the official BurpAI"
    )
    mode_group.add_argument(
        "--burp-ai-token",
        metavar="TOKEN",
        help="Replace the Portswigger-Burp-Ai-Token header value in passthrough mode",
    )
    mode_group.add_argument("-d", "--debug", action="store_true", help="Enable debug logging in the console output")
    mode_group.add_argument("-w", "--web", action="store_true", help="Launch mitmweb interface for mitmproxy debugging")

    # Maintenance commands
    maint_group = parser.add_argument_group("Maintenance commands")
    maint_group.add_argument(
        "-s", "--settings", action="store_true", help="Edit settings file using $VISUAL or $EDITOR"
    )
    maint_group.add_argument("--reset", action="store_true", help="Delete settings file and secrets in keyring")
    maint_group.add_argument("--del-secrets", action="store_true", help="Delete secrets in keyring (e.g., API keys)")

    return parser


def main():
    parser = setup_argument_parser()
    args = parser.parse_args()

    init_logger(debug=args.debug)

    settings = Settings()

    # Load config unless we're about to edit the settings
    if not args.settings and not settings.load_config():
        sys.exit(1)

    # Process maintenance commands
    if args.reset:
        settings.reset()
        sys.exit(0)

    if args.del_secrets:
        settings.delete_secrets()
        sys.exit(0)

    if args.settings:
        if not settings.spawn_editor() or not settings.load_config():
            sys.exit(1)
        logger.info("Settings file is valid")
        sys.exit(0)

    # CLI-args take priority over settings.json
    overrides = {key: value for key, value in vars(args).items() if value is not None}

    config = settings.resolve(overrides=overrides)
    if config is None:
        sys.exit(1)

    # Process CLI-only args
    config["passthrough"] = args.passthrough
    config["debug"] = args.debug
    config["web"] = args.web
    if args.burp_ai_token is not None:
        config["burp_ai_token"] = args.burp_ai_token

    burp = Burp(config)
    if not burp.setup():
        sys.exit(1)

    if not is_port_available(LISTEN_HOST, config["port"]):
        sys.exit(1)

    asyncio.run(master_loop(config))


# main() should be invoked from cli()
# `uv run burpai` starts here
def cli():
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    cli()
