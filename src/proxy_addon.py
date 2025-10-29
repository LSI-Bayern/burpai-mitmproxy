import sys
import urllib.parse
from http import HTTPStatus

from .llm import LLM
from .utils import logger

import mitmproxy.http
import mitmproxy.proxy.server_hooks

from . import responses
from .prompts.explain import ExplainThisPrompt
from .prompts.montoya import MontoyaPrompt
from .prompts.explore import ExplorePrompt


class ProxyAddon:
    """Mitmproxy addon intercepting Burp Suite AI requests and allowing the usage of a custom LLM service."""

    def __init__(self, config: dict, burp_ai_domain: str = "ai.portswigger.net") -> None:
        self._passthrough: bool = config.get("passthrough", False)
        self._burp_ai_token: str | None = config.get("burp_ai_token")
        self._debug: bool = config.get("debug", False)
        self._burp_ai_domain: str = burp_ai_domain
        self._config = config

        if self._passthrough:
            logger.info("Passthrough mode enabled - requests will be forwarded to official Burp AI server")

    async def running(self):
        if self._passthrough:
            return

        self._llm = LLM(
            base_url=self._config["llm_url"],
            api_key=self._config["api_key"],
            default_model=self._config["model"],
            token_limit=self._config["token_limit"],
            default_temperature=self._config.get("temperature", 1.0),
            proxy=self._config.get("proxy"),
            proxy_username=self._config.get("proxy_username"),
            proxy_password=self._config.get("proxy_password"),
        )

        if not await self._llm.check_llm_setup():
            sys.exit(1)

        self._explain_prompt = ExplainThisPrompt(self)
        self._montoya_prompt = MontoyaPrompt(self)
        self._explore_prompt = ExplorePrompt(self)

    async def request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Route ai.portswigger.net requests by path to appropriate prompt handlers."""
        if flow.request.pretty_host != self._burp_ai_domain:
            return

        if self._passthrough:
            if self._burp_ai_token:
                flow.request.headers["Portswigger-Burp-Ai-Token"] = self._burp_ai_token
            return

        path = flow.request.path
        if path == "/burp/balance":
            logger.info("Balance check requested")
            flow.response = responses.CreditBalanceResponse()
        elif path == self._explain_prompt.explain_path:
            await self._explain_prompt.handle_request(flow)
        elif path == self._montoya_prompt.montoya_path:
            await self._montoya_prompt.handle_request(flow)
        elif path in [
            self._explore_prompt.start_path,
            self._explore_prompt.continue_path,
            self._explore_prompt.finish_path,
        ]:
            await self._explore_prompt.handle_request(flow)
        else:
            logger.warning("This request was unhandled in burpai-proxy")
            flow.response = mitmproxy.http.Response.make(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                b"This request was unhandled in burpai-proxy",
                {"Content-Type": "text/plain"},
            )

    async def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Post-process responses: add standard headers, route to prompt handlers."""
        if flow.request.pretty_host != self._burp_ai_domain:
            return

        if flow.response is None:
            logger.warning("No response received")
            return

        if self._passthrough:
            return

        flow.response.headers.update(responses.headers())

        path = flow.request.path
        if path == "/burp/balance":
            pass
        elif path == self._explain_prompt.explain_path:
            await self._explain_prompt.handle_response(flow)
        elif path == self._montoya_prompt.montoya_path:
            await self._montoya_prompt.handle_response(flow)
        elif path in [
            self._explore_prompt.start_path,
            self._explore_prompt.continue_path,
            self._explore_prompt.finish_path,
        ]:
            await self._explore_prompt.handle_response(flow)
        else:
            logger.warning("This response was unhandled in burpai-proxy")

    def server_connect(self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData) -> None:
        """Redirect upstream connection to prevent connection failures."""
        if self._passthrough:
            return

        host, _ = data.server.address if data.server.address else ("", 0)
        if host != self._burp_ai_domain:
            return

        backend_url = urllib.parse.urlparse(self._llm.base_url)
        port = backend_url.port or (443 if backend_url.scheme == "https" else 80)
        data.server.address = (str(backend_url.hostname), port)
        data.server.tls = backend_url.scheme == "https"
        if data.server.tls:
            data.server.sni = backend_url.hostname
