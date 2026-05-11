import asyncio
import contextlib
from pathlib import Path

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from src.proxy_addon import ProxyAddon


class ProxyHarness:
    """Manages mitmproxy DumpMaster lifecycle for E2E testing."""

    def __init__(self, proxy_port, llm_url, config_dir, model_name="test-model"):
        self.port = proxy_port
        self._config_dir = Path(config_dir)
        self.config = {
            "port": proxy_port,
            "llm_url": llm_url,
            "api_key": "test-key",
            "model": model_name,
            "token_limit": 100000,
            "mitmproxy_config_dir": str(config_dir),
            "debug": False,
            "passthrough": False,
            "proxy": None,
            "proxy_username": None,
            "proxy_password": None,
            "web": False,
        }
        self._master = None
        self._task = None

    async def start(self):
        self._config_dir.mkdir(parents=True, exist_ok=True)

        opts = Options()
        opts.listen_host = "127.0.0.1"
        opts.listen_port = self.port
        opts.confdir = str(self._config_dir)
        opts.ssl_insecure = True

        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        addon = ProxyAddon(self.config)

        # Wrap running() to signal when the addon is fully initialized
        addon_ready = asyncio.Event()
        original_running = addon.running

        async def _notify_running():
            await original_running()
            addon_ready.set()

        addon.running = _notify_running

        self._master.addons.add(addon)
        self._task = asyncio.create_task(self._master.run())

        try:
            await asyncio.wait_for(addon_ready.wait(), timeout=10.0)
        except asyncio.TimeoutError as err:
            await self.stop()
            raise TimeoutError("Proxy addon did not become ready within 10s") from err

    async def stop(self):
        if self._master:
            self._master.shutdown()
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
